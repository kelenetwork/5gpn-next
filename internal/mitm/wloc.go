package mitm

// Apple 网络定位（WLOC）响应改写。
//
// 原理：iPhone 把扫到的 WiFi BSSID 上报给 gs-loc.apple.com，Apple 返回
// 每个 AP 的已知坐标；系统据此推算「我在哪」。把响应里的坐标改成目标点，
// 网络定位即随之改变。
//
// 仅影响**网络定位**（WiFi/基站），不影响 GPS 硬件定位 —— 室外 GPS 信号
// 好时系统可能仍以 GPS 为准，这是该方案的固有边界。
//
// 协议基于公开的 protobuf wire format 自行解析，未使用任何第三方实现。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
)

// coordScale 是 Apple 坐标的定点缩放：整数值 = 度数 × 1e8。
const coordScale = 1e8

// unknownLat 是 Apple 表示「该 AP 位置未知」的哨兵值（-180°）。
const unknownLat = int64(-180 * coordScale)

// maxWlocBody 限制处理体积，防御异常响应导致的内存放大。
const maxWlocBody = 8 << 20

// jitterDeg 是每个 AP 的随机偏移幅度（度）。
//
// 若所有 AP 返回完全相同的坐标，定位结果会显得可疑且不利于系统收敛；
// 按 BSSID 派生确定性抖动（约 ±30m），既稳定又更接近真实分布。
const jitterDeg = 0.0003

// RewriteResponse 把 WLOC 响应中所有 AP 坐标改写为目标点。
//
// body 可能带有非 protobuf 前缀头，函数会自动定位 protobuf 起点；
// 无法解析时返回错误，调用方应原样透传，绝不能返回半成品。
func RewriteResponse(body []byte, lat, lon float64) ([]byte, error) {
	if len(body) == 0 {
		return nil, errors.New("空响应")
	}
	if len(body) > maxWlocBody {
		return nil, fmt.Errorf("响应过大: %d 字节", len(body))
	}
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return nil, fmt.Errorf("坐标超出范围: %f,%f", lat, lon)
	}

	off, err := findProtobufStart(body)
	if err != nil {
		return nil, err
	}
	origPBLen := len(body) - off
	rewritten, n, err := rewriteMessage(body[off:], lat, lon, 0)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("响应中没有可改写的坐标")
	}

	out := make([]byte, 0, off+len(rewritten))
	out = append(out, body[:off]...)
	out = append(out, rewritten...)

	// 回写 header 里的 protobuf 长度。
	//
	// Apple 响应形如：00 01 00 00 00 01 00 00 00 86 | <protobuf 134 字节>
	//                                        ↑ 大端长度字段
	// 改写后长度会变（未知位置的 -180 是 10 字节 varint，真实坐标只要 5 字节），
	// 不同步更新则 iOS 按旧长度读取会解析失败并丢弃响应，
	// 表现为“改写成功但定位不变”并伴随密集重试。
	patchHeaderLength(out, off, origPBLen, len(rewritten))
	return out, nil
}

// patchHeaderLength 把 header 末尾的长度字段改为新的 protobuf 长度。
//
// 实测 Apple 响应头为 10 字节，末尾 4 字节大端即 protobuf 长度：
//
//	00 01 00 00 00 01 00 00 00 86 | <protobuf 134 字节>
//	                     ^^^^^^^^^^^ 大端 134
//
// 只有当原值确实等于原 protobuf 长度时才改写；否则说明头部布局
// 与预期不符，此时保持原样——改错头部比不改更糟。
func patchHeaderLength(out []byte, off, origLen, newLen int) {
	if origLen == newLen || off < 4 {
		return
	}
	if binary.BigEndian.Uint32(out[off-4:off]) == uint32(origLen) {
		binary.BigEndian.PutUint32(out[off-4:off], uint32(newLen))
	}
}

// findProtobufStart 定位 protobuf 正文起点。
//
// Apple 响应在 protobuf 前带有固定长度的二进制头，且该头长度随版本变化。
// 与其硬编码偏移，不如逐字节尝试：第一个能完整解析到末尾的偏移即正文起点。
func findProtobufStart(body []byte) (int, error) {
	limit := 16
	if limit > len(body) {
		limit = len(body)
	}
	for off := 0; off <= limit; off++ {
		if validMessage(body[off:], 0) {
			return off, nil
		}
	}
	return 0, errors.New("未找到 protobuf 正文")
}

// validMessage 校验整段是否为合法 protobuf 且恰好消费完。
func validMessage(b []byte, depth int) bool {
	if depth > 8 || len(b) == 0 {
		return false
	}
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return false
		}
		b = b[n:]
		field := tag >> 3
		if field == 0 {
			return false
		}
		switch tag & 7 {
		case 0: // varint
			_, n := binary.Uvarint(b)
			if n <= 0 {
				return false
			}
			b = b[n:]
		case 1: // 64-bit
			if len(b) < 8 {
				return false
			}
			b = b[8:]
		case 2: // length-delimited
			l, n := binary.Uvarint(b)
			if n <= 0 {
				return false
			}
			b = b[n:]
			if uint64(len(b)) < l {
				return false
			}
			b = b[l:]
		case 5: // 32-bit
			if len(b) < 4 {
				return false
			}
			b = b[4:]
		default:
			return false
		}
	}
	return true
}

// rewriteMessage 递归改写消息中的坐标，返回新消息与改写次数。
//
// 判定「这是一个坐标消息」的依据：同时含有 field 1 与 field 2 的 varint，
// 且数值落在合法经纬度范围（或为未知哨兵值）。这样无需硬编码嵌套路径，
// 对 Apple 调整报文结构更健壮。
func rewriteMessage(b []byte, lat, lon float64, depth int) ([]byte, int, error) {
	if depth > 8 {
		return append([]byte(nil), b...), 0, nil
	}

	type fieldVal struct {
		tag     uint64
		varint  uint64
		payload []byte
		kind    int // 0=varint 1=fixed64 2=bytes 5=fixed32
	}
	var fields []fieldVal
	rest := b
	for len(rest) > 0 {
		tag, n := binary.Uvarint(rest)
		if n <= 0 {
			return nil, 0, errors.New("tag 解析失败")
		}
		rest = rest[n:]
		f := fieldVal{tag: tag, kind: int(tag & 7)}
		switch f.kind {
		case 0:
			v, n := binary.Uvarint(rest)
			if n <= 0 {
				return nil, 0, errors.New("varint 解析失败")
			}
			f.varint = v
			rest = rest[n:]
		case 1:
			if len(rest) < 8 {
				return nil, 0, errors.New("fixed64 越界")
			}
			f.payload = rest[:8]
			rest = rest[8:]
		case 2:
			l, n := binary.Uvarint(rest)
			if n <= 0 {
				return nil, 0, errors.New("length 解析失败")
			}
			rest = rest[n:]
			if uint64(len(rest)) < l {
				return nil, 0, errors.New("bytes 越界")
			}
			f.payload = rest[:l]
			rest = rest[l:]
		case 5:
			if len(rest) < 4 {
				return nil, 0, errors.New("fixed32 越界")
			}
			f.payload = rest[:4]
			rest = rest[4:]
		default:
			return nil, 0, fmt.Errorf("未知 wire type %d", f.kind)
		}
		fields = append(fields, f)
	}

	// 识别坐标消息：field 1 / field 2 均为 varint 且在合法范围内
	var latIdx, lonIdx = -1, -1
	for i, f := range fields {
		if f.kind != 0 {
			continue
		}
		switch f.tag >> 3 {
		case 1:
			if isCoord(int64(f.varint), 90) {
				latIdx = i
			}
		case 2:
			if isCoord(int64(f.varint), 180) {
				lonIdx = i
			}
		}
	}

	count := 0
	if latIdx >= 0 && lonIdx >= 0 {
		// 用整段内容派生抖动：同一 AP 每次结果一致，不同 AP 之间分散
		dLat, dLon := jitterFor(b)
		fields[latIdx].varint = uint64(int64(math.Round((lat + dLat) * coordScale)))
		fields[lonIdx].varint = uint64(int64(math.Round((lon + dLon) * coordScale)))
		count++
	}

	out := make([]byte, 0, len(b)+16)
	for _, f := range fields {
		out = binary.AppendUvarint(out, f.tag)
		switch f.kind {
		case 0:
			out = binary.AppendUvarint(out, f.varint)
		case 1, 5:
			out = append(out, f.payload...)
		case 2:
			// 子消息递归改写；不是合法子消息则原样保留（字符串/二进制字段）
			if validMessage(f.payload, depth+1) && len(f.payload) > 0 {
				sub, n, err := rewriteMessage(f.payload, lat, lon, depth+1)
				if err == nil {
					count += n
					out = binary.AppendUvarint(out, uint64(len(sub)))
					out = append(out, sub...)
					continue
				}
			}
			out = binary.AppendUvarint(out, uint64(len(f.payload)))
			out = append(out, f.payload...)
		}
	}
	return out, count, nil
}

// isCoord 判断定点整数是否为合法坐标（含 Apple 的未知哨兵值）。
func isCoord(v int64, maxDeg float64) bool {
	if v == unknownLat {
		return true
	}
	limit := int64(maxDeg * coordScale)
	return v >= -limit && v <= limit && v != 0
}

// jitterFor 由内容派生确定性偏移，避免所有 AP 落在同一点。
func jitterFor(seed []byte) (float64, float64) {
	h := fnv.New64a()
	_, _ = h.Write(seed)
	sum := h.Sum64()
	// 取两段独立位域，映射到 [-1,1]
	a := float64(int64(sum&0xffff)-0x8000) / 0x8000
	b := float64(int64((sum>>16)&0xffff)-0x8000) / 0x8000
	return a * jitterDeg, b * jitterDeg
}
