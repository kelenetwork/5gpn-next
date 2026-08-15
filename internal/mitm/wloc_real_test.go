package mitm

import (
	"encoding/binary"
	"math"
	"os"
	"testing"
)

// testdata/wloc-response.bin 是向 Apple 查询公开测试 BSSID 得到的真实响应，
// 不含任何用户实际采集的热点数据。
const realSample = "testdata/wloc-response.bin"

func loadReal(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(realSample)
	if err != nil {
		t.Skipf("缺少真实样本 %s", realSample)
	}
	return b
}

// 真实响应的 header 末尾 4 字节大端记录 protobuf 长度；改写会让长度变化
// （未知位置 -180 是 10 字节 varint，真实坐标只要 5 字节），若不同步更新，
// iOS 按旧长度读取会解析失败并丢弃响应 —— 这正是「改写成功但定位不变」
// 且伴随密集重试的根因。
func TestRealResponseHeaderLengthIsPatched(t *testing.T) {
	body := loadReal(t)

	off, err := findProtobufStart(body)
	if err != nil {
		t.Fatalf("定位 protobuf 起点失败: %v", err)
	}
	if off < 4 {
		t.Fatalf("header 过短，无法验证长度字段: off=%d", off)
	}
	origLen := len(body) - off
	if got := binary.BigEndian.Uint32(body[off-4 : off]); int(got) != origLen {
		t.Fatalf("样本 header 长度字段 %d != protobuf 长度 %d", got, origLen)
	}

	out, err := RewriteResponse(body, 40.7580, -73.9855)
	if err != nil {
		t.Fatalf("改写失败: %v", err)
	}

	newLen := len(out) - off
	if newLen == origLen {
		t.Skip("本样本改写后长度未变，无法验证回写逻辑")
	}
	got := binary.BigEndian.Uint32(out[off-4 : off])
	if int(got) != newLen {
		t.Fatalf("header 长度字段 %d != 实际 protobuf 长度 %d（iOS 会丢弃该响应）", got, newLen)
	}
}

// 改写后的报文必须自洽：能被重新解析，且坐标确实是目标值。
func TestRealResponseRewriteIsSelfConsistent(t *testing.T) {
	body := loadReal(t)
	const wantLat, wantLon = 40.7580, -73.9855

	out, err := RewriteResponse(body, wantLat, wantLon)
	if err != nil {
		t.Fatalf("改写失败: %v", err)
	}
	off, err := findProtobufStart(out)
	if err != nil {
		t.Fatalf("改写后无法定位 protobuf: %v", err)
	}
	if !validMessage(out[off:], 0) {
		t.Fatal("改写后的 protobuf 无法解析")
	}

	coords := collectCoords(out[off:], 0)
	if len(coords) == 0 {
		t.Fatal("改写后找不到坐标")
	}
	for i, c := range coords {
		// 允许确定性抖动（±jitterDeg），但必须落在目标附近
		if math.Abs(c[0]-wantLat) > jitterDeg*1.5 || math.Abs(c[1]-wantLon) > jitterDeg*1.5 {
			t.Errorf("坐标 #%d = %v，未落在目标 %.4f,%.4f 附近", i+1, c, wantLat, wantLon)
		}
	}
}

// 幂等性：对已改写的响应再改写一次，长度字段仍需自洽。
func TestRealResponseRewriteTwice(t *testing.T) {
	body := loadReal(t)

	once, err := RewriteResponse(body, 40.7580, -73.9855)
	if err != nil {
		t.Fatalf("首次改写失败: %v", err)
	}
	twice, err := RewriteResponse(once, 35.6586, 139.7454)
	if err != nil {
		t.Fatalf("二次改写失败: %v", err)
	}

	off, err := findProtobufStart(twice)
	if err != nil {
		t.Fatal(err)
	}
	if off >= 4 {
		got := binary.BigEndian.Uint32(twice[off-4 : off])
		if int(got) != len(twice)-off {
			t.Fatalf("二次改写后 header 长度 %d != %d", got, len(twice)-off)
		}
	}
	if !validMessage(twice[off:], 0) {
		t.Fatal("二次改写后 protobuf 不可解析")
	}
}

// collectCoords 递归收集消息中的 (lat, lon) 对，用于断言改写结果。
func collectCoords(b []byte, depth int) [][2]float64 {
	if depth > 8 {
		return nil
	}
	var out [][2]float64
	var lat, lon int64
	var hasLat, hasLon bool

	i := 0
	for i < len(b) {
		tag, n := binary.Uvarint(b[i:])
		if n <= 0 {
			return out
		}
		i += n
		switch tag & 7 {
		case 0:
			v, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return out
			}
			i += n
			switch tag >> 3 {
			case 1:
				lat, hasLat = int64(v), true
			case 2:
				lon, hasLon = int64(v), true
			}
		case 2:
			l, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return out
			}
			i += n
			if uint64(len(b)-i) < l {
				return out
			}
			out = append(out, collectCoords(b[i:i+int(l)], depth+1)...)
			i += int(l)
		case 1:
			i += 8
		case 5:
			i += 4
		default:
			return out
		}
	}
	if hasLat && hasLon {
		out = append(out, [2]float64{float64(lat) / coordScale, float64(lon) / coordScale})
	}
	return out
}
