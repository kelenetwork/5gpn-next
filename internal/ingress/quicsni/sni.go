// Package quicsni 从 QUIC Initial 包中还原 TLS ClientHello 的 SNI。
//
// 动机：Google Play 下载器（Cronet）坚持使用 HTTP/3。DNS 把下载域名
// 改写到网关后，它只对网关发 QUIC（UDP 443），被拒绝也不回落 TCP，
// 表现为「下载永远等待中」。网关要接管这条流量，第一步就是从加密的
// Initial 包里解出目的域名。
//
// QUIC Initial 包虽然“加密”，但密钥完全由客户端首包的 DCID 公开派生
// （RFC 9001 §5.2），任何中间设备都能解出 ClientHello，这不是攻击，
// 是协议设计如此。本包只读取 SNI，不修改、不解密后续任何数据包。
//
// 安全边界：全部输入来自公网 UDP，必须假定恶意构造。所有长度都做
// 显式边界检查，任何异常一律返回错误，绝不 panic。
package quicsni

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNotInitial 表示该数据报不是 QUIC 长包头 Initial 包。
	ErrNotInitial = errors.New("非 QUIC Initial 包")
	// ErrUnsupportedVersion 表示 QUIC 版本未知（含版本协商包）。
	ErrUnsupportedVersion = errors.New("不支持的 QUIC 版本")
	// ErrMalformed 表示包结构越界或不合法。
	ErrMalformed = errors.New("QUIC 包结构不合法")
	// ErrNoSNI 表示 ClientHello 已完整但不含 SNI。
	ErrNoSNI = errors.New("ClientHello 中无 SNI")
)

// MaxCryptoBytes 限制单个连接累积的 CRYPTO 数据上限。
//
// 正常 ClientHello 即使带后量子密钥交换也远小于此值；设上限是防止
// 恶意端用海量分片把网关内存吃光。
const MaxCryptoBytes = 64 << 10

// MaxInitialPackets 限制单连接参与 SNI 还原的 Initial 包数量。
const MaxInitialPackets = 8

// quicVersion 描述一个 QUIC 版本的初始密钥参数。
type quicVersion struct {
	salt        []byte
	keyLabel    string
	ivLabel     string
	hpLabel     string
	initialType byte // 长包头 Type 字段中 Initial 的取值
}

// RFC 9001 §5.2（v1）与 RFC 9369 §3.3.1 / §5.8（v2）。
var (
	versionV1 = quicVersion{
		salt: []byte{
			0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
			0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
		},
		keyLabel: "quic key", ivLabel: "quic iv", hpLabel: "quic hp",
		initialType: 0x00,
	}
	versionV2 = quicVersion{
		salt: []byte{
			0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
			0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
		},
		keyLabel: "quicv2 key", ivLabel: "quicv2 iv", hpLabel: "quicv2 hp",
		initialType: 0x01,
	}
)

func lookupVersion(v uint32) (quicVersion, bool) {
	switch v {
	case 0x00000001:
		return versionV1, true
	case 0x6b3343cf:
		return versionV2, true
	default:
		return quicVersion{}, false
	}
}

// IsLongHeader 报告数据报首字节是否为 QUIC 长包头。
//
// 用于快速排除短包头（1-RTT）数据报，避免对已建立连接的每个包做无谓解析。
func IsLongHeader(datagram []byte) bool {
	return len(datagram) > 0 && datagram[0]&0x80 != 0
}

// Decoder 累积同一 QUIC 连接的 Initial CRYPTO 数据并还原 SNI。
//
// ClientHello 可能被拆到多个 Initial 包（Chrome/Cronet 启用后量子
// 密钥交换后是常态），因此必须按 CRYPTO 帧偏移重组后再解析。
type Decoder struct {
	segments map[uint64][]byte
	total    int
	packets  int
	done     bool
}

// NewDecoder 构造解码器。
func NewDecoder() *Decoder {
	return &Decoder{segments: make(map[uint64][]byte, 4)}
}

// Packets 返回已参与解析的 Initial 包数量。
func (d *Decoder) Packets() int { return d.packets }

// Feed 处理一个 UDP 数据报。
//
// 返回 ok=true 表示已还原出 SNI。ok=false 且 err==nil 表示数据尚不完整，
// 需要后续数据报继续喂入。
func (d *Decoder) Feed(datagram []byte) (sni string, ok bool, err error) {
	if d.done {
		return "", false, nil
	}
	if d.packets >= MaxInitialPackets {
		return "", false, fmt.Errorf("%w: Initial 包过多", ErrMalformed)
	}

	// 一个数据报可能合并多个 QUIC 包（coalesced packets），逐个处理。
	var sawInitial bool
	rest := datagram
	for len(rest) > 0 {
		payload, consumed, perr := decryptInitial(rest)
		if perr != nil {
			// 首包就不是 Initial：交由调用方判断（可能是短包头或其它协议）。
			if !sawInitial {
				return "", false, perr
			}
			break // 后续合并包可能是 Handshake/1-RTT，无法解密，正常退出
		}
		sawInitial = true
		d.packets++
		if err := d.collectCrypto(payload); err != nil {
			return "", false, err
		}
		if consumed <= 0 || consumed > len(rest) {
			break
		}
		rest = rest[consumed:]
	}
	if !sawInitial {
		return "", false, ErrNotInitial
	}

	hello, complete := d.assemble()
	if !complete {
		return "", false, nil
	}
	name, err := parseSNI(hello)
	if err != nil {
		return "", false, err
	}
	d.done = true
	return name, true, nil
}

// collectCrypto 从已解密的帧序列中提取 CRYPTO 数据。
func (d *Decoder) collectCrypto(payload []byte) error {
	for len(payload) > 0 {
		typ, n, ok := readVarint(payload)
		if !ok {
			return fmt.Errorf("%w: 帧类型截断", ErrMalformed)
		}
		payload = payload[n:]

		switch typ {
		case 0x00: // PADDING：连续填充一次跳过
			i := 0
			for i < len(payload) && payload[i] == 0x00 {
				i++
			}
			payload = payload[i:]

		case 0x01: // PING

		case 0x02, 0x03: // ACK
			rest, err := skipACK(payload, typ == 0x03)
			if err != nil {
				return err
			}
			payload = rest

		case 0x06: // CRYPTO
			off, n1, ok1 := readVarint(payload)
			if !ok1 {
				return fmt.Errorf("%w: CRYPTO 偏移截断", ErrMalformed)
			}
			ln, n2, ok2 := readVarint(payload[n1:])
			if !ok2 {
				return fmt.Errorf("%w: CRYPTO 长度截断", ErrMalformed)
			}
			head := n1 + n2
			if ln > uint64(len(payload)-head) {
				return fmt.Errorf("%w: CRYPTO 数据越界", ErrMalformed)
			}
			data := payload[head : head+int(ln)]
			d.addSegment(off, data)
			payload = payload[head+int(ln):]

		case 0x1c, 0x1d: // CONNECTION_CLOSE：不再有有效数据
			return nil

		default:
			// Initial 包中不应出现其它帧类型；遇到即停止解析该包，
			// 已收集的数据仍然有效。
			return nil
		}
	}
	return nil
}

func (d *Decoder) addSegment(off uint64, data []byte) {
	if len(data) == 0 || off > MaxCryptoBytes {
		return
	}
	if d.total+len(data) > MaxCryptoBytes {
		return
	}
	if _, exists := d.segments[off]; exists {
		return // 重传分片，忽略
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	d.segments[off] = cp
	d.total += len(cp)
}

// assemble 尝试从偏移 0 起拼出连续的 CRYPTO 流，并判断 ClientHello 是否完整。
func (d *Decoder) assemble() ([]byte, bool) {
	var buf []byte
	for {
		seg, ok := d.segments[uint64(len(buf))]
		if !ok {
			break
		}
		buf = append(buf, seg...)
	}
	// TLS 握手消息头：type(1) + length(3)
	if len(buf) < 4 {
		return nil, false
	}
	if buf[0] != 0x01 { // 必须是 ClientHello
		return nil, false
	}
	want := 4 + (int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3]))
	if len(buf) < want {
		return nil, false
	}
	return buf[:want], true
}

// skipACK 跳过一个 ACK 帧体。
func skipACK(b []byte, ecn bool) ([]byte, error) {
	// largest_acked, ack_delay, range_count, first_range
	var counts [4]uint64
	for i := range counts {
		v, n, ok := readVarint(b)
		if !ok {
			return nil, fmt.Errorf("%w: ACK 帧截断", ErrMalformed)
		}
		counts[i] = v
		b = b[n:]
	}
	rangeCount := counts[2]
	if rangeCount > uint64(len(b)) { // 每个 range 至少 2 字节，粗略上界防御
		return nil, fmt.Errorf("%w: ACK range 数异常", ErrMalformed)
	}
	for i := uint64(0); i < rangeCount; i++ {
		for j := 0; j < 2; j++ {
			_, n, ok := readVarint(b)
			if !ok {
				return nil, fmt.Errorf("%w: ACK range 截断", ErrMalformed)
			}
			b = b[n:]
		}
	}
	if ecn {
		for i := 0; i < 3; i++ {
			_, n, ok := readVarint(b)
			if !ok {
				return nil, fmt.Errorf("%w: ACK ECN 截断", ErrMalformed)
			}
			b = b[n:]
		}
	}
	return b, nil
}

// decryptInitial 解密单个 Initial 包，返回明文帧序列与该包在数据报中占用的字节数。
func decryptInitial(pkt []byte) ([]byte, int, error) {
	// 长包头最小长度：1(首字节)+4(版本)+1(DCID len)+1(SCID len)+1(token len)+1(length)
	if len(pkt) < 9 {
		return nil, 0, ErrNotInitial
	}
	first := pkt[0]
	if first&0x80 == 0 {
		return nil, 0, ErrNotInitial // 短包头（1-RTT）
	}
	if first&0x40 == 0 {
		return nil, 0, ErrNotInitial // Fixed Bit 必须为 1
	}
	ver := binary.BigEndian.Uint32(pkt[1:5])
	if ver == 0 {
		return nil, 0, ErrUnsupportedVersion // 版本协商包
	}
	vp, ok := lookupVersion(ver)
	if !ok {
		return nil, 0, ErrUnsupportedVersion
	}
	if (first>>4)&0x03 != vp.initialType {
		return nil, 0, ErrNotInitial
	}

	i := 5
	dcidLen := int(pkt[i])
	i++
	if dcidLen > 20 || i+dcidLen > len(pkt) {
		return nil, 0, fmt.Errorf("%w: DCID 长度非法", ErrMalformed)
	}
	dcid := pkt[i : i+dcidLen]
	i += dcidLen

	if i >= len(pkt) {
		return nil, 0, fmt.Errorf("%w: SCID 缺失", ErrMalformed)
	}
	scidLen := int(pkt[i])
	i++
	if scidLen > 20 || i+scidLen > len(pkt) {
		return nil, 0, fmt.Errorf("%w: SCID 长度非法", ErrMalformed)
	}
	i += scidLen

	tokenLen, n, ok := readVarint(pkt[i:])
	if !ok {
		return nil, 0, fmt.Errorf("%w: token 长度截断", ErrMalformed)
	}
	i += n
	if tokenLen > uint64(len(pkt)-i) {
		return nil, 0, fmt.Errorf("%w: token 越界", ErrMalformed)
	}
	i += int(tokenLen)

	length, n, ok := readVarint(pkt[i:])
	if !ok {
		return nil, 0, fmt.Errorf("%w: length 截断", ErrMalformed)
	}
	i += n
	pnOffset := i
	if length < 20 || length > uint64(len(pkt)-pnOffset) {
		// 至少要容纳最短包号(1) + GCM tag(16)
		return nil, 0, fmt.Errorf("%w: length 字段越界", ErrMalformed)
	}
	pktEnd := pnOffset + int(length)

	// 头部保护采样：从包号偏移 +4 起取 16 字节（RFC 9001 §5.4.2）
	sampleOff := pnOffset + 4
	if sampleOff+16 > pktEnd {
		return nil, 0, fmt.Errorf("%w: 采样区越界", ErrMalformed)
	}

	key, iv, hp := deriveClientInitialKeys(vp, dcid)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, 0, err
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[sampleOff:sampleOff+16])

	unprotectedFirst := first ^ (mask[0] & 0x0f)
	pnLen := int(unprotectedFirst&0x03) + 1
	if pnOffset+pnLen > pktEnd {
		return nil, 0, fmt.Errorf("%w: 包号越界", ErrMalformed)
	}

	// 重建未受保护的头部（作为 GCM 的 AAD）
	header := make([]byte, pnLen+pnOffset)
	copy(header, pkt[:pnOffset+pnLen])
	header[0] = unprotectedFirst
	var pn uint64
	for j := 0; j < pnLen; j++ {
		header[pnOffset+j] = pkt[pnOffset+j] ^ mask[1+j]
		pn = pn<<8 | uint64(header[pnOffset+j])
	}
	header = header[:pnOffset+pnLen]

	ciphertext := pkt[pnOffset+pnLen : pktEnd]
	if len(ciphertext) < 16 {
		return nil, 0, fmt.Errorf("%w: 密文短于认证标签", ErrMalformed)
	}

	// nonce = iv XOR 右对齐的包号
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for j := 0; j < 8; j++ {
		nonce[len(nonce)-1-j] ^= byte(pn >> (8 * j))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: Initial 解密失败", ErrMalformed)
	}
	return plain, pktEnd, nil
}

// deriveClientInitialKeys 由客户端首包 DCID 派生 client_initial 密钥。
func deriveClientInitialKeys(vp quicVersion, dcid []byte) (key, iv, hp []byte) {
	initialSecret := hkdfExtract(vp.salt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	key = hkdfExpandLabel(clientSecret, vp.keyLabel, 16)
	iv = hkdfExpandLabel(clientSecret, vp.ivLabel, 12)
	hp = hkdfExpandLabel(clientSecret, vp.hpLabel, 16)
	return
}

// ---------- HKDF（RFC 5869 + TLS 1.3 HkdfLabel） ----------
//
// 自行实现而非引入 golang.org/x/crypto：网关是数据面组件，
// 依赖越少供应链面越小；这两个函数总共不到 30 行且有 RFC 向量覆盖。

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 3+len(full)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // 空 context
	return hkdfExpand(secret, info, length)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	var t []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// ---------- 变长整数（RFC 9000 §16） ----------

func readVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	length := 1 << (b[0] >> 6)
	if len(b) < length {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, length, true
}

// ---------- TLS ClientHello ----------

// parseSNI 从完整的 ClientHello 握手消息中取出 server_name。
func parseSNI(hello []byte) (string, error) {
	// type(1) length(3) legacy_version(2) random(32)
	i := 4 + 2 + 32
	if len(hello) < i+1 {
		return "", fmt.Errorf("%w: ClientHello 头部截断", ErrMalformed)
	}
	sidLen := int(hello[i])
	i++
	if i+sidLen > len(hello) {
		return "", fmt.Errorf("%w: session id 越界", ErrMalformed)
	}
	i += sidLen

	if i+2 > len(hello) {
		return "", fmt.Errorf("%w: cipher suites 截断", ErrMalformed)
	}
	csLen := int(binary.BigEndian.Uint16(hello[i:]))
	i += 2
	if i+csLen > len(hello) {
		return "", fmt.Errorf("%w: cipher suites 越界", ErrMalformed)
	}
	i += csLen

	if i+1 > len(hello) {
		return "", fmt.Errorf("%w: compression 截断", ErrMalformed)
	}
	cmLen := int(hello[i])
	i++
	if i+cmLen > len(hello) {
		return "", fmt.Errorf("%w: compression 越界", ErrMalformed)
	}
	i += cmLen

	if i+2 > len(hello) {
		return "", ErrNoSNI // 无扩展
	}
	extTotal := int(binary.BigEndian.Uint16(hello[i:]))
	i += 2
	if i+extTotal > len(hello) {
		return "", fmt.Errorf("%w: 扩展区越界", ErrMalformed)
	}
	ext := hello[i : i+extTotal]

	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext)
		ln := int(binary.BigEndian.Uint16(ext[2:]))
		if 4+ln > len(ext) {
			return "", fmt.Errorf("%w: 扩展长度越界", ErrMalformed)
		}
		body := ext[4 : 4+ln]
		if typ == 0x0000 { // server_name
			return parseServerNameExt(body)
		}
		ext = ext[4+ln:]
	}
	return "", ErrNoSNI
}

func parseServerNameExt(b []byte) (string, error) {
	if len(b) < 2 {
		return "", fmt.Errorf("%w: SNI 列表截断", ErrMalformed)
	}
	listLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if listLen > len(b) {
		return "", fmt.Errorf("%w: SNI 列表越界", ErrMalformed)
	}
	b = b[:listLen]
	for len(b) >= 3 {
		nameType := b[0]
		nameLen := int(binary.BigEndian.Uint16(b[1:]))
		if 3+nameLen > len(b) {
			return "", fmt.Errorf("%w: SNI 条目越界", ErrMalformed)
		}
		if nameType == 0x00 { // host_name
			name := string(b[3 : 3+nameLen])
			if !validHost(name) {
				return "", fmt.Errorf("%w: SNI 含非法字符", ErrMalformed)
			}
			return strings.ToLower(name), nil
		}
		b = b[3+nameLen:]
	}
	return "", ErrNoSNI
}

// validHost 只接受可作为主机名的字符，防止把控制字符或空格带进日志与策略。
func validHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}
