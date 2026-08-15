package mitm

import (
	"encoding/binary"
	"math"
	"os"
	"testing"
	"time"
)

// 白名单是安全边界：只有 Apple 定位服务可被中间人，其余一律拒绝。
//
// 生产实测发现 iOS 并不总是直连 gs-loc.apple.com，也会把定位查询发给
// gspe1-ssl.ls.apple.com 这类边缘节点，因此白名单需覆盖 gsp* 定位子域。
func TestAllowedHostsIsStrict(t *testing.T) {
	allowed := []string{
		"gs-loc.apple.com",
		"gs-loc-cn.apple.com",
	}
	for _, h := range allowed {
		if !Allowed(h) {
			t.Errorf("%s should be allowed", h)
		}
	}

	denied := []string{
		"apple.com", "www.apple.com", "evil.com", "", "google.com",
		// 后缀伪装：绝不能因为结尾像白名单就放行
		"gs-loc.apple.com.evil.com",
		"gs-loc.apple.co",
		// ls.apple.com 下的服务一律拒绝。
		//
		// gsp* 是 Apple **地图服务**（Geo Services Provider），不是 WLOC。
		// v0.12.3 曾因其流量特征（上传 ~1.9KB / 下载 ~4.3KB）相似而误放行，
		// 导致启发式坐标改写在地图响应里也“匹配成功”并写入垃圾数据。
		"ls.apple.com",
		"gspe1-ssl.ls.apple.com",
		"gsp64-ssl.ls.apple.com",
		"gspe79-ssl.ls.apple.com",
		"gspe19-cn-ssl.ls.apple.com",
		"init.ls.apple.com",
		"configuration.ls.apple.com",
		"evil.gspe1-ssl.ls.apple.com",
	}
	for _, h := range denied {
		if Allowed(h) {
			t.Errorf("%s must NOT be allowed for MITM", h)
		}
	}
}

func TestCALeafOnlyForAllowedHosts(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"gs-loc.apple.com", "gs-loc-cn.apple.com"} {
		if _, err := ca.LeafFor(h); err != nil {
			t.Fatalf("allowed host %s must get a leaf: %v", h, err)
		}
	}
	for _, h := range []string{"evil.com", "init.ls.apple.com", "gspe1-ssl.ls.apple.com"} {
		if _, err := ca.LeafFor(h); err == nil {
			t.Fatalf("must refuse to sign for %s", h)
		}
	}
}

func TestCAPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 重启后必须复用同一 CA，否则用户已装的描述文件立即失效
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatal("CA must be stable across restarts")
	}
	if len(second.CertDER()) == 0 {
		t.Fatal("empty CA DER")
	}
}

func TestCAValidity(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !ca.cert.IsCA {
		t.Fatal("must be a CA cert")
	}
	if ca.cert.NotAfter.Before(time.Now().AddDate(5, 0, 0)) {
		t.Fatal("CA lifetime too short; profile would silently expire")
	}
	leaf, err := ca.LeafFor("gs-loc.apple.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("leaf chain should include CA, got %d certs", len(leaf.Certificate))
	}
}

// ---- WLOC protobuf 改写 ----

func encodeVarintField(field uint64, v uint64) []byte {
	b := binary.AppendUvarint(nil, field<<3|0)
	return binary.AppendUvarint(b, v)
}

func encodeBytesField(field uint64, payload []byte) []byte {
	b := binary.AppendUvarint(nil, field<<3|2)
	b = binary.AppendUvarint(b, uint64(len(payload)))
	return append(b, payload...)
}

// 构造一个近似 Apple WLOC 响应：外层含若干 AP 条目，每条内嵌坐标消息。
func buildWlocResponse(coords [][2]float64) []byte {
	var out []byte
	for _, c := range coords {
		inner := encodeVarintField(1, uint64(int64(c[0]*coordScale)))
		inner = append(inner, encodeVarintField(2, uint64(int64(c[1]*coordScale)))...)
		// AP 条目：field 1 = BSSID 字符串，field 2 = 坐标子消息
		ap := encodeBytesField(1, []byte("00:11:22:33:44:55"))
		ap = append(ap, encodeBytesField(2, inner)...)
		out = append(out, encodeBytesField(2, ap)...)
	}
	return out
}

func decodeCoords(t *testing.T, b []byte) [][2]float64 {
	t.Helper()
	var found [][2]float64
	var walk func(b []byte, depth int)
	walk = func(b []byte, depth int) {
		if depth > 8 {
			return
		}
		var lat, lon int64
		var hasLat, hasLon bool
		rest := b
		for len(rest) > 0 {
			tag, n := binary.Uvarint(rest)
			if n <= 0 {
				return
			}
			rest = rest[n:]
			switch tag & 7 {
			case 0:
				v, n := binary.Uvarint(rest)
				if n <= 0 {
					return
				}
				rest = rest[n:]
				if tag>>3 == 1 {
					lat, hasLat = int64(v), true
				}
				if tag>>3 == 2 {
					lon, hasLon = int64(v), true
				}
			case 2:
				l, n := binary.Uvarint(rest)
				if n <= 0 {
					return
				}
				rest = rest[n:]
				if uint64(len(rest)) < l {
					return
				}
				walk(rest[:l], depth+1)
				rest = rest[l:]
			case 1:
				if len(rest) < 8 {
					return
				}
				rest = rest[8:]
			case 5:
				if len(rest) < 4 {
					return
				}
				rest = rest[4:]
			default:
				return
			}
		}
		if hasLat && hasLon {
			found = append(found, [2]float64{
				float64(lat) / coordScale,
				float64(lon) / coordScale,
			})
		}
	}
	walk(b, 0)
	return found
}

func TestRewriteResponseMovesAllCoords(t *testing.T) {
	orig := buildWlocResponse([][2]float64{
		{22.544577, 113.94114},
		{22.545000, 113.942000},
		{31.230400, 121.473700},
	})
	const wantLat, wantLon = 39.9042, 116.4074

	out, err := RewriteResponse(orig, wantLat, wantLon)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	coords := decodeCoords(t, out)
	if len(coords) != 3 {
		t.Fatalf("expected 3 coords, got %d", len(coords))
	}
	for _, c := range coords {
		// 允许确定性抖动（±jitterDeg）
		if math.Abs(c[0]-wantLat) > jitterDeg*1.5 || math.Abs(c[1]-wantLon) > jitterDeg*1.5 {
			t.Errorf("coord %v not moved near target %v,%v", c, wantLat, wantLon)
		}
	}
}

// 抖动必须是确定性的：同一响应两次改写结果一致，否则定位会抖动
func TestRewriteIsDeterministic(t *testing.T) {
	orig := buildWlocResponse([][2]float64{{22.5, 113.9}, {22.6, 114.0}})
	a, err := RewriteResponse(orig, 39.9042, 116.4074)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RewriteResponse(orig, 39.9042, 116.4074)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("rewrite must be deterministic for the same input")
	}
}

// 不同 AP 应落在不同点，避免所有 AP 完全重合
func TestRewriteJittersPerEntry(t *testing.T) {
	orig := buildWlocResponse([][2]float64{{22.5, 113.9}, {22.6, 114.0}, {22.7, 114.1}})
	out, err := RewriteResponse(orig, 39.9042, 116.4074)
	if err != nil {
		t.Fatal(err)
	}
	coords := decodeCoords(t, out)
	if len(coords) < 2 {
		t.Fatalf("need >=2 coords, got %d", len(coords))
	}
	same := 0
	for _, c := range coords[1:] {
		if c == coords[0] {
			same++
		}
	}
	if same == len(coords)-1 {
		t.Fatal("all APs collapsed to the exact same point")
	}
}

func TestRewriteRejectsBadInput(t *testing.T) {
	valid := buildWlocResponse([][2]float64{{22.5, 113.9}})
	cases := []struct {
		name     string
		body     []byte
		lat, lon float64
	}{
		{"空响应", nil, 39.9, 116.4},
		{"纬度越界", valid, 91, 116.4},
		{"经度越界", valid, 39.9, 181},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := RewriteResponse(c.body, c.lat, c.lon); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// 没有坐标的响应必须报错，调用方据此原样透传而非返回半成品
func TestRewriteReportsNoCoords(t *testing.T) {
	body := encodeBytesField(1, []byte("no coordinates here"))
	if _, err := RewriteResponse(body, 39.9042, 116.4074); err == nil {
		t.Fatal("must report when nothing was rewritten")
	}
}

func TestSpooferGating(t *testing.T) {
	s := New(t.TempDir())
	if err := s.EnsureCA(); err != nil {
		t.Fatal(err)
	}

	if s.Active() {
		t.Fatal("must be inactive before enabling")
	}
	s.SetEnabled(true)
	if s.Active() {
		t.Fatal("enabled but no coordinate: must stay inactive")
	}
	if err := s.SetLocation(39.9042, 116.4074); err != nil {
		t.Fatal(err)
	}
	if !s.Active() {
		t.Fatal("should be active once enabled with a fix")
	}
	s.ClearLocation()
	if s.Active() {
		t.Fatal("cleared location must deactivate")
	}
	if err := s.SetLocation(200, 0); err == nil {
		t.Fatal("must reject out-of-range latitude")
	}
	s.SetEnabled(false)
	_ = s.SetLocation(39.9042, 116.4074)
	if s.Active() {
		t.Fatal("disabled must never be active")
	}
}

// CA 延迟生成：未启用的部署不应凭空多出一张根证书，
// 也绝不能在没有证书时声称自己 Active。
func TestSpooferLazyCA(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	if s.HasCA() {
		t.Fatal("CA must not exist before first enable")
	}
	if s.CACertDER() != nil || s.CAFingerprint() != "" {
		t.Fatal("no CA yet: DER/fingerprint must be empty")
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
		t.Fatalf("CA dir should stay empty, got %d entries", len(entries))
	}

	// 没有 CA 时即使开启+设坐标也不能生效
	s.SetEnabled(true)
	if err := s.SetLocation(39.9042, 116.4074); err != nil {
		t.Fatal(err)
	}
	if s.Active() {
		t.Fatal("must not be active without a CA")
	}

	if err := s.EnsureCA(); err != nil {
		t.Fatal(err)
	}
	if !s.HasCA() || !s.Active() {
		t.Fatal("should become active once CA is ready")
	}
	fp := s.CAFingerprint()
	if fp == "" {
		t.Fatal("fingerprint must be available after EnsureCA")
	}

	// 重复调用幂等：开关多次不得更换证书，否则已装描述文件会失效
	if err := s.EnsureCA(); err != nil {
		t.Fatal(err)
	}
	if s.CAFingerprint() != fp {
		t.Fatal("EnsureCA must be idempotent")
	}

	// 关闭后重新打开，证书仍需保持不变
	s.SetEnabled(false)
	s.SetEnabled(true)
	if s.CAFingerprint() != fp {
		t.Fatal("toggling must not rotate the CA")
	}
}
