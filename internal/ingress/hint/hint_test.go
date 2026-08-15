package hint

import (
	"fmt"
	"testing"
	"time"
)

func TestAddLookupLatestWins(t *testing.T) {
	s := New()
	s.Add("172.22.2.42", "g.whatsapp.net")
	s.Add("172.22.2.42", "e3.whatsapp.net")
	got, ok := s.Lookup("172.22.2.42")
	if !ok || got != "e3.whatsapp.net" {
		t.Fatalf("Lookup=%q,%v want e3.whatsapp.net", got, ok)
	}
	// 不消费：再查仍在
	if got, ok = s.Lookup("172.22.2.42"); !ok || got != "e3.whatsapp.net" {
		t.Fatalf("second Lookup=%q,%v", got, ok)
	}
}

func TestLookupUnknownClient(t *testing.T) {
	s := New()
	if _, ok := s.Lookup("10.0.0.1"); ok {
		t.Fatal("unknown client must miss")
	}
}

func TestExpiry(t *testing.T) {
	s := New()
	s.Add("c1", "old.example")
	// 手动把时间戳改到过期之外
	s.mu.Lock()
	es := s.m["c1"]
	es[0].at = time.Now().Add(-ttl - time.Second)
	s.m["c1"] = es
	s.mu.Unlock()
	if _, ok := s.Lookup("c1"); ok {
		t.Fatal("expired hint must miss")
	}
}

func TestSameHostRefreshesNotDuplicates(t *testing.T) {
	s := New()
	for i := 0; i < 20; i++ {
		s.Add("c1", "g.whatsapp.net")
	}
	s.mu.Lock()
	n := len(s.m["c1"])
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("same host duplicated %d times", n)
	}
}

func TestPerClientBounded(t *testing.T) {
	s := New()
	for i := 0; i < 30; i++ {
		s.Add("c1", fmt.Sprintf("h%d.example", i))
	}
	s.mu.Lock()
	n := len(s.m["c1"])
	s.mu.Unlock()
	if n > perClient {
		t.Fatalf("per-client entries %d > %d", n, perClient)
	}
	// 最新的必须还在
	if got, ok := s.Lookup("c1"); !ok || got != "h29.example" {
		t.Fatalf("latest lost: %q %v", got, ok)
	}
}

func TestClientsBounded(t *testing.T) {
	s := New()
	for i := 0; i < maxClients+500; i++ {
		s.Add(fmt.Sprintf("10.0.%d.%d", i/256, i%256), "x.example")
	}
	s.mu.Lock()
	n := len(s.m)
	s.mu.Unlock()
	if n > maxClients {
		t.Fatalf("clients %d > %d", n, maxClients)
	}
}
