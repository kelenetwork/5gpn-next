package sniff

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

type partialWriter struct{}

func (partialWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return 1, errors.New("synthetic write failure")
}

func TestTrafficWriterReportsEachSuccessfulWriteIncrement(t *testing.T) {
	var dst bytes.Buffer
	var got []int64
	w := trafficWriter{dst: &dst, report: func(n int64) { got = append(got, n) }}

	if n, err := w.Write([]byte("abc")); err != nil || n != 3 {
		t.Fatalf("first write n=%d err=%v", n, err)
	}
	if n, err := w.Write([]byte("defgh")); err != nil || n != 5 {
		t.Fatalf("second write n=%d err=%v", n, err)
	}
	if !reflect.DeepEqual(got, []int64{3, 5}) {
		t.Fatalf("reported increments=%v, want [3 5]", got)
	}
	if dst.String() != "abcdefgh" {
		t.Fatalf("forwarded bytes=%q", dst.String())
	}
}

func TestTrafficWriterCountsPartialWriteBeforeError(t *testing.T) {
	var got int64
	w := trafficWriter{dst: partialWriter{}, report: func(n int64) { got += n }}
	n, err := w.Write([]byte("payload"))
	if n != 1 || err == nil || got != 1 {
		t.Fatalf("partial write n=%d err=%v reported=%d, want 1/non-nil/1", n, err, got)
	}
}
