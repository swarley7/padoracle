package libpadoracle

import (
	"bytes"
	"testing"
)

func TestGetRangeDataSafe(t *testing.T) {
	pre := []byte{0x01, 0x02, 0x03}
	res := GetRangeDataSafe(pre)
	if len(res) != 256 {
		t.Fatalf("expected 256 bytes, got %d", len(res))
	}
	if !bytes.Equal(res[:3], pre) {
		t.Errorf("expected pre at beginning, got %x", res[:3])
	}
	// ensure no duplicates
	seen := make(map[byte]bool)
	for _, b := range res {
		if seen[b] {
			t.Errorf("duplicate byte found: %v", b)
		}
		seen[b] = true
	}
}
