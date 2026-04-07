package libpadoracle

import (
	"testing"
)

func TestGetRangeDataSafe(t *testing.T) {
	res := GetRangeDataSafe(false, 16)
	if len(res) != 256 {
		t.Fatalf("expected 256 bytes, got %d", len(res))
	}
	// ensure no duplicates
	seen := make(map[byte]bool)
	for _, b := range res {
		if seen[b] {
			t.Errorf("duplicate byte found: %v", b)
		}
		seen[b] = true
	}

	resPadded := GetRangeDataSafe(true, 16)
	if len(resPadded) != 256 {
		t.Fatalf("expected 256 bytes for padded, got %d", len(resPadded))
	}
}
