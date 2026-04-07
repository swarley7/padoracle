package libpadoracle

import (
	"testing"
)

func TestGetRangeData(t *testing.T) {
	cfg := &Config{BlockSize: 16}
	engine := NewEngine(cfg)
	res := engine.GetRangeData(false)
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

	resPadded := engine.GetRangeData(true)
	if len(resPadded) != 256 {
		t.Fatalf("expected 256 bytes for padded, got %d", len(resPadded))
	}
}
