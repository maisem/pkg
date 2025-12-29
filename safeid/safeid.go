package safeid

import (
	"math"
	"math/rand/v2"
)

// MaxSafeID is the maximum value that can be safely used as a JSON
// number.
const MaxSafeID = int64(1)<<53 - 1

// ID is a JavaScript-safe integer ID. It ranges from 1 to MaxSafeID.
type ID int64

func New[T ~int64](attempt int) T {
	// Try to generate smaller IDs first by starting with a small range and exponentially
	// increasing it with each attempt. This helps avoid large gaps between IDs while still
	// maintaining good randomness. The range grows from 10,000 up to maxJSONSafeNumber.
	maxVal := int64(10_000)
	if attempt > 10 {
		maxVal *= int64(math.Pow(2, float64(attempt-10)))
		if maxVal > MaxSafeID || maxVal <= 0 {
			maxVal = MaxSafeID
		}
	}

	// Generate random number between 1000 and maxVal (minimum 1000 to avoid low IDs)
	if maxVal < 1000 {
		maxVal = 1000
	}
	n := rand.Int64N(maxVal-1000+1) + 1000
	return T(n)
}
