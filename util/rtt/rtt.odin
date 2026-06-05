package rtt

// Allocation-free RTT estimator using the Jacobson/Karels algorithm
// (the same exponentially weighted moving average TCP uses, RFC 6298).
//
// All state is O(1) and lives inline in the struct: no allocations, no
// owned pointers. You can copy it by value freely.
//
// Usage:
//     est: RTT_Estimator
//     for sample in samples {
//         update(&est, sample)
//     }
//     typical := smoothed(&est)   // the "reasonable" aggregate RTT
//     timeout := rto(&est)        // a retransmission timeout you can trust

import "core:time"

// Gains and constants from RFC 6298.
ALPHA :: 1.0 / 8.0 // weight given to each new sample for the mean
BETA :: 1.0 / 4.0 // weight given to each new sample for the deviation
K :: 4.0 // how many "deviations" of slack the RTO leaves

// Clock-granularity floor. Keeps the RTO from collapsing toward SRTT on a
// very stable link. ~1ms is a conventional, safe value.
G :: f64(time.Millisecond)

Estimator :: struct {
	srtt:        f64, // smoothed RTT          (nanoseconds)
	rttvar:      f64, // smoothed mean deviation (nanoseconds)
	min_rtt:     f64, // smallest sample seen  (nanoseconds)
	last_sample: f64, // most recent sample    (nanoseconds)
	initialized: bool,
}

// Fold one RTT sample into the estimate. O(1), no allocations.
update :: proc(e: ^Estimator, sample: time.Duration) {
	r := f64(sample)
	e.last_sample = r

	if !e.initialized {
		// First measurement seeds the estimator (RFC 6298 §2.2).
		e.srtt = r
		e.rttvar = r / 2
		e.min_rtt = r
		e.initialized = true
		return
	}

	// RTTVAR MUST be updated before SRTT: it reads the previous srtt.
	e.rttvar = (1 - BETA) * e.rttvar + BETA * abs(e.srtt - r)
	e.srtt = (1 - ALPHA) * e.srtt + ALPHA * r
	if r < e.min_rtt do e.min_rtt = r
}

smoothed :: proc(e: ^Estimator) -> f32 {
	return f32(e.srtt / f64(time.Second * 2))
}

// Smoothed jitter / mean deviation of the samples.
variation :: proc(e: ^Estimator) -> time.Duration {
	return time.Duration(e.rttvar)
}

// Best-case (≈ propagation) latency observed so far.
minimum :: proc(e: ^Estimator) -> time.Duration {
	return time.Duration(e.min_rtt)
}

// Most recent raw sample.
latest :: proc(e: ^Estimator) -> time.Duration {
	return time.Duration(e.last_sample)
}

// A retransmission timeout: SRTT plus headroom proportional to jitter,
// clamped to a sane range. RFC 6298: RTO = SRTT + max(G, K * RTTVAR).
rto :: proc(
	e: ^Estimator,
	lo := 200 * time.Millisecond,
	hi := 60 * time.Second,
) -> time.Duration {
	raw := e.srtt + max(G, K * e.rttvar)
	return clamp(time.Duration(raw), lo, hi)
}
