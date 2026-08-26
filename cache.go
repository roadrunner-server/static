package static

import (
	"sync"
	"sync/atomic"
	"time"
)

const sweepInterval = time.Second

type cacheEntry struct {
	size      int64
	mtimeSec  int64
	mtimeNsec int32
	etag      string
	ctype     string
	filled    time.Time
}

type cacheState struct {
	// positive maps a request path to *cacheEntry.
	positive sync.Map
	// negative maps a request path to the time.Time of the miss.
	negative     sync.Map
	posCount     atomic.Int64
	negCount     atomic.Int64
	posLastSweep atomic.Int64 // unix nanos of the last positive-map sweep attempt
	negLastSweep atomic.Int64 // unix nanos of the last negative-map sweep attempt
	posTTL       time.Duration
	negTTL       time.Duration
	max          int64 // for each map
}

func newCacheState(posTTL, negTTL time.Duration, maxEntries int64) *cacheState {
	return &cacheState{
		posTTL: posTTL,
		negTTL: negTTL,
		max:    maxEntries,
	}
}

func (c *cacheState) lookupPositive(key string) *cacheEntry {
	if c.posTTL == 0 {
		return nil
	}

	v, ok := c.positive.Load(key)
	if !ok {
		return nil
	}

	e := v.(*cacheEntry)
	if time.Since(e.filled) < c.posTTL {
		return e
	}

	c.dropPositive(key)

	return nil
}

// lookupNegative reports whether a fresh miss exists for the key.
func (c *cacheState) lookupNegative(key string) bool {
	if c.negTTL == 0 {
		return false
	}

	v, ok := c.negative.Load(key)
	if !ok {
		return false
	}

	if time.Since(v.(time.Time)) < c.negTTL {
		return true
	}

	if _, loaded := c.negative.LoadAndDelete(key); loaded {
		c.negCount.Add(-1)
	}

	return false
}

func (c *cacheState) storePositive(key string, e *cacheEntry) {
	if c.posTTL == 0 {
		return
	}

	if _, ok := c.positive.Load(key); !ok {
		if c.posCount.Load() >= c.max && !c.sweep(&c.positive, &c.posCount, &c.posLastSweep, c.posTTL, positiveFilled) {
			return
		}
	}

	if _, loaded := c.positive.Swap(key, e); !loaded {
		c.posCount.Add(1)
	}
}

func (c *cacheState) storeNegative(key string) {
	if c.negTTL == 0 {
		return
	}

	if _, ok := c.negative.Load(key); !ok {
		if c.negCount.Load() >= c.max && !c.sweep(&c.negative, &c.negCount, &c.negLastSweep, c.negTTL, negativeFilled) {
			return
		}
	}

	if _, loaded := c.negative.Swap(key, time.Now()); !loaded {
		c.negCount.Add(1)
	}
}

func (c *cacheState) dropPositive(key string) {
	if _, loaded := c.positive.LoadAndDelete(key); loaded {
		c.posCount.Add(-1)
	}
}

func (c *cacheState) sweep(m *sync.Map, count *atomic.Int64, lastSweep *atomic.Int64, ttl time.Duration, filled func(any) time.Time) bool {
	now := time.Now()

	last := lastSweep.Load()
	if now.UnixNano()-last <= int64(sweepInterval) {
		return false
	}

	if !lastSweep.CompareAndSwap(last, now.UnixNano()) {
		return false
	}

	m.Range(func(k, v any) bool {
		if now.Sub(filled(v)) < ttl {
			return true
		}

		if _, loaded := m.LoadAndDelete(k); loaded {
			count.Add(-1)
		}

		return true
	})

	return count.Load() < c.max
}

func positiveFilled(v any) time.Time {
	return v.(*cacheEntry).filled
}

func negativeFilled(v any) time.Time {
	return v.(time.Time)
}
