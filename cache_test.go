package static

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// countEntries walks the map, the only way to compare a counter against reality.
func countEntries(m *sync.Map) int64 {
	var n int64
	m.Range(func(_, _ any) bool {
		n++
		return true
	})

	return n
}

func freshEntry(size int64) *cacheEntry {
	return &cacheEntry{size: size, filled: time.Now()}
}

func TestCachePositiveLookupAndExpiry(t *testing.T) {
	c := newCacheState(50*time.Millisecond, time.Hour, 16)

	require.Nil(t, c.lookupPositive("/absent.txt"))

	c.storePositive("/a.txt", freshEntry(7))
	got := c.lookupPositive("/a.txt")
	require.NotNil(t, got)
	require.EqualValues(t, 7, got.size)
	require.EqualValues(t, 1, c.posCount.Load())

	time.Sleep(100 * time.Millisecond)

	require.Nil(t, c.lookupPositive("/a.txt"), "an entry older than the ttl must miss")
	require.EqualValues(t, 0, c.posCount.Load(), "the expired entry must be dropped and counted out")
	require.EqualValues(t, 0, countEntries(&c.positive))
}

// TestCachePositiveRoundTrip pins that a stored entry comes back as-is: the cache is the only source of the metadata for a cached response.
func TestCachePositiveRoundTrip(t *testing.T) {
	c := newCacheState(time.Hour, time.Hour, 16)
	stored := &cacheEntry{
		size:      42,
		mtimeSec:  1700000000,
		mtimeNsec: 250,
		etag:      `W/"42-1700000000.250"`,
		ctype:     "text/css; charset=utf-8",
		filled:    time.Now(),
	}

	c.storePositive("/a.css", stored)
	got := c.lookupPositive("/a.css")

	require.NotNil(t, got)
	require.Same(t, stored, got, "entries are immutable, the stored pointer is handed back")
	require.EqualValues(t, 42, got.size)
	require.EqualValues(t, 1700000000, got.mtimeSec)
	require.EqualValues(t, 250, got.mtimeNsec)
	require.Equal(t, `W/"42-1700000000.250"`, got.etag)
	require.Equal(t, "text/css; charset=utf-8", got.ctype)
}

func TestCacheNegativeLookupAndExpiry(t *testing.T) {
	c := newCacheState(time.Hour, 50*time.Millisecond, 16)

	require.False(t, c.lookupNegative("/absent.txt"))

	c.storeNegative("/missing.txt")
	require.True(t, c.lookupNegative("/missing.txt"))
	require.EqualValues(t, 1, c.negCount.Load())

	time.Sleep(100 * time.Millisecond)

	require.False(t, c.lookupNegative("/missing.txt"), "a negative entry older than the ttl must miss")
	require.EqualValues(t, 0, c.negCount.Load())
	require.EqualValues(t, 0, countEntries(&c.negative))
}

func TestCacheZeroTTLDisablesStores(t *testing.T) {
	t.Run("both_disabled", func(t *testing.T) {
		c := newCacheState(0, 0, 16)

		c.storePositive("/a.txt", freshEntry(1))
		c.storeNegative("/a.txt")

		require.Nil(t, c.lookupPositive("/a.txt"))
		require.False(t, c.lookupNegative("/a.txt"))
		require.EqualValues(t, 0, c.posCount.Load())
		require.EqualValues(t, 0, c.negCount.Load())
		require.EqualValues(t, 0, countEntries(&c.positive))
		require.EqualValues(t, 0, countEntries(&c.negative))
	})

	t.Run("positive_only", func(t *testing.T) {
		c := newCacheState(time.Hour, 0, 16)

		c.storePositive("/a.txt", freshEntry(1))
		c.storeNegative("/a.txt")

		require.NotNil(t, c.lookupPositive("/a.txt"))
		require.False(t, c.lookupNegative("/a.txt"))
		require.EqualValues(t, 0, c.negCount.Load())
	})

	t.Run("negative_only", func(t *testing.T) {
		c := newCacheState(0, time.Hour, 16)

		c.storePositive("/a.txt", freshEntry(1))
		c.storeNegative("/a.txt")

		require.Nil(t, c.lookupPositive("/a.txt"))
		require.True(t, c.lookupNegative("/a.txt"))
		require.EqualValues(t, 0, c.posCount.Load())
	})
}

func TestCacheCounterProtocol(t *testing.T) {
	c := newCacheState(time.Hour, time.Hour, 16)

	c.storePositive("/a.txt", freshEntry(1))
	c.storePositive("/a.txt", freshEntry(2))
	c.storeNegative("/b.txt")
	c.storeNegative("/b.txt")

	require.EqualValues(t, 1, c.posCount.Load(), "refreshing a key must not grow the counter")
	require.EqualValues(t, 1, c.negCount.Load(), "refreshing a key must not grow the counter")

	got := c.lookupPositive("/a.txt")
	require.NotNil(t, got)
	require.EqualValues(t, 2, got.size, "a refresh must replace the stored entry")

	c.dropPositive("/never-stored.txt")
	require.EqualValues(t, 1, c.posCount.Load(), "dropping an absent key must not decrement")

	c.dropPositive("/a.txt")
	require.EqualValues(t, 0, c.posCount.Load())
	require.Nil(t, c.lookupPositive("/a.txt"))
	require.EqualValues(t, 0, countEntries(&c.positive))
}

// TestCacheCapSweepIsGated covers the overflow path: the first insert over the cap sweeps once, the next one inside the gate window gives up without a Range.
func TestCacheCapSweepIsGated(t *testing.T) {
	c := newCacheState(time.Hour, time.Hour, 4)

	for i := range 4 {
		c.storePositive("/f"+strconv.Itoa(i)+".txt", freshEntry(int64(i)))
	}

	require.EqualValues(t, 4, c.posCount.Load())
	require.EqualValues(t, 0, c.posLastSweep.Load(), "no sweep happens below the cap")

	c.storePositive("/overflow-1.txt", freshEntry(100))
	swept := c.posLastSweep.Load()

	require.NotEqualValues(t, 0, swept, "the first insert over the cap must sweep")
	require.EqualValues(t, 4, c.posCount.Load(), "nothing expired, so the insert is skipped")
	require.Nil(t, c.lookupPositive("/overflow-1.txt"))

	c.storePositive("/overflow-2.txt", freshEntry(101))

	require.Equal(t, swept, c.posLastSweep.Load(), "a second overflow within the gate must not sweep again")
	require.EqualValues(t, 4, c.posCount.Load())
	require.Nil(t, c.lookupPositive("/overflow-2.txt"))
}

func TestCacheSweepFreesExpiredEntries(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		c := newCacheState(50*time.Millisecond, time.Hour, 4)

		for i := range 4 {
			c.storePositive("/f"+strconv.Itoa(i)+".txt", freshEntry(int64(i)))
		}

		time.Sleep(100 * time.Millisecond)
		c.storePositive("/fresh.txt", freshEntry(9))

		require.EqualValues(t, 1, c.posCount.Load(), "the sweep frees the expired entries and the insert lands")
		require.EqualValues(t, 1, countEntries(&c.positive))
		require.NotNil(t, c.lookupPositive("/fresh.txt"))
	})

	t.Run("negative", func(t *testing.T) {
		c := newCacheState(time.Hour, 50*time.Millisecond, 2)

		c.storeNegative("/a.txt")
		c.storeNegative("/b.txt")

		time.Sleep(100 * time.Millisecond)
		c.storeNegative("/c.txt")

		require.EqualValues(t, 1, c.negCount.Load())
		require.EqualValues(t, 1, countEntries(&c.negative))
		require.True(t, c.lookupNegative("/c.txt"))
	})

	t.Run("negative_full", func(t *testing.T) {
		c := newCacheState(time.Hour, time.Hour, 2)

		c.storeNegative("/a.txt")
		c.storeNegative("/b.txt")
		c.storeNegative("/c.txt")

		require.EqualValues(t, 2, c.negCount.Load(), "a full cache skips the insert")
		require.False(t, c.lookupNegative("/c.txt"))
	})
}

// cacheStorm drives every cache operation from several goroutines at once and checks the counters still describe the maps afterward.
func cacheStorm(t *testing.T, c *cacheState) {
	t.Helper()

	const (
		goroutines = 8
		ops        = 500
		keys       = 32
	)

	keyOf := func(i int) string { return "/f" + strconv.Itoa(i%keys) + ".txt" }

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			for i := range ops {
				key := keyOf(g*7 + i)
				switch i % 5 {
				case 0:
					c.storePositive(key, freshEntry(int64(i)))
				case 1:
					c.lookupPositive(key)
				case 2:
					c.storeNegative(key)
				case 3:
					c.lookupNegative(key)
				default:
					c.dropPositive(key)
				}
			}
		})
	}
	wg.Wait()

	require.Equal(t, countEntries(&c.positive), c.posCount.Load())
	require.Equal(t, countEntries(&c.negative), c.negCount.Load())
}

// TestCacheConcurrentAccessKeepsCountersInSync is the -race guard for the counter protocol: after the storm the counters must match the map contents.
func TestCacheConcurrentAccessKeepsCountersInSync(t *testing.T) {
	t.Run("no_eviction", func(t *testing.T) {
		cacheStorm(t, newCacheState(time.Hour, time.Hour, 1024))
	})

	// a cap the storm reaches at once, plus a ttl shorter than the storm, so sweeps and expiry drops interleave with stores
	t.Run("with_eviction", func(t *testing.T) {
		cacheStorm(t, newCacheState(time.Millisecond, time.Millisecond, 8))
	})
}
