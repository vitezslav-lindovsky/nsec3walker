package nsec3walker

import (
	"log"
	"math"
	"os"
	"sync/atomic"
	"time"
)

type Stats struct {
	queries              atomic.Int64
	hashes               atomic.Int64
	queriesWithoutResult atomic.Int64
	secondsWithoutResult atomic.Int64
}

func (stats *Stats) logCounterChanges(interval time.Duration, quitAfterMin uint) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var cntQueryLast int64
	var cntHashLast int64

	for {
		<-ticker.C
		cntQuery := stats.queries.Load()
		cntHash := stats.hashes.Load()
		cntQ := atomic.LoadInt64(&cntQuery)
		cntH := atomic.LoadInt64(&cntHash)
		deltaQ := cntQ - cntQueryLast
		deltaH := cntH - cntHashLast
		ratioTotal := stats.calculateRatio(cntH, cntQ)
		ratioDelta := stats.calculateRatio(deltaH, deltaQ)

		qWithoutResult := stats.queriesWithoutResult.Load()
		secWithoutResult := stats.secondsWithoutResult.Load()

		msg := "In the last %v: Queries total/change %d/%d | Hashes total/change: %d/%d | Ratio total/change %d%%/%d%%"
		msg += " | Without answer: %d , seconds %d\n"
		log.Printf(msg, interval, cntQ, deltaQ, cntH, deltaH, ratioTotal, ratioDelta, qWithoutResult, secWithoutResult)

		cntQueryLast = cntQ
		cntHashLast = cntH
		stats.secondsWithoutResult.Add(int64(interval.Seconds()))

		if stats.secondsWithoutResult.Load() >= int64(quitAfterMin*60) {
			log.Printf("No new hashes for %d seconds, quitting\n", secWithoutResult)
			os.Exit(0)
		}
	}
}

func (stats *Stats) gotHash(startExists bool, endExists bool) {
	add := 0

	if !startExists {
		add++
	}

	if !endExists {
		add++
	}

	stats.hashes.Add(int64(add))
	stats.queriesWithoutResult.Store(0)
	stats.secondsWithoutResult.Store(0)
}

func (stats *Stats) didQuery() {
	stats.queries.Add(1)
	stats.queriesWithoutResult.Add(1)
}

func (stats *Stats) calculateRatio(numerator, denominator int64) int {
	if denominator == 0 {
		return 0
	}

	ratio := int(math.Round((float64(numerator) / float64(denominator)) * 100))

	// Sometimes goes over 100% - great work, comrades!
	if ratio > 100 {
		return 100
	}

	return ratio
}
