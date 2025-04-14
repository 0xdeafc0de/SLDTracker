package sld

import (
	"sort"
	"sync"
	"time"
	"fmt"
)

type SLDStore struct {
	data  map[string][]int64 // SLD → [counts per minute]
	mu    sync.Mutex
	start time.Time
	window int
}

func NewSLDStore(windowMinutes int) *SLDStore {
	return &SLDStore{
		data:   make(map[string][]int64),
		start:  time.Now().Truncate(time.Minute),
		window: windowMinutes,
	}
}

func (s *SLDStore) Add(fqdn string) {
	sld := ExtractSLD(fqdn, true)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	minsSinceStart := int(now.Sub(s.start).Minutes())

	if minsSinceStart >= s.window {
		s.trimOld(minsSinceStart)
	}

	bucketIdx := minsSinceStart % s.window
	if _, ok := s.data[sld]; !ok {
		s.data[sld] = make([]int64, s.window)
	}
	s.data[sld][bucketIdx]++
}

func (s *SLDStore) trimOld(currentIndex int) {
	for sld, counts := range s.data {
		for i := 0; i < s.window; i++ {
			bucketIdx := (currentIndex + i) % s.window
			counts[bucketIdx] = 0
		}
		_ = sld
	}
	s.start = time.Now().Truncate(time.Minute)
}

type SLDCount struct {
	Name  string
	Count int64
}

func (s *SLDStore) TopN(n int) []SLDCount {
	fmt.Println("Get Top", n)
	s.mu.Lock()
	defer s.mu.Unlock()

	var results []SLDCount
	for sld, counts := range s.data {
		var total int64
		for _, c := range counts {
			total += c
		}
		if total > 0 {
			results = append(results, SLDCount{sld, total})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})

	if len(results) > n {
		return results[:n]
	}
	return results
}

func (s *SLDStore) Track(sld string) {
    s.mu.Lock()
    defer s.mu.Unlock()

    now := time.Now()
    minsSinceStart := int(now.Sub(s.start).Minutes())

    if minsSinceStart >= s.window || minsSinceStart < 0 {
        s.trimOld(minsSinceStart)
        minsSinceStart = 0
    }

    bucketIdx := minsSinceStart % s.window

    if _, ok := s.data[sld]; !ok {
        s.data[sld] = make([]int64, s.window)
    }

    s.data[sld][bucketIdx]++
}

