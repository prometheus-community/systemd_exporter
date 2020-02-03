package cgroup

import (
	"reflect"
	"testing"
)

func TestMemStat(t *testing.T) {
	expected := MemStat{
		CacheBytes:        69984256,
		RssBytes:          4866048,
		RssHugeBytes:      0,
		Shmem:             491520,
		MappedFileBytes:   9818112,
		DirtyBytes:        8192,
		WritebackBytes:    0,
		SwapBytes:         0,
		PgPgIn:            397887,
		PgPgOut:           379613,
		PgFault:           541883,
		PgMajFault:        232,
		InactiveAnonBytes: 4096,
		ActiveAnonBytes:   5353472,
		InactiveFileBytes: 2621440,
		ActiveFileBytes:   63873024,
		UnevictableBytes:  2998272,

		HierarchialMemoryLimitBytes: 9223372036854771712,
		HierarchialMemswLimitBytes:  9223372036854771712,
		TotalCacheBytes:             12469047296,
		TotalRssBytes:               2168885248,
		TotalRssHugeBytes:           10485760,
		TotalShmemBytes:             13168640,
		TotalMappedFileBytes:        228769792,
		TotalDirtyBytes:             573440,
		TotalWritebackBytes:         0,
		TotalSwapBytes:              0,
		TotalPgPgIn:                 135633232,
		TotalPgPgOut:                132074848,
		TotalPgFault:                96879883,
		TotalPgMajFault:             24509,
		TotalInactiveAnonBytes:      11632640,
		TotalActiveAnonBytes:        2134667264,
		TotalInactiveFileBytes:      9267785728,
		TotalActiveFileBytes:        3208708096,
		TotalUnevictableBytes:       15052800}

	have, err := getHybridFixtures(t).NewMemStat("/")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(have, expected) {
		t.Logf("have: %+v", have)
		t.Logf("expected: %+v", expected)
		t.Errorf("structs are not equal")
	}
}
