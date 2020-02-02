package cgroup

import (
	"reflect"
	"testing"
)

func TestMemStat(t *testing.T) {
	expected := MemStat{
		Cache:        69984256,
		Rss:          4866048,
		RssHuge:      0,
		Shmem:        491520,
		MappedFile:   9818112,
		Dirty:        8192,
		Writeback:    0,
		Swap:         0,
		PgPgIn:       397887,
		PgPgOut:      379613,
		PgFault:      541883,
		PgMajFault:   232,
		InactiveAnon: 4096,
		ActiveAnon:   5353472,
		InactiveFile: 2621440,
		ActiveFile:   63873024,
		Unevictable:  2998272,

		HierarchialMemoryLimit: 9223372036854771712,
		HierarchialMemswLimit:  9223372036854771712,
		TotalCache:             12469047296,
		TotalRss:               2168885248,
		TotalRssHuge:           10485760,
		TotalShmem:             13168640,
		TotalMappedFile:        228769792,
		TotalDirty:             573440,
		TotalWriteback:         0,
		TotalSwap:              0,
		TotalPgPgIn:            135633232,
		TotalPgPgOut:           132074848,
		TotalPgFault:           96879883,
		TotalPgMajFault:        24509,
		TotalInactiveAnon:      11632640,
		TotalActiveAnon:        2134667264,
		TotalInactiveFile:      9267785728,
		TotalActiveFile:        3208708096,
		TotalUnevictable:       15052800}

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
