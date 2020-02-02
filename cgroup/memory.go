package cgroup

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"strconv"
	"strings"
)

// https://www.kernel.org/doc/Documentation/cgroup-v1/memory.txt
// memory.stat file
type MemStat struct {
	// bytes of page cache memory
	Cache uint64
	// bytes of anon and swap cache, including transparent hugepages.
	// Note: Only anonymous and swap cache memory is listed as part of 'rss' stat.
	// This should not be confused with the true 'resident set size' or the
	// amount of physical memory used by the cgroup. 'rss + file_mapped" will
	// give you resident set size of cgroup
	Rss uint64
	// bytes of anonymous transparent hugepages
	RssHuge uint64
	// No kernel documentation
	Shmem uint64
	// bytes of mapped files (includes tmpfs/shmem)
	MappedFile uint64
	// number of charging events to the memory cgroup. The charging
	// event happens each time a page is accounted as either mapped
	// anon page(RSS) or cache page(Page Cache) to the cgroup.
	PgPgIn uint64
	// # of uncharging events to the memory cgroup. The uncharging
	// event happens each time a page is unaccounted from the cgroup.
	PgPgOut uint64
	// no kernel documentation
	PgFault uint64
	// no kernel documentation
	PgMajFault uint64
	// # of bytes of swap usage
	Swap uint64
	// # of bytes that are waiting to get written back to the disk.
	Dirty uint64
	// writeback	- # of bytes of file/anon cache that are queued for syncing to
	// disk.
	Writeback uint64
	// inactive_anon	- # of bytes of anonymous and swap cache memory on inactive
	// LRU list.
	InactiveAnon uint64
	// active_anon	- # of bytes of anonymous and swap cache memory on active
	// LRU list.
	ActiveAnon uint64
	// inactive_file	- # of bytes of file-backed memory on inactive LRU list.
	InactiveFile uint64
	// active_file	- # of bytes of file-backed memory on active LRU list.
	ActiveFile uint64
	// unevictable	- # of bytes of memory that cannot be reclaimed (mlocked etc).
	Unevictable uint64

	// status considering hierarchy (see memory.use_hierarchy settings)
	// # of bytes of memory limit with regard to hierarchy
	// under which the memory cgroup is
	HierarchialMemoryLimit uint64
	// # of bytes of memory+swap limit with regard to
	// hierarchy under which memory cgroup is.
	HierarchialMemswLimit uint64
	// total_cache		- sum of all children's "cache"
	TotalCache uint64
	// No kernel doc
	TotalDirty uint64
	// total_rss		- sum of all children's "rss"
	TotalRss uint64
	// No kernel docs
	TotalRssHuge uint64
	// total_mapped_file	- sum of all children's "cache"
	TotalMappedFile uint64
	// No kernel docs
	TotalPgFault uint64
	// No kernel docs
	TotalPgMajFault uint64
	// total_pgpgout		- sum of all children's "pgpgout"
	TotalPgPgIn uint64
	// total_pgpgout		- sum of all children's "pgpgout"
	TotalPgPgOut uint64
	// No kernel doc
	TotalShmem uint64
	// total_swap		- sum of all children's "swap"
	TotalSwap uint64
	// total_inactive_anon	- sum of all children's "inactive_anon"
	TotalInactiveAnon uint64
	// total_active_anon	- sum of all children's "active_anon"
	TotalActiveAnon uint64
	// total_inactive_file	- sum of all children's "inactive_file"
	TotalInactiveFile uint64
	// total_active_file	- sum of all children's "active_file"
	TotalActiveFile uint64
	// total_unevictable	- sum of all children's "unevictable"
	TotalUnevictable uint64
	// No kernel doc
	TotalWriteback uint64
	// 	# The following additional stats are dependent on CONFIG_DEBUG_VM.
	// 	inactive_ratio		- VM internal parameter. (see mm/page_alloc.c)
	// 	recent_rotated_anon	- VM internal parameter. (see mm/vmscan.c)
	// 	recent_rotated_file	- VM internal parameter. (see mm/vmscan.c)
	// 	recent_scanned_anon	- VM internal parameter. (see mm/vmscan.c)
	// 	recent_scanned_file	- VM internal parameter. (see mm/vmscan.c)

}

func parseMemStat(r io.Reader) (*MemStat, error) {
	var m MemStat
	s := bufio.NewScanner(r)
	for s.Scan() {
		// Each line has at least a name and value
		fields := strings.Fields(s.Text())
		if len(fields) < 2 {
			return nil, fmt.Errorf("malformed memory.stat line: %q", s.Text())
		}

		v, err := strconv.ParseUint(fields[1], 0, 64)
		if err != nil {
			return nil, err
		}

		switch fields[0] {
		case "cache":
			m.Cache = v
		case "rss":
			m.Rss = v
		case "rss_huge":
			m.RssHuge = v
		case "shmem":
			m.Shmem = v
		case "mapped_file":
			m.MappedFile = v
		case "dirty":
			m.Dirty = v
		case "writeback":
			m.Writeback = v
		case "swap":
			m.Swap = v
		case "pgpgin":
			m.PgPgIn = v
		case "pgpgout":
			m.PgPgOut = v
		case "pgfault":
			m.PgFault = v
		case "pgmajfault":
			m.PgMajFault = v
		case "inactive_anon":
			m.InactiveAnon = v
		case "active_anon":
			m.ActiveAnon = v
		case "inactive_file":
			m.InactiveFile = v
		case "active_file":
			m.ActiveFile = v
		case "unevictable":
			m.Unevictable = v
		case "hierarchical_memory_limit":
			m.HierarchialMemoryLimit = v
		case "hierarchical_memsw_limit":
			m.HierarchialMemswLimit = v
		case "total_cache":
			m.TotalCache = v
		case "total_rss":
			m.TotalRss = v
		case "total_rss_huge":
			m.TotalRssHuge = v
		case "total_shmem":
			m.TotalShmem = v
		case "total_mapped_file":
			m.TotalMappedFile = v
		case "total_dirty":
			m.TotalDirty = v
		case "total_writeback":
			m.TotalWriteback = v
		case "total_swap":
			m.TotalSwap = v
		case "total_pgpgin":
			m.TotalPgPgIn = v
		case "total_pgpgout":
			m.TotalPgPgOut = v
		case "total_pgfault":
			m.TotalPgFault = v
		case "total_pgmajfault":
			m.TotalPgMajFault = v
		case "total_inactive_anon":
			m.TotalInactiveAnon = v
		case "total_inactive_file":
			m.TotalInactiveFile = v
		case "total_active_anon":
			m.TotalActiveAnon = v
		case "total_active_file":
			m.TotalActiveFile = v
		case "total_unevictable":
			m.TotalUnevictable = v
		}
	}

	return &m, nil
}

// NewMemStat will locate and read the kernel's cpu accounting info for
// the provided systemd cgroup subpath.
func NewMemStat(cgSubpath string) (MemStat, error) {
	fs, err := NewDefaultFS()
	if err != nil {
		return MemStat{}, err
	}
	return fs.NewMemStat(cgSubpath)
}

// MemStat returns an information about cgroup memory statistics.
// See
func (fs FS) NewMemStat(cgSubpath string) (MemStat, error) {
	cgPath, err := fs.cgGetPath("memory", cgSubpath, "memory.stat")
	if err != nil {
		return MemStat{}, errors.Wrapf(err, "unable to get cpu controller path")
	}

	b, err := ReadFileNoStat(cgPath)
	if err != nil {
		return MemStat{}, err
	}

	m, err := parseMemStat(bytes.NewReader(b))
	if err != nil {
		return MemStat{}, fmt.Errorf("failed to parse meminfo: %v", err)
	}

	return *m, nil
}
