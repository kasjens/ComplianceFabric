// Package ledger is an append-only, tamper-evident store for evidence records.
// Each entry is chained to the previous one by a hash over the prior hash and the
// record, so any later mutation or reordering of a stored entry breaks the chain
// and is detectable by Verify. Records are persisted as one JSON object per line
// (JSON Lines) under the ledger path.
//
// # What the chain does and does not prove
//
// The hash chain alone detects mutation and reordering of stored entries, and
// deletion from the middle. It does NOT by itself detect deletion from the TAIL:
// dropping trailing lines leaves a shorter but perfectly self-consistent chain.
// Nor is an unkeyed hash chain evidence against an attacker with write access,
// who can recompute the whole chain from any point.
//
// To close the tail-truncation gap the ledger maintains a checkpoint sidecar
// (<ledger>.head) holding the current head hash and entry count. Verify checks
// the chain against it when present, so a truncated ledger is rejected. A ledger
// written before checkpointing existed has no sidecar and is treated as legacy
// and unanchored: the chain is still verified, the tail check is skipped, and a
// sidecar is written on the next append. The sidecar lives beside the ledger, so
// it raises the bar rather than removing it; defeating both requires write access
// to both files. Anchoring that survives a hostile writer needs an external
// notary (signed checkpoints or a transparency log) — see ADR-0010.
package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
)

// maxRecordBytes bounds a single stored line. A default bufio.Scanner caps a line
// at 64 KB, which a real SBOM record exceeds, and one oversized line would
// otherwise make the entire ledger — including every prior valid entry —
// permanently unreadable.
const maxRecordBytes = 16 << 20

// pathLocks serializes appends to the same ledger file within this process. It is
// keyed by cleaned path rather than held on the Ledger value, so two Ledger
// handles opened on one path still serialize against each other.
var pathLocks sync.Map // string -> *sync.Mutex

func lockFor(path string) *sync.Mutex {
	v, _ := pathLocks.LoadOrStore(path, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// Ledger is a file-backed, append-only evidence store. It is safe for concurrent
// use, and serializes against other processes appending to the same file.
type Ledger struct {
	path string

	// Cached head, valid only while the file's size still matches cachedSize.
	// This keeps Append O(1) instead of re-reading the whole ledger per record
	// (which made building an n-record ledger O(n^2)), while staying correct if
	// another process appended behind our back — a size change invalidates it.
	cachedHead  string
	cachedCount int
	cachedSize  int64
	hasCache    bool
}

// Entry is one stored evidence record plus the hash chain that makes the ledger
// tamper-evident. Hash is over PrevHash and the record; PrevHash links to the
// entry before it ("" for the first entry).
type Entry struct {
	Record   evidence.Record `json:"record"`
	PrevHash string          `json:"prev-hash"`
	Hash     string          `json:"hash"`
}

// checkpoint is the sidecar anchoring the ledger's tail.
type checkpoint struct {
	Hash  string `json:"hash"`
	Count int    `json:"count"`
}

// Open returns a ledger backed by the file at path. The file is created on first
// Append; it need not exist yet.
func Open(path string) *Ledger {
	return &Ledger{path: filepath.Clean(path)}
}

func (l *Ledger) headPath() string { return l.path + ".head" }
func (l *Ledger) lockPath() string { return l.path + ".lock" }

// Append adds a record to the end of the ledger, chaining it to the current last
// entry, and returns the stored entry. Appends are serialized within the process
// and against other processes, and the record is flushed to disk before the call
// returns, so a concurrent or interrupted append cannot break the chain.
func (l *Ledger) Append(r evidence.Record) (Entry, error) {
	mu := lockFor(l.path)
	mu.Lock()
	defer mu.Unlock()

	release, err := l.acquireFileLock()
	if err != nil {
		return Entry{}, err
	}
	defer release()

	prev, count, err := l.head()
	if err != nil {
		return Entry{}, err
	}

	hash, err := chainHash(prev, r)
	if err != nil {
		return Entry{}, err
	}
	entry := Entry{Record: r, PrevHash: prev, Hash: hash}

	line, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, err
	}
	if len(line)+1 > maxRecordBytes {
		return Entry{}, fmt.Errorf("ledger: record is %d bytes, over the %d byte limit", len(line)+1, maxRecordBytes)
	}

	if err := l.writeLine(append(line, '\n')); err != nil {
		return Entry{}, err
	}

	// Anchor the new tail. A failure here leaves a valid ledger with a stale
	// checkpoint, which Verify reports rather than ignores.
	if err := l.writeCheckpoint(checkpoint{Hash: hash, Count: count + 1}); err != nil {
		return Entry{}, err
	}

	if fi, err := os.Stat(l.path); err == nil {
		l.cachedHead, l.cachedCount, l.cachedSize, l.hasCache = hash, count+1, fi.Size(), true
	} else {
		l.hasCache = false
	}
	return entry, nil
}

// writeLine appends one line and flushes it to stable storage before returning.
func (l *Ledger) writeLine(line []byte) error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	// The Close error is reported: on some filesystems a deferred write error
	// surfaces only here, and silently dropping it would lose an evidence record.
	return f.Close()
}

func (l *Ledger) writeCheckpoint(cp checkpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	return os.WriteFile(l.headPath(), append(data, '\n'), 0o644)
}

// readCheckpoint returns the stored checkpoint, and false when the ledger has
// none (a legacy, unanchored ledger).
func (l *Ledger) readCheckpoint() (checkpoint, bool, error) {
	data, err := os.ReadFile(l.headPath())
	if os.IsNotExist(err) {
		return checkpoint{}, false, nil
	}
	if err != nil {
		return checkpoint{}, false, err
	}
	var cp checkpoint
	if err := json.Unmarshal(bytes.TrimSpace(data), &cp); err != nil {
		return checkpoint{}, false, fmt.Errorf("ledger checkpoint is unreadable: %w", err)
	}
	return cp, true, nil
}

// acquireFileLock takes an exclusive cross-process lock via an O_EXCL lockfile.
// The standard library has no file-locking primitive and the project is
// stdlib-only, so this is a cooperative lock: it excludes other Fabric processes,
// not an arbitrary writer. A lock left behind by a killed process must be removed
// by hand, which the timeout error says explicitly.
func (l *Ledger) acquireFileLock() (func(), error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := os.OpenFile(l.lockPath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(l.lockPath()) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("ledger: timed out waiting for lock %s; "+
				"if no other process is appending, remove it", l.lockPath())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// head returns the current head hash and entry count, using the cache when the
// file is unchanged since this handle last wrote it.
func (l *Ledger) head() (string, int, error) {
	fi, err := os.Stat(l.path)
	if os.IsNotExist(err) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	if l.hasCache && fi.Size() == l.cachedSize {
		return l.cachedHead, l.cachedCount, nil
	}

	entries, err := l.Entries()
	if err != nil {
		return "", 0, err
	}
	prev := ""
	if n := len(entries); n > 0 {
		prev = entries[n-1].Hash
	}
	l.cachedHead, l.cachedCount, l.cachedSize, l.hasCache = prev, len(entries), fi.Size(), true
	return prev, len(entries), nil
}

// Entries reads every stored entry in order. A ledger whose file does not exist
// yet is empty, not an error. A final line with no terminating newline is the
// residue of a process killed mid-write: it was never committed, so it is
// discarded rather than allowed to make the ledger permanently unreadable.
func (l *Ledger) Entries() ([]Entry, error) {
	data, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	// Splitting on "\n" always yields a final element that must be dropped:
	// either the empty string after a terminating newline, or an uncommitted
	// partial line.
	lines := bytes.Split(data, []byte("\n"))
	lines = lines[:len(lines)-1]

	entries := make([]Entry, 0, len(lines))
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if len(line)+1 > maxRecordBytes {
			return nil, fmt.Errorf("ledger entry %d: line is %d bytes, over the %d byte limit", i, len(line)+1, maxRecordBytes)
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("ledger entry %d: %w", i, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Verify walks the ledger and confirms it has not been tampered with: each
// entry's PrevHash must link to the prior entry's Hash, and each Hash must match
// a recomputation over its PrevHash and record. A mismatch means a stored entry
// was mutated, deleted, or reordered after it was written.
//
// When a checkpoint sidecar is present the tail is checked too, so deleting
// trailing entries is detected. A ledger with no sidecar predates checkpointing
// and is verified for chain integrity only.
func (l *Ledger) Verify() error {
	entries, err := l.Entries()
	if err != nil {
		return err
	}
	prev := ""
	for i, e := range entries {
		if e.PrevHash != prev {
			return fmt.Errorf("ledger entry %d: broken chain, prev-hash %q does not match preceding hash %q", i, e.PrevHash, prev)
		}
		want, err := chainHash(e.PrevHash, e.Record)
		if err != nil {
			return err
		}
		if e.Hash != want {
			return fmt.Errorf("ledger entry %d: record does not match its hash", i)
		}
		prev = e.Hash
	}

	cp, ok, err := l.readCheckpoint()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if cp.Count != len(entries) {
		return fmt.Errorf("ledger has %d entries but its checkpoint records %d: "+
			"%d entries were deleted from the end", len(entries), cp.Count, cp.Count-len(entries))
	}
	if cp.Hash != prev {
		return fmt.Errorf("ledger head %q does not match its checkpoint %q", prev, cp.Hash)
	}
	return nil
}

// chainHash computes the entry hash over the previous hash and the record.
func chainHash(prev string, r evidence.Record) (string, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}
