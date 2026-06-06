// Package ledger is an append-only, tamper-evident store for evidence records.
// Each entry is chained to the previous one by a hash over the prior hash and
// the record, so any later mutation or deletion of a stored entry breaks the
// chain and is detectable by Verify. Records are persisted as one JSON object
// per line (JSON Lines) under the ledger path.
package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kasjens/ComplianceFabric/internal/evidence"
)

// Ledger is a file-backed, append-only evidence store.
type Ledger struct {
	path string
}

// Entry is one stored evidence record plus the hash chain that makes the ledger
// tamper-evident. Hash is over PrevHash and the record; PrevHash links to the
// entry before it ("" for the first entry).
type Entry struct {
	Record   evidence.Record `json:"record"`
	PrevHash string          `json:"prev-hash"`
	Hash     string          `json:"hash"`
}

// Open returns a ledger backed by the file at path. The file is created on first
// Append; it need not exist yet.
func Open(path string) *Ledger {
	return &Ledger{path: path}
}

// Append adds a record to the end of the ledger, chaining it to the current last
// entry, and returns the stored entry.
func (l *Ledger) Append(r evidence.Record) (Entry, error) {
	entries, err := l.Entries()
	if err != nil {
		return Entry{}, err
	}

	prev := ""
	if n := len(entries); n > 0 {
		prev = entries[n-1].Hash
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
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// Entries reads every stored entry in order. A ledger whose file does not exist
// yet is empty, not an error.
func (l *Ledger) Entries() ([]Entry, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// Verify walks the ledger and confirms it has not been tampered with: each
// entry's PrevHash must link to the prior entry's Hash, and each Hash must match
// a recomputation over its PrevHash and record. A mismatch means a stored entry
// was mutated, deleted, or reordered after it was written.
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
