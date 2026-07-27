# ADR 0010: What the evidence ledger proves, and what it does not

## Status

Accepted.

## Context

The evidence ledger is an append-only JSON Lines file where each entry carries a SHA-256 hash over the previous entry's hash and its own record. The package documentation claimed that "any later mutation or deletion of a stored entry breaks the chain and is detectable by Verify".

That claim was too strong in three ways:

1. **Tail truncation was undetectable.** Deleting trailing lines leaves a shorter but perfectly self-consistent chain. `head -n -1 ledger.jsonl` destroyed evidence and `Verify()` returned success.
2. **An unkeyed hash chain does not resist a writer.** Anyone who can write the file can recompute every hash from any point and produce a chain that verifies cleanly. The chain detects *accidental* corruption and *naive* edits, not an adversary with write access.
3. **Concurrency corrupted it in a way indistinguishable from tampering.** Two processes appending at once both read the same head and wrote entries claiming the same predecessor. `Verify()` then reported a broken chain forever — the same error an attacker would produce — with no way to tell them apart and no repair path.

For a system whose entire value proposition is trustworthy audit evidence, overstating the guarantee is itself a defect. An auditor told "tamper-evident" will reasonably assume more than the chain delivered.

## Decision

**State the guarantee precisely, raise it where it is cheap to do so, and be explicit that stronger anchoring requires an external notary.**

Staged, in the order the strength is actually gained:

1. **Correct the documentation.** The package doc now says what the chain does (detects mutation, reordering, and deletion from the middle) and what it does not (tail truncation on its own; anything against a writer who can recompute).
2. **Serialize appends and make them durable.** Appends take a per-path in-process mutex and an `O_EXCL` lockfile, and each line is flushed before the call returns. Concurrency can no longer produce corruption that masquerades as tampering. An uncommitted trailing partial line — the residue of a killed process — is discarded on read rather than making the ledger permanently unreadable.
3. **Anchor the tail with a checkpoint sidecar.** A `<ledger>.head` file records the current head hash and entry count; `Verify` checks the chain against it, so truncation is caught. A ledger written before checkpointing existed has no sidecar, is treated as legacy and unanchored, and gets one on its next append.
4. **External anchoring remains future work.** Signed checkpoints, or publishing the head hash to a transparency log, are what would make the ledger resist a hostile writer.

## Consequences

- The sidecar lives beside the ledger, so it **raises the bar rather than removing it**: defeating both requires write access to two files instead of one. This is a real but bounded improvement and must not be described as tamper-proof.
- Because the stdlib has no file-locking primitive and this project is stdlib-only, the cross-process lock is **cooperative**. It excludes other Fabric processes, not an arbitrary writer, and a lockfile left behind by a killed process must be removed by hand — the timeout error says so explicitly.
- Verification now has three distinguishable outcomes rather than two: intact, chain broken (mutation or reordering), and tail truncated (entry count below the checkpoint). Separating the last two is what makes the failure actionable.
- Historical ledgers are never rewritten. An audit trail that is retroactively edited is worth less than one with a documented discontinuity, so legacy ledgers stay valid and unanchored rather than being migrated.
- Until step 4 lands, no claim may be made — in docs, README, or marketing — that the ledger resists an attacker with write access to its host. It does not.
