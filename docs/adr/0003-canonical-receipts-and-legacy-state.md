# ADR 0003: Receipts bind canonical content and preserve legacy uncertainty

Status: accepted

Native audit events use canonical JSON, contiguous sequence numbers, previous
hashes, and complete entry hashes. A sealed case manifest commits evidence,
the logical SQLite store, claim/anchor record sets, the audit head and event
count, methodology/tool inventory, and report artifacts. Offline verification
must identify the exact missing or changed subject.

An unchained legacy prefix is readable but `legacy_unverified`; the first native
event may anchor its complete canonical content. An unsigned manifest is valid
but explicitly unsigned. Neither state is silently promoted to cryptographic
verification. Optional examiner signatures bind the exact canonical manifest
and are never backed by an automatically generated identity key.

Environmental or tool-version drift belongs to replay status, not tamper
status. Verification answers whether retained bytes match their commitments;
replay answers whether the analysis can be reproduced under comparable inputs.
