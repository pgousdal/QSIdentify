# Evidence Governance

QSIdentify separates observed electronic evidence, physical inspection,
statistical correlation, reviewer conclusions, catalog proposals, and
approved catalog records. The governance ledger is immutable: an operation
returns a new ledger and appends an audit event rather than editing a record.

Evidence follows the explicit lifecycle:

`Observed -> Sanitized -> Imported -> Reviewed -> Correlated -> Candidate -> Approved -> Published`

Each transition records the actor, timestamp, rationale, evidence IDs and a
chain-linked audit event. A correction or withdrawal is a new event; previous
events remain intact. Human-gated stages require a reviewer ID and an explicit
review record.

The registry remains the source of observed evidence. The governance ledger
records decisions about that evidence and never performs serial I/O, network
access, telemetry, or catalog mutation.
