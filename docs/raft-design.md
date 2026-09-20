# Raft Design: openraft-based cluster state

Status: accepted
Target: openraft 0.9.x, tonic 0.14, SQLite (sqlx)

## Goals

- Replace the unfinished custom Raft implementation (`src/rpc/{raft_state,log,service}.rs`,
  tarpc-based) with [openraft](https://docs.openraft.dev/) 0.9.x.
- Replicate the **full cluster state** (peers, routes, tokens, permissions, networks) so any
  server node can serve clients and survive leader failure.
- Support three deployment shapes with one mechanism:
  - 1 server node (dev / small setups, single voter)
  - 3+ server nodes (fault tolerance)
  - 2 server nodes (single voter + read-only learner replica, manual failover)

## Non-goals

- Automatic failover for 2-node clusters. A 2-voter Raft group tolerates zero failures;
  the 2-server deployment is intentionally modeled as 1 voter + 1 learner instead.
- Migrating pre-existing Raft state between versions. There are no production
  deployments with persisted raft state; the storage format is defined fresh.
- Linearizable reads on learners/replicas (documented as eventually consistent).

## Decisions

| Area | Decision |
| --- | --- |
| Consensus crate | openraft 0.9.x stable line |
| Node ID | Wrapper over the node's 32-byte raft public key (`Copy + Ord`, lexicographic) |
| Applied state | Live SQLite schema (peers, routes, tokens, permissions) + additive `networks` table |
| Hot path | Every actual state change is one raft write; no writes when nothing changed |
| Reads | Leader: linearizable (`ensure_linearizable`). Learner replica: eventually consistent, documented |
| Admin RPCs | Followers return `UNAVAILABLE` + leader hint; clients retry against the leader |
| Transport | tonic/gRPC, same service as the client protocol |
| Node-to-node auth | ed25519 signature per raft RPC, key derived from the node master secret |
| Storage | Single SQLite file, WAL, `synchronous=FULL` |
| Events | Generated per node from `apply()`; event cursor = raft last-applied log index |
| Verification | openraft storage test Suite + testcontainers 3-node chaos tests |

## Node identity and key hierarchy

Each node generates a 32-byte **master secret** at first start (stored in SQLite, never
replicated). Per-purpose keys are derived with HKDF-SHA256:

```
HKDF(master, info = "wirespider/raft-sign")  -> ed25519 raft signing key
HKDF(master, info = "wirespider/wireguard")  -> x25519 wireguard key
HKDF(master, info = "wirespider/<future>")   -> future purposes
```

- The Raft `NodeId` is the 32-byte public key of the raft signing key. openraft requires
  `NodeId: Copy + Ord`; a `#[repr(transparent)]` wrapper over `[u8; 32]` with byte-wise
  `Ord` satisfies this. No truncation, no registry, no bootstrap chicken-and-egg.
- Keys are never multipurpose: the wireguard key, the raft signing key, and any future
  TLS identity are separate derivations. The raft signing key is never serialized inside
  replicated raft state.
- A joining node is enrolled by its raft public key; the cluster learns the key during
  operator-driven join (below).

### Why signed RPCs and not mTLS

Raft RPCs are consensus-level write access: anyone who can inject `append_entries`
rewrites cluster state. Every raft method therefore carries an ed25519 signature over the
serialized request, made with the node's raft signing key. Receivers verify against the
enrolled voter/learner pubkey set and reject unknown senders.

Replay is bounded by Raft itself:

- Any replayed `append_entries`/`request_vote` with an old term fails the term check.
- Same-term replays are idempotent under log matching.
- Snapshot chunks are already deduplicated by comparing `(leader, last_log_index, last_log_term)`.

No new infrastructure (PKI, cert rotation) is introduced. ed25519-dalek is already a
dependency; this reuses the primitive with a purpose-dedicated key.

## Transport

Raft RPCs become additional gRPC methods on the existing tonic service, so there is one
transport and one auth story throughout.

A `RaftNetwork` adapter (openraft 0.9 `RaftNetworkFactory` + `RaftNetwork`) wraps the
tonic client. InstallSnapshot maps to a gRPC server stream for chunking.

## Data model

The state machine operates on the existing SQLite schema (peers, routes, tokens,
permissions, addresses) rather than a separate in-memory cluster state model. The
aspirational `ClusterState` / `ClusterNodeState` / `ClusterNetwork` model that predates
this design is not part of it: cluster state lives in the database the gRPC handlers
already use. VXLAN support is an additive `networks` table rather than a new model:

```sql
CREATE TABLE networks (
    id          BLOB PRIMARY KEY,      -- uuid
    net         TEXT NOT NULL,         -- IpNet
    net_type    TEXT NOT NULL,         -- 'wireguard' | 'vxlan'
    vni         INTEGER,               -- set iff net_type = 'vxlan'
    parent      BLOB                   -- nullable; parent network id
);
```

`RaftStateMachine::apply()` mutates the live tables. Raft log entries are typed mutations
of this schema (add/change/delete peer, add/delete route, upsert network, ...). The
`get_events` stream maps 1:1 to applies.

## Client request flow

### Reads (`get_addresses`, `get_events`)

- On the leader: linearizable. Confirm leadership (`ensure_linearizable`), then read the
  applied state.
- On a learner replica: served from applied state, explicitly eventually consistent. No
  redirect for reads.

### `get_addresses` mutations

`get_addresses` authenticates the client and may update `nat_type`/endpoints. Under raft:

- The existing "did anything change" check gates the write: no change → no log entry,
  no fsync.
- A change on the leader: one `client_write` (one fsync'd log write).
- A change on the learner replica: serve the read locally, **forward the update to the
  leader** as a raft write, so clients work transparently on any node.

### Admin RPCs (`add_peer`, `add_route`, ...)

- Any node accepts the request; if not leader, respond `UNAVAILABLE` with the current
  leader hint (openraft forwards this via `ClientWriteError::ForwardToLeader`).
- Enrollment tokens are generated **on the leader before the write** and carried inside
  the log entry, so `apply()` stays deterministic.

## Storage layout

One SQLite database file, containing:

- Raft log table: `(index INTEGER PRIMARY KEY, term INTEGER, entry BLOB)`
- Raft vote/hard-state row (openraft `Vote`)
- The applied state machine tables (existing peers/routes/tokens + `networks`)
- A metadata row for the node master secret

Durability contract: WAL journal mode + `PRAGMA synchronous = FULL`. Every acknowledged
raft append is fsync'd. This is the price of Raft's durability guarantee on power loss;
`synchronous = NORMAL` is explicitly rejected (it can lose acknowledged writes and
resurrect committed state).

Log storage appends and purges run as normal single-entry operations, never a
full-table rewrite; the vote/hard-state and applied-position metadata are stored
transactionally alongside the log.

Snapshot behavior:

- Snapshot policy: openraft default (snapshot after a log-size threshold). Cluster state
  is small (mesh scale, not event scale).
- Snapshots are built from the state machine; install uses `begin_receiving_snapshot`.
- Snapshot data is the state machine's serialization; transferred in chunks via gRPC
  server streaming.

## Membership and cluster formation

### Bootstrap (first node)

`wirespider init` on the first server: generate master secret + derived keys, initialize
a single-voter cluster (`Raft::initialize` with itself as voter).

### Joining a server node

`wirespider join <existing-node-addr>`:

1. The joining node presents its raft public key + endpoint to an existing member.
2. The member verifies the operator intent (this is an operator command, not
   client-facing), runs `add_learner`, waits for log catch-up, then
   `change_membership` to promote it to voter.
3. No static peer lists; no auto-enrollment. Every membership change is an explicit
   operator action on a healthy quorum.

### 2-node deployments: single voter + learner

- Deployment: one **primary** (single voter) + one **read-only replica** running as a
  learner. The replica serves reads and event streams but can never become leader; its
  gRPC server refuses/forwards writes.
- **Manual failover** (primary alive): operator runs the promote command on the
  replica node → `change_membership({replica})`, old primary is re-added or wiped as
  learner.
- **Dead-primary takeover**: operator-confirmed reset command on the replica. It resets
  its raft metadata and re-initializes a single-voter cluster from its applied state.
  Safe only because the operator asserts the primary is gone; acknowledged-but-unreplicated
  writes on the dead primary may be lost (documented RPO).

### Expected shapes

| Servers | Mode | Failure tolerance |
| --- | --- | --- |
| 1 | single voter | 0 (dev) |
| 2 | 1 voter + learner | 0 (manual failover only) |
| 3+ | normal voters | floor((n-1)/2) |

The CLI/docs enforce this: joining a second voter is rejected with guidance to either
run a learner replica or add a third voter.

## Events

Every node applies every entry, so every node derives events for its own connected
clients from `apply()`. No leader relay, no event loss on failover.

Event IDs are the **raft last-applied log index**:

- Monotonic per node, gap-free enough for resume semantics.
- `get_events(start_event)` resumes from the last applied index the client saw.
- Snapshot restore and log compaction do not disturb the cursor (applied index only
  grows).

## Consistency

- Leader reads: linearizable via openraft's `ensure_linearizable` before reading applied
  state. `add_peer`-then-verify flows are correct.
- Learner reads: eventually consistent by design; documented at the RPC level.
- No write coalescing beyond "only write on actual change". If NAT-flapping write rates
  become a problem, add time-window coalescing as a follow-up, not now.

## Replaced components

This design supersedes the hand-written Raft skeleton that preceded it. Its pieces are
not migrated:

- the tarpc-based transport and its hand-written `append_entries`/`request_vote`/
  `install_snapshot` handling — replaced by the tonic service and openraft's own
  replication engine
- the ad-hoc log storage that rewrote the entire log table on every save — replaced by
  the openraft `RaftLogStorage` implementation with transactional appends
- the JSON raft-state blob — replaced by the per-node master secret and openraft's
  persisted metadata
- the aspirational `ClusterState` model — superseded by mutations of the live schema
  (see *Data model*)

Kept: the SQLite schema (extended with `networks` and `users`) and the signature
concept, rebuilt on the HKDF-derived raft key.

## Component overview

1. Key hierarchy: master secret generation + HKDF derivations; raft signing key.
2. Protocol: raft service methods (`vote`, `append`, `install_snapshot`) wrapped in
   signature envelopes.
3. Type config: openraft `RaftTypeConfig` (`NodeId` = pubkey wrapper, `Node` = endpoint
   metadata, `Entry` = typed mutations, `SnapshotData`).
4. Storage: `RaftLogStorage` + `RaftStateMachine` on SQLite (WAL, `synchronous=FULL`);
   verified by the `openraft::testing` Suite.
5. Network adapter: `RaftNetwork` over tonic with signed requests.
6. State machine: apply mutations to live tables; emit events; snapshot serialization.
7. Server wiring: `protocol.rs` handlers follow authenticate → `client_write` →
   read applied; mutations are forwarded to the leader on non-leaders; reads are
   linearizable on the leader.
8. CLI: `raft-init`, `raft-join`, `raft-promote`, `raft-leave`, `raft-takeover`
   (operator-confirmed).
9. Config: election/heartbeat timeouts tuned for WAN deployments; 2-node caveats
   documented.

## Testing

- **Storage compliance**: openraft `openraft::testing::log::Suite` against the SQLite
  storage impl (all suite tests).
- **Integration (testcontainers, container based)**:
  - 3-node cluster: election, `client_write`, kill leader mid-write, new leader, no lost
    acknowledged writes.
  - Follower `UNAVAILABLE` + leader hint redirect flow.
  - Snapshot: force compaction, join a fresh learner, verify it catches up via snapshot.
  - Learner flow: promote online; dead-primary takeover with operator confirmation.
  - Event cursor continuity across a leader change.
  - Signature rejection: raft RPC from an unknown pubkey is refused.
- Unit tests for HKDF derivation stability and `NodeId` ordering.

## Open items

- Benchmark `synchronous=FULL` under realistic client churn; revisit coalescing if
  needed.
- Decide whether learner replicas also serve `get_events` streams from apply (yes, by
  design) and whether any admin RPCs should be readable on learners.
- Snapshot serialization format (JSON vs bincode) — JSON is fine at
  this size; revisit if state grows.
- Key backup/rotation story for the master secret (out of scope for v1; document that
  losing it loses the node identity).

## Related documents

- `docs/architecture.md` — process model (roles, `wirespider start`), users
  and permissions, client state sync, server discovery.
- `docs/bootstrap.md` — node enrollment, bootstrap file, rendez-vous flow.
