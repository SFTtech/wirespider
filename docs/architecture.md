# Wirespider Architecture: Processes, Users, and State Sync

Status: accepted design; sections marked **[implemented]** reflect the current
code, everything else is planned work.

## Process model

A single `wirespider start` command serves all roles. The process reads its
**local state database** and resumes whatever it was configured to be:

| Stored state | Process becomes |
| --- | --- |
| raft state (vote, log, master secret) + cluster membership | raft participant (voter or learner), serves client + raft gRPC |
| enrollment record + local client DB | mesh client, connects to servers, manages its wireguard interface |
| neither | refuses to start, tells the operator to run `raft-init` / `raft-join` (server) or enroll (client) first |

**First start is explicit, restarts are automatic.** The initial role decision
cannot be inferred from empty state, so it lives in operator actions:

- server: `wirespider database raft-init` (first node) or `raft-join`
  (additional nodes)
- client: enrollment via a rendez-vous (see `docs/bootstrap.md`)

After that, `wirespider start` needs no arguments beyond the state database
location.

### Node-owned keys

Every node (server *and* client) has a 32-byte **master secret** in its local
database. Per-purpose keys are HKDF-derived from it:

- `wirespider/raft-signing` — ed25519 key signing raft RPCs (server nodes)
- `wirespider/wireguard` — the node's tunnel key
- future purposes get their own derivation labels

**Keys belong to the node, not the user.** The user owns the *enrollment
record* that links their account to the node's public keys. Consequences:

- Revoking a node revokes only that node's keys; the user's other nodes are
  unaffected.
- A compromised device cannot impersonate the user's other nodes.
- "Which node is operated by whom" is answered by the enrollment record, not
  by key ownership.
- One user with several nodes has one wireguard key per node (each tunnel is
  a distinct peer) and one signature key per server node.

## Users, nodes, and permissions **[planned]**

Today a single `peers` row mixes user, token, and node. The model splits them:

```
users                     nodes (peers)
+----+----------+-----+   +----+---------+----------+------------+
| id | name     | ... |   | id | user_id | wg_key   | node keys  |
+----+----------+-----+   +----+---------+----------+------------+
        ^                          |
        +------ enrollment record -+
```

- A **user** is a natural person. May own zero or more nodes.
- A **node** is one running wirespider process with its own keys and (for mesh
  members) a wireguard tunnel.
- Capabilities that describe the tunnel (monitor, relay) stay per-node;
  permissions describe the user.

### Permission cap on node roles

The user's permission limits what their node may become:

```
effective capability = min(user permission, node role)
```

- Becoming a **raft voter** requires the owning user to hold the server
  capability. A node run by a minimal-permission user can never join
  consensus — which is exactly right for intermittently available nodes.
- Becoming a **learner** requires a lower threshold.
- A plain mesh client needs nothing beyond enrollment.

The cap is checked **at enrollment** (node is created with a role at most as
powerful as its user) and **re-checked at promote time** (promoting a learner
to voter re-validates the owner's current permission; a demoted user's nodes
cannot be promoted). Permission changes do not retroactively demote existing
nodes until the next role operation.

### External authentication outlook

The users/nodes split is the foundation for enterprise-style join flows:

- An external identity provider (SSO) provisions a **user**.
- The provider (or the user, if permitted) issues **node enrollment tokens**
  on that user's behalf.
- Time-restricted access = expiring enrollment tokens + expiring node records.
  The schema needs nothing more than timestamps that the state machine already
  carries; enforcement is a policy layer, not a data model change.

Nothing here needs implementation now; it constrains the schema so the split
does not have to be redone.

## Role switching

Roles are not permanent. Switching is an operator action composed from the
existing subcommands, and every direction requires quorum:

**client → server**

1. `raft-join --member <addr> --advertise <addr>` — adds the node as learner
   (approved by an existing member; the permission cap applies).
2. optional: `raft-promote --leader <addr>` — learner becomes voter.

**server → client**

1. remove the node from raft membership (`change_membership`, via an operator
   command on a surviving member),
2. stop the raft subsystem, archive the local raft state (log + meta are kept
   for forensics, not reused),
3. keep running as a plain client with the same wireguard identity.

The permission cap is re-checked whenever a node gains a role.

## Client state sync

Clients are not raft participants: they never see raft RPCs, hold no raft
state, and their presence or absence affects nothing in consensus. Their
identity in the mesh is a row in the replicated state plus a token.

A client keeps a **local state database**: its token, wireguard key, and the
last-seen **event cursor** (a raft log index).

### Incremental updates

- `get_events(start_event)` streams events after the cursor; event ids are
  raft log indexes, monotonic and identical on every node — the cursor works
  against any server, including after leader changes.
- The server keeps a bounded in-memory history (`EVENT_BUFFER`, 1000 entries).
- If the cursor is **within history**: only the delta is streamed. This is the
  normal reconnect path (laptop sleep, network blip).
- If the cursor is **older than history** (client offline longer than the
  window): the server falls back to a full state dump as the initial events,
  the client rebuilds from it, and the cursor resumes from the applied index.

This mirrors raft's own log/snapshot division: the bounded history is the
"log", the full state dump is the "snapshot". The trade-off is accepted:
long-offline clients re-pull full state rather than servers retaining an
unbounded log. If large meshes make full re-syncs expensive, the follow-up is
a state-version diff (client sends per-table versions, server sends changed
rows) — a compatible extension, not a redesign.

### Commands from clients

All mutations travel through the client's **local node** to the leader:

- Every mutating RPC received by a non-leader is forwarded to the current
  leader with the caller's auth metadata; the leader re-verifies permissions
  and submits the raft write. Clients never need to know who the leader is.
- Implemented so far for `get_addresses`; the same forwarding applies to
  `add_peer`/`delete_peer`/`change_peer`/`add_route`/`del_route`/network
  commands.
- Reads: `get_addresses` is linearizable on the leader; on learners/clients'
  servers it is eventually consistent (documented at the RPC level).

## Listening model **[planned]**

Each role opens only the ports it needs; public exposure is opt-in and
role-gated:

| Listener | Client | Server | Rendez-vous server |
| --- | --- | --- | --- |
| Wireguard UDP port | always | always | always |
| gRPC control plane (client + raft RPCs) | never | bound to the **wireguard interface** by default | same |
| Rendez-vous gRPC (enrollment) | never | off by default | **opt-in** via `--enable-rendezvous` (+ optional `--rendezvous-bind IP:PORT`) |

- Simple clients **listen for nothing** on the control plane: they only send
  wireguard traffic and connect out to servers. Compromising a client exposes
  its tunnel, not an attack surface.
- Server control-plane traffic (raft RPCs, client RPCs) rides the wireguard
  interface by default, so it is not reachable from the public internet
  unless the operator opts in.
- A server that wants to serve enrollments enables the rendez-vous listener,
  optionally on a dedicated interface/IP. It announces this capability in the
  replicated server list (below), so enrollment-capable nodes are explicit,
  not inferred from having a fixed address.
- The raft RPC surface is additionally protected by per-node signature
  verification regardless of where it is reachable.

## Server discovery **[planned]**

Fixed-address servers (public IP or DNS) announce themselves in the
**replicated state** (a `raft_members` table updated by the same mutations
that drive raft membership). Entries are role-flagged:

```
{ address, raft_pubkey, serves_rendezvous: bool }
```

Clients:

1. keep the bootstrap member list from enrollment (see `docs/bootstrap.md`),
2. store the last-known server list from events,
3. on start, try the intersection of both, then the bootstrap list,
4. refresh continuously from events — newly added servers appear without
   config changes, dead ones age out of the last-known list.

Only servers with `serves_rendezvous: true` are used for enrollment;
ordinary clients never contact them otherwise. The replicated state is the
source of truth once the cluster runs; the bootstrap JSON only covers first
contact.

## Mesh joining (gateways) **[planned]**

Two wirespider networks can be joined by a **gateway host** running one
normal wirespider node per cluster — two separate enrollments, two separate
key hierarchies and state databases, no shared process:

```
cluster A (10.10.0.0/24)          cluster B (10.20.0.0/16)
        |                                 |
   [node gw-a] <-- ip_forward --> [node gw-b]
        |                                 |
   wireguard wg0                      wg0
```

- Each gateway side is an ordinary member of its cluster; a cluster's
  security is never coupled to the other cluster's.
- **Data path**: the Linux kernel forwards between the two wireguard devices
  (`ip_forward=1`); no wirespider code is in the forwarding path. If one
  gateway side dies, its cluster stays healthy — only cross-mesh traffic
  breaks. Redundancy = a second gateway host.
- **Control path**: each cluster gets routes to the other's prefixes via its
  own gateway side, using the existing route announcement:

  - in cluster A: `10.20.0.0/16 via <gw-a's A-side IP>`
  - in cluster B: `10.10.0.0/24 via <gw-b's B-side IP>`

  The announcing user needs sufficient permission (see below); the routes
  replicate to every node and are programmed onto the wireguard devices by
  the existing client route handling.

### Route announcement and validation

Route authorization is the user's permission (a gateway operator needs an
elevated permission to announce routes for prefixes beyond their own node),
and every node enforces the rules **in `apply()`** — in the state machine, so
the log itself can never contain invalid routes, regardless of who was
leader:

- the `via` address must be an existing peer address in this cluster;
- duplicate `(destination, via)` entries apply idempotently;
- per-owner route count is capped (prevents log flooding through route
  churn);
- overlapping prefixes are allowed (the kernel resolves by specificity).

### Why not one process in multiple clusters

A single process holding identities in several clusters would couple their
security (one blast radius, one key hierarchy, one upgrade window) and would
need custom forwarding logic — recreating the kernel's routing in
wirespider. Two enrolled processes plus `ip_forward` need no new wirespider
code at all and contain failures the same way any router does.

## Implementation status

| Piece | Status |
| --- | --- |
| Node master secret + HKDF keys, node-owned | **[implemented]** |
| Raft voters/learners, join/promote/takeover | **[implemented]** |
| Signed raft RPCs, unknown-signer rejection | **[implemented]** |
| Event cursor + bounded history + full-dump fallback | **[implemented]** |
| All-mutation forwarding to leader | **[implemented]** |
| `users` table, `peers.user_id`, permission cap (enroll + apply) | **[implemented]** |
| User management RPCs (`createUser`/`deleteUser`/`changeUser`) | **[implemented]** |
| Route validation rules in `apply()` | **[implemented]** |
| Role switching (leave/archive; composed subcommands) | **[implemented]** |
| Raft node peer records (`RecordRaftNode`), ownership transfer (`changePeer --owner`) | **[implemented]** |
| Listening model (wg-bound control plane, opt-in rendez-vous) | planned |
| Replicated server list with rendez-vous flags + client last-known tracking | planned |
| Rendez-vous enrollment endpoint, one-time tokens | planned (see `docs/bootstrap.md`) |
| Mesh gateway pattern (two enrollments + ip_forward) | planned (docs + setup, no code) |
| SSO provisioning | outlook only |
| Web UI + TLS on its own port | outlook only |
