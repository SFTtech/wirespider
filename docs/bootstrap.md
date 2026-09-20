# Wirespider Bootstrap and Enrollment

Status: accepted design; **[implemented]** marks what exists today.

How a new node joins a wirespider cluster: the workflow, who owns which key,
where authority lives, and the wire format of the bootstrap data.

## Key ownership

- **Wireguard key** — per node, from the node's master secret.
- **Raft signature key** — per server node, from the node's master secret.
- **Users own neither.** A user owns the enrollment record that binds their
  account to a node's public keys. Revoking a node revokes its keys only.

## Bootstrap: first contact with a cluster

A fresh node knows nothing. It receives a **bootstrap file** (JSON) from the
operator or from the enrollment flow (below):

```json
{
  "cluster_name": "wirespider",
  "servers": [
    {
      "address": "vpn1.example.com:49582",
      "raft_pubkey": "<64 hex chars>",
      "serves_rendezvous": true
    }
  ]
}
```

- Only servers with fixed addresses (public IP or stable DNS) are listed.
  `serves_rendezvous: true` marks those that accept enrollments — the
  operator only lists rendez-vous servers here, since that is all a joining
  node needs for first contact.
- The `raft_pubkey` is pinned so the client can verify the server's raft
  signature key on first contact (mitM protection before any trust exists).
- The list is a **bootstrap aid, not the source of truth**: once connected,
  the client tracks the replicated server list (see `docs/architecture.md`).

## Enrollment flow **[planned]**

```
operator/user                new node                  raft cluster
     |                           |                          |
     |-- issue one-time token -->|                          |
     |   (+ bootstrap file)      |                          |
     |                           |-- POST /enroll ---------->|
     |                           |   {token, wg_pubkey,      |
     |                           |    raft_pubkey, role}     |
     |                           |                           |-- validate token (raft state)
     |                           |                           |-- create node, link to user
     |                           |                           |-- (raft write)
     |                           |<-- member list, config ---|
     |                           |   (signed response)       |
```

1. **Token issuance**: an operator (or a user with sufficient permission)
   creates a one-time enrollment token bound to a user account, a requested
   node role, and an expiry. Issuance is a raft write — the pending token is
   part of the **replicated state**, so every raft node can validate a redeem
   and no node is special.
2. **Redeem**: the new node connects to any fixed server's rendez-vous
   endpoint and presents `{token, wireguard pubkey, raft pubkey}`. The server
   checks the token against the replicated pending-enrollments table
   (single-use, unexpired), creates the node record linked to the token's
   user, and marks the token used.
3. **Response**: the node receives the current member list (bootstrap JSON
   content) and its configuration; it stores its identity and starts.

The **permission cap applies at enrollment**: the requested role (client /
learner / voter-eligible) is checked against the owning user's permission.
Promoting later re-checks it.

### Why the token lives in replicated state

- Any raft node can serve enrollment — no single rendez-vous node.
- Outstanding tokens survive node failure.
- Validation logic exists exactly once (the state machine), not twice (local
  pre-raft table + raft state).

### Revocation

- Unused token: delete it (raft write); redemption fails afterwards.
- Enrolled node: remove the node record; its keys are dead for both the mesh
  (wireguard) and any future raft traffic (signature check against enrolled
  keys fails).
- Time-restricted access (SSO outlook): expiring tokens and expiring node
  records — the same mechanism with timestamps enforced by policy.

## Rendez-vous transport and exposure **[planned]**

The enrollment endpoint is **gRPC on its own opt-in listener** of raft nodes,
same stack as everything else (tonic):

- A server enables it explicitly with `--enable-rendezvous` (optionally
  `--rendezvous-bind IP:PORT` for a dedicated interface/IP). It then
  announces itself as a rendez-vous point in the replicated server list —
  capability is explicit, never inferred from having a fixed address.
- The regular control plane stays bound to the **wireguard interface** by
  default: raft and client RPCs are not reachable from the public internet.
  Only the rendez-vous listener is potentially public.
- Clients and plain servers never open this listener; a client compromised
  exposes its tunnel, not an attack surface.
- No second transport, no required external reverse proxy in deployments.
- The exchanged payloads are public keys and one-time tokens; the token is
  single-use and expiring, so plaintext transport short-term is an accepted
  risk.
- TLS arrives with the future web interface (own port, rustls,
  self-signed/ACME). The bootstrap JSON's pinned keys prevent impersonation
  on first contact.

## First server: cluster creation **[implemented]**

The initial cluster has no one to ask — creation is a local operator action:

1. `wirespider database migrate`
2. `wirespider database create-network ...` / `create-admin ...`
   (local rows; imported into the log by the next step)
3. `wirespider database raft-init` — creates a single-voter cluster and
   replays the local rows into it so they replicate.

The admin token printed by `create-admin` is the operator's credential for
subsequent management commands. Additional servers join via
`raft-join` + `raft-promote` (permission-capped once the users model lands);
clients enroll via the flow above.

## Implementation status

| Piece | Status |
| --- | --- |
| Key hierarchy (node-owned master secret, HKDF) | **[implemented]** |
| `raft-init` with local state import | **[implemented]** |
| `raft-join` / `raft-promote` (operator CLI) | **[implemented]** |
| Bootstrap JSON format + pinning | planned |
| Enrollment tokens in replicated state | planned |
| Rendez-vous gRPC listener (opt-in, separately bound) | planned |
| Token expiry / revocation / SSO outlook | planned |
| TLS (with future web UI port) | outlook |
