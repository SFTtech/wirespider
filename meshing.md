# Meshing

Plan for connecting server-managed wirespider networks with each other, and for making a single host a network of its own.

## Concepts

- **Realm** — one database and one server, the single writer for the peers it owns.
  This is what a wirespider deployment is today; it only gains a name and an identity.
- **Node** — a wirespider client. It talks to exactly one realm.
- **Peering** — a pairwise link between two realms. Each side authenticates the other with a token, and each side sends only the peers it exports.
- **Export** — a per-peer flag deciding whether a peer is visible to peered realms.

A realm with one node is an independent node.
Federation is optional: without a peering configured, nothing changes.

Trust is pairwise and structural.
A realm is authoritative for its own peers, and records received from a peered realm are read-only locally.
There is no transitive federation, so records need no signatures and the existing token authentication is sufficient.
If transitive federation is ever wanted, a signature field can be added to the records without breaking the wire format.

## Transport trait

The client reaches the server only through a `tonic::Channel`, so the split can be abstracted without touching any logic.

The interface is the generated `wirespider_server::Wirespider` trait itself — there is no reason to invent a second one.

- `WirespiderServerState` already implements it; this is the in-process transport.
- A new wrapper around `WirespiderClient<Channel>` implements the same trait for the gRPC transport.
- Both fix the associated stream type to the boxed `EventStream` that [src/server/protocol.rs](src/server/protocol.rs) already defines, so the client can hold `Arc<dyn Wirespider<GetEventsStream = EventStream>>`.

The local transport injects the node's token into the request metadata, so `authenticate()` runs unchanged and there is no privileged bypass.
A unix socket transport is a third implementation later and needs no further design.

Running both roles in one process uses the `tokio_graceful_shutdown` subsystems that are already in place.

## CLI

Old subcommand names are dropped.

```
wirespider client --endpoint <uri> --token <uuid>   # join a remote realm over grpc
wirespider client -d <database-url>                 # be the realm, in this process
wirespider server -d <database-url> --bind <addr>   # realm server for multi-node realms
wirespider ctl ...                                  # manage peers and routes, either transport
wirespider realm init|invite|join|export ...        # realm lifecycle and peering
```

There is no flag that names the transport.
`--endpoint`/`--token` and `--database-url` form a mutually exclusive group, reusing the existing `ConnectionOptions` and `DatabaseOptions` from [src/cli.rs](src/cli.rs) including the `DATABASE_URL` environment variable.
Pointing a client at a database means this process is the realm and the calls stay in-process.

The database is a file, so peers, routes and peerings survive a restart.
`--ephemeral` selects an in-memory database instead, for the case where the entire configuration comes from the command line or a config file anyway.

`wirespider realm init` replaces the current `database migrate` plus `create-network` plus `create-admin` sequence with one command.
`realm invite` prints one blob (realm name, endpoint, one-shot token), `realm join` consumes it and creates the reverse token, and the two realms are peered.

## Data model

Migrations stay append-only.

- `realms`: name, identity, endpoint, peering token, and a flag marking the local realm.
  Each peering also stores the cursor of the last event applied from that realm.
- `peers.realmid`, backfilled to the local realm.
- `peers.exported`, with a realm-wide default.
  Export is decided per peer only; filtering per peering is deliberately left out until someone needs it.
- `routes.metric`, so two realms announcing the same prefix have a defined winner.

Peer names stay unique per realm and are qualified as `name@realm` across realms.

## Federation

A peering is one RPC, `sync(stream SyncMessage) -> stream SyncMessage`, authenticated by the peering token.
It is bidirectional rather than two opposite calls so that only one of the two realms has to be reachable, which is what lets a single-host realm on a laptop peer with a public one.
Which side dials is then the only asymmetry; both behave identically afterwards.

The realm servers reach each other over their public endpoints, not through the tunnel.

### Handshake

The first message in each direction is a hello carrying the realm name, its networks, and the cursor of the last event this side already holds from the other.
The networks let both sides refuse an overlapping address space before anything is imported.
The cursor decides where replication resumes.

### What is exchanged

Two record kinds, which are the entire vocabulary of the existing `Event` message: peers, added, changed or deleted, and routes, added or deleted.

For every exported peer, the same `Peer` message clients already receive: public key, name, its addresses, endpoint, NAT type, node flags, local IPs and port.
Routes carry prefix, via and metric, and a realm with no subnets behind its nodes simply never emits any.

This is a stream rather than a one-shot exchange of keys because endpoints and NAT types change while the peering is up, and that is exactly the information hole punching needs.
A cursor over an ordered log is just the cheap version of repeatedly dumping the whole set.

Never exchanged: tokens, permission levels, non-exported peers, and anything the realm learned from a third realm.

### Replication

After the hello each side simply forwards its own event stream, reusing the `event_list` deque and `current_eventid` of [src/server/protocol.rs](src/server/protocol.rs) unchanged.
A realm has a single writer, so its log is already totally ordered and a cursor per peering is enough; there is nothing to merge.

Attribution comes from the connection, not from the payload.
Everything arriving on a peering is stored against that realm and is read-only locally, so a realm cannot assert records about a realm it is not.

When the requested cursor is older than the deque, the sender falls back to a full snapshot, as it already does for clients.
The receiver then has to sweep the foreign peers the snapshot did not contain, so the snapshot needs an explicit end marker — without one, a peer deleted while the peering was down lingers forever.

A disconnect does not remove foreign peers, because their tunnels keep working; reconciliation happens on reconnect, using the `backoff` retry the client event loop already uses.

Federation is pairwise and non-transitive, so no realm ever forwards foreign records: there are no loops and no path vector to maintain.

Clients are unaffected: foreign peers arrive through the normal event stream and are configured like any other peer.

### Compatibility

Two peered realms are administered by different people and will run different versions, so this is the one interface where version skew is the normal case rather than an accident.

Proto3 covers most of it: unknown fields are ignored, added fields default, and field numbers are never reused.
What it does not cover is new enum values and new `oneof` variants, which an older peer decodes as an unknown number or as an absent field, and then acts on a record it does not actually understand.

So the hello carries a protocol version, both sides record the other's, and anything that cannot be expressed in the older version is not sent to that peering.
A realm that is too old to be understood at all is refused with a clear error instead of being half-supported.

## Addressing

Two realms with overlapping prefixes cannot be joined.
`realm join` validates this and refuses, rather than producing a half-broken routing table.

For automated setups, the default IPv6 prefix is derived from a hash of the realm identity into a ULA `/48`, which makes accidental collisions negligible.
IPv4 stays manual; the space is too small to allocate automatically.

## Routing

Reaching foreign *nodes* needs no routing protocol: each peer's own addresses are in its `allowed_ips`.
Routing only matters for subnets behind a node and for having more than one path to them.

A `--route-manager` setting selects who owns the kernel routing table:

- `internal` (default) — distributed routes are installed as today, now ordered by metric.
- `none` — configure the WireGuard peers and `allowed_ips`, and leave the FIB to an external daemon.

There are too many routing daemons to integrate with any of them.
Wirespider generates no daemon configuration and calls no daemon, it only exposes both directions as subcommands and ships examples:

- outbound, `wirespider ctl watch` — subscribe to the realm's events and print peer and route changes as JSON lines, with an optional `--exec` hook. This is what a daemon's integration script consumes.
- inbound, `wirespider ctl route add|del` — how a daemon pushes a learned prefix back into the realm, so the other nodes and peered realms learn it too.

Two things have to be fixed for external routing to work at all:

Today `allowed_ips` comes only from the server's per-peer computation, and a route via a peer does not widen it, so transit works by accident through the `monitor` and `relay` flags granting the whole network.
A route via a peer must contribute that prefix to the peer's `allowed_ips`; otherwise the kernel silently drops forwarded packets no matter what the routing daemon decides.

WireGuard cannot carry multicast, because cryptokey routing delivers a packet to at most one peer.
Protocols that discover neighbours by multicast therefore cannot run directly on the wirespider interface.
They can run on the VXLAN overlay interface that wirespider already creates, or be configured with explicit unicast neighbours.

## Inspection

`wirespider ctl status` prints what the realm knows, in one of three formats.

- `list`, the default, human readable: the local realm and each peering with its connection state and cursor, then the peers per realm with their addresses, endpoint, NAT type and flags, then the routes.
- `json`, the same data with a stable schema, shared with `ctl watch` so that a snapshot and the deltas that follow it describe the same objects.
- `dot`, for when the picture is easier than the list.

The graph draws one cluster per realm and one edge per peering, because an edge per peer pair is a hairball that says nothing.
Peer to peer edges are only drawn when live link state is available, which is the case when `ctl status` runs against a node rather than a realm server: a node can read the actual handshake state from the WireGuard device, as [src/client/monitor.rs](src/client/monitor.rs) already does, while a server only knows the endpoints it was told about.

## Work order

1. Transport trait plus the in-process implementation, with no behaviour change.
2. CLI restructure and `realm init`.
3. `realms` table, `peers.realmid`, `peers.exported`, `routes.metric`.
4. `sync`, the federation subsystem, `realm invite` and `realm join`.
5. `ctl status` in all three formats, sharing its schema with `ctl watch`.
6. Routing: `allowed_ips` derived from routes, `--route-manager none`, `ctl watch` and the examples.

Steps 1 and 2 are worth doing on their own even if federation is never built.
