-- Raft server nodes are also recorded as peers: the raft pubkey links a
-- running raft node (NodeId = raft pubkey) to its peer row and owning user.
-- SQLite cannot ALTER ADD a UNIQUE column; the unique index is separate.
ALTER TABLE "peers" ADD COLUMN "raft_pubkey" BLOB NULL;
CREATE UNIQUE INDEX IF NOT EXISTS "idx_peers_raft_pubkey" ON "peers"("raft_pubkey");
