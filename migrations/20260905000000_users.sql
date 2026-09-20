-- Users are natural persons owning zero or more nodes (peers).
-- No data migration: existing databases start empty of users; deployments
-- re-create admins through the raft-backed createUser flow.
CREATE TABLE IF NOT EXISTS "users"
(
    "userid"      INTEGER PRIMARY KEY NOT NULL,
    "user_name"   TEXT UNIQUE         NOT NULL,
    "permissions" INTEGER             NOT NULL DEFAULT 0
);

ALTER TABLE "peers" ADD COLUMN "user_id" INTEGER NULL
    REFERENCES users(userid) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS "idx_peers_user" ON "peers"("user_id");
