CREATE TABLE IF NOT EXISTS "keyvalue"
(
    "key"     TEXT NOT NULL UNIQUE,
    "value"   BLOB
);

INSERT INTO "keyvalue" ("key", "value") VALUES ('raft', ''), ('last_leader', ''), ('last_applied', 0);
