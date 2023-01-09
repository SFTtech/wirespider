CREATE TABLE IF NOT EXISTS "keyvalue"
(
    "key"     TEXT NOT NULL UNIQUE,
    "value"   BLOB
);

INSERT INTO "keyvalue" ("key", "value") VALUES ('raft', '{"current_term":0}'), ('last_leader', ''), ('last_applied', 0);
