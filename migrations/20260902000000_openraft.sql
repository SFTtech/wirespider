-- openraft storage tables.
CREATE TABLE IF NOT EXISTS "raft_log"
(
    "index" INTEGER PRIMARY KEY,
    term    INTEGER NOT NULL,
    entry   BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS "raft_meta"
(
    "key"   TEXT PRIMARY KEY,
    "value" BLOB
);
