CREATE TABLE IF NOT EXISTS state
(
    key     TEXT NOT NULL UNIQUE,
    value   BLOB,
);

INSERT INTO state (key) VALUES ("raft"), ("commited_index");
