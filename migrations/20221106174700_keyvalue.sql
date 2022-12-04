CREATE TABLE IF NOT EXISTS state
(
    key     TEXT NOT NULL UNIQUE,
    value   TEXT,
);

INSERT INTO state (key) VALUES ("raft");
