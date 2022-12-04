CREATE TABLE IF NOT EXISTS log
(
    index   INTEGER NOT NULL UNIQUE,
    term    INTEGER NOT NULL,
    value   TEXT,
);

