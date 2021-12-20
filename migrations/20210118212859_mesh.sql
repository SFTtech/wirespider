CREATE TABLE IF NOT EXISTS peers
(
    peerid           INTEGER PRIMARY KEY NOT NULL,
    peer_name        TEXT UNIQUE         NOT NULL,
    token            BLOB UNIQUE         NOT NULL,
    pubkey           BLOB UNIQUE         NULL,
    permissions      INTEGER             NOT NULL DEFAULT 0,
    static_endpoint  TEXT                NULL
);

CREATE TABLE IF NOT EXISTS routes
(
    routeid     INTEGER PRIMARY KEY NOT NULL,
    addressid   INTEGER             NOT NULL,
    destination TEXT                NOT NULL,
    FOREIGN KEY(addressid) REFERENCES addresses(addressid)
);


CREATE TABLE IF NOT EXISTS networks
(
    networkid   INTEGER PRIMARY KEY NOT NULL,
    network     TEXT UNIQUE         NOT NULL,
    ipv6        BOOLEAN             NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS addresses
(
    addressid   INTEGER PRIMARY KEY NOT NULL,
    networkid   INTEGER             NOT NULL,
    peerid      INTEGER             NOT NULL,
    ip_address  TEXT UNIQUE         NOT NULL,
    FOREIGN KEY(peerid) REFERENCES peers(peerid) ON DELETE CASCADE,
    FOREIGN KEY(networkid) REFERENCES networks(networkid) ON DELETE CASCADE
);
