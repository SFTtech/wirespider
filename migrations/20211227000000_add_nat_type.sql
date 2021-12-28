ALTER TABLE peers ADD COLUMN monitor INTEGER;
ALTER TABLE peers ADD COLUMN relay INTEGER;
UPDATE peers SET monitor=FALSE, relay=FALSE WHERE node_type<=2;
UPDATE peers SET monitor=TRUE, relay=FALSE WHERE node_type=3;
UPDATE peers SET monitor=FALSE, relay=TRUE WHERE node_type=4;
UPDATE peers SET monitor=TRUE, relay=TRUE WHERE node_type=5;
ALTER TABLE peers RENAME COLUMN node_type TO nat_type;
ALTER TABLE peers RENAME COLUMN static_endpoint TO current_endpoint;
UPDATE peers SET nat_type=0;