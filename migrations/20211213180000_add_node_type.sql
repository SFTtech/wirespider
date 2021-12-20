ALTER TABLE peers ADD COLUMN node_type INTEGER;
UPDATE peers SET node_type=0;