ALTER TABLE networks ADD COLUMN network_type TEXT;
UPDATE networks SET network_type="wireguard";
