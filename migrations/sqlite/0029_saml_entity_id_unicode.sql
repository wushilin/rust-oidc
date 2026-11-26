-- An Entity ID may again hold any characters, not only ASCII as 0027 says. The
-- column is TEXT here and holds them already, so nothing changes; MySQL
-- widens its column's character set and rebuilds its keys in this migration.
SELECT 1;
