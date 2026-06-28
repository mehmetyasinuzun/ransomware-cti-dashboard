package store

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS victims (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	date          TEXT NOT NULL,
	ransomware_group TEXT NOT NULL,
	country       TEXT,
	country_name  TEXT,
	target_sector TEXT,
	attack_vector TEXT,
	technique_id  TEXT,
	technique     TEXT,
	severity      INTEGER NOT NULL,
	ioc_ip        TEXT,
	ioc_hash      TEXT,
	victim        TEXT,
	description   TEXT,
	domain        TEXT,
	claim_url     TEXT,
	source_url    TEXT
);
CREATE INDEX IF NOT EXISTS idx_victims_group   ON victims(ransomware_group);
CREATE INDEX IF NOT EXISTS idx_victims_country ON victims(country);
CREATE INDEX IF NOT EXISTS idx_victims_sector  ON victims(target_sector);
CREATE INDEX IF NOT EXISTS idx_victims_date    ON victims(date);
CREATE INDEX IF NOT EXISTS idx_victims_sev     ON victims(severity);

CREATE TABLE IF NOT EXISTS iocs (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	value         TEXT NOT NULL,
	type          TEXT NOT NULL,
	ransomware_group TEXT NOT NULL,
	malware_family TEXT,
	confidence    INTEGER,
	first_seen    TEXT,
	source        TEXT
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_group ON iocs(ransomware_group);
CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(type);

CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT
);
`

func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(8000)&_pragma=foreign_keys(1)", filepath.ToSlash(path))
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := sdb.Ping(); err != nil {
		return nil, err
	}
	return &DB{sdb}, nil
}

func (db *DB) Migrate() error {
	_, err := db.Exec(schema)
	return err
}
