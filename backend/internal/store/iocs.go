package store

import (
	"database/sql"

	"ransomware-cti/internal/model"
)

type IOCFilter struct {
	Type   string
	Group  string
	Query  string
	Limit  int
	Offset int
}

func scanIOCs(rows *sql.Rows) []model.IOC {
	out := []model.IOC{}
	for rows.Next() {
		var m model.IOC
		if err := rows.Scan(&m.Value, &m.Type, &m.Group, &m.MalwareFamily, &m.Confidence, &m.FirstSeen, &m.Source); err != nil {
			continue
		}
		out = append(out, m)
	}
	return out
}

// IOCList: tum gostergeleri zaman sirasiyla (en yeni once), filtreli ve sayfali doner.
func (db *DB) IOCList(f IOCFilter) ([]model.IOC, int, error) {
	var where []string
	var args []any
	if f.Type != "" {
		where = append(where, "type = ?")
		args = append(args, f.Type)
	}
	if f.Group != "" {
		where = append(where, "ransomware_group = ?")
		args = append(args, f.Group)
	}
	if f.Query != "" {
		where = append(where, "(value LIKE ? OR malware_family LIKE ? OR ransomware_group LIKE ?)")
		q := "%" + f.Query + "%"
		args = append(args, q, q, q)
	}
	clause := whereOf(where)

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM iocs`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if f.Limit <= 0 {
		f.Limit = 50
	}
	q := `SELECT value, type, ransomware_group, malware_family, confidence, first_seen, source
		FROM iocs` + clause + ` ORDER BY (first_seen = '') ASC, first_seen DESC, value LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	return scanIOCs(rows), total, rows.Err()
}

// AllVictims: tum kurban kayitlarini id sirasiyla doner (IOC yeniden-ingest icin).
func (db *DB) AllVictims() ([]model.Victim, error) {
	rows, err := db.Query(`SELECT id, date, ransomware_group, country, country_name, target_sector, attack_vector,
		technique_id, technique, severity, ioc_ip, ioc_hash, victim, description, domain, claim_url, source_url
		FROM victims ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVictims(rows), rows.Err()
}

// IOCGroups: gostergesi olan gruplar ve sayilari (filtre acilir menusu icin).
func (db *DB) IOCGroups() ([]GroupStat, error) {
	rows, err := db.Query(`SELECT ransomware_group, COUNT(*) c FROM iocs
		GROUP BY ransomware_group ORDER BY c DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupStat
	for rows.Next() {
		var g GroupStat
		if err := rows.Scan(&g.Group, &g.Count); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
