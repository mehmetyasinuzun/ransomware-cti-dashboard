package store

import (
	"strings"

	"ransomware-cti/internal/model"
)

type GroupStat struct {
	Group       string  `json:"ransomware_group"`
	Count       int     `json:"count"`
	AvgSeverity float64 `json:"avg_severity"`
}

type CountryStat struct {
	Country     string  `json:"country"`
	CountryName string  `json:"country_name"`
	Count       int     `json:"count"`
	AvgSeverity float64 `json:"avg_severity"`
}

type SectorStat struct {
	Sector      string  `json:"target_sector"`
	Count       int     `json:"count"`
	AvgSeverity float64 `json:"avg_severity"`
}

type VectorStat struct {
	AttackVector string `json:"attack_vector"`
	Count        int    `json:"count"`
}

type TechniqueStat struct {
	TechniqueID string `json:"technique_id"`
	Technique   string `json:"technique"`
	Count       int    `json:"count"`
}

type TimePoint struct {
	Period      string  `json:"period"`
	Count       int     `json:"count"`
	AvgSeverity float64 `json:"avg_severity"`
}

type SeverityBin struct {
	Severity int `json:"severity"`
	Count    int `json:"count"`
}

type Summary struct {
	VictimCount  int               `json:"victim_count"`
	GroupCount   int               `json:"group_count"`
	CountryCount int               `json:"country_count"`
	SectorCount  int               `json:"sector_count"`
	IOCCount     int               `json:"ioc_count"`
	AvgSeverity  float64           `json:"avg_severity"`
	HighSevCount int               `json:"high_severity_count"`
	DateMin      string            `json:"date_min"`
	DateMax      string            `json:"date_max"`
	Last30dCount int               `json:"last30d_count"`
	Window       string            `json:"window"`
	Meta         map[string]string `json:"meta"`
}

func floorCond(floor string, existing []string, args []any) ([]string, []any) {
	if floor != "" {
		existing = append(existing, "date >= ?")
		args = append(args, floor)
	}
	return existing, args
}

func whereOf(conds []string) string {
	if len(conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(conds, " AND ")
}

func (db *DB) MaxDate() string {
	var d string
	_ = db.QueryRow(`SELECT COALESCE(MAX(date),'') FROM victims`).Scan(&d)
	return d
}

func (db *DB) Meta() (map[string]string, error) {
	rows, err := db.Query(`SELECT key, value FROM meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (db *DB) Summary(floor string) (Summary, error) {
	var s Summary
	conds, args := floorCond(floor, nil, nil)
	q := `SELECT
		COUNT(*),
		COUNT(DISTINCT ransomware_group),
		COUNT(DISTINCT NULLIF(country,'')),
		COUNT(DISTINCT NULLIF(target_sector,'')),
		COALESCE(AVG(severity),0),
		COALESCE(SUM(CASE WHEN severity>=8 THEN 1 ELSE 0 END),0),
		COALESCE(MIN(date),''),
		COALESCE(MAX(date),'')
		FROM victims` + whereOf(conds)
	if err := db.QueryRow(q, args...).Scan(&s.VictimCount, &s.GroupCount, &s.CountryCount, &s.SectorCount,
		&s.AvgSeverity, &s.HighSevCount, &s.DateMin, &s.DateMax); err != nil {
		return s, err
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM iocs`).Scan(&s.IOCCount)
	maxd := db.MaxDate()
	if maxd != "" {
		_ = db.QueryRow(`SELECT COUNT(*) FROM victims WHERE date >= date(?, '-30 day')`, maxd).Scan(&s.Last30dCount)
	}
	meta, _ := db.Meta()
	s.Meta = meta
	return s, nil
}

func (db *DB) GroupDist(limit int, floor string) ([]GroupStat, error) {
	conds, args := floorCond(floor, nil, nil)
	args = append(args, limit)
	rows, err := db.Query(`SELECT ransomware_group, COUNT(*) c, AVG(severity)
		FROM victims`+whereOf(conds)+` GROUP BY ransomware_group ORDER BY c DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupStat
	for rows.Next() {
		var g GroupStat
		if err := rows.Scan(&g.Group, &g.Count, &g.AvgSeverity); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (db *DB) CountryDist(limit int, floor string) ([]CountryStat, error) {
	conds, args := floorCond(floor, []string{"country <> ''"}, nil)
	args = append(args, limit)
	rows, err := db.Query(`SELECT country, COALESCE(MAX(country_name),''), COUNT(*) c, AVG(severity)
		FROM victims`+whereOf(conds)+` GROUP BY country ORDER BY c DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CountryStat
	for rows.Next() {
		var c CountryStat
		if err := rows.Scan(&c.Country, &c.CountryName, &c.Count, &c.AvgSeverity); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) SectorDist(limit int, floor string) ([]SectorStat, error) {
	conds, args := floorCond(floor, []string{"target_sector <> ''"}, nil)
	args = append(args, limit)
	rows, err := db.Query(`SELECT target_sector, COUNT(*) c, AVG(severity)
		FROM victims`+whereOf(conds)+` GROUP BY target_sector ORDER BY c DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SectorStat
	for rows.Next() {
		var s SectorStat
		if err := rows.Scan(&s.Sector, &s.Count, &s.AvgSeverity); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) VectorDist(floor string) ([]VectorStat, error) {
	conds, args := floorCond(floor, []string{"attack_vector <> ''"}, nil)
	rows, err := db.Query(`SELECT attack_vector, COUNT(*) c FROM victims`+whereOf(conds)+
		` GROUP BY attack_vector ORDER BY c DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VectorStat
	for rows.Next() {
		var v VectorStat
		if err := rows.Scan(&v.AttackVector, &v.Count); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (db *DB) TechniqueDist(limit int, floor string) ([]TechniqueStat, error) {
	conds, args := floorCond(floor, []string{"technique_id <> ''"}, nil)
	args = append(args, limit)
	rows, err := db.Query(`SELECT technique_id, COALESCE(MAX(technique),''), COUNT(*) c FROM victims`+
		whereOf(conds)+` GROUP BY technique_id ORDER BY c DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TechniqueStat
	for rows.Next() {
		var t TechniqueStat
		if err := rows.Scan(&t.TechniqueID, &t.Technique, &t.Count); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) TimeSeries(floor string, daily bool) ([]TimePoint, error) {
	expr, minLen := "substr(date,1,7)", "7"
	if daily {
		expr, minLen = "substr(date,1,10)", "10"
	}
	conds, args := floorCond(floor, []string{"length(date) >= " + minLen}, nil)
	rows, err := db.Query(`SELECT `+expr+` p, COUNT(*) c, AVG(severity)
		FROM victims`+whereOf(conds)+` GROUP BY p ORDER BY p`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimePoint
	for rows.Next() {
		var t TimePoint
		if err := rows.Scan(&t.Period, &t.Count, &t.AvgSeverity); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) SeverityDist(floor string) ([]SeverityBin, error) {
	conds, args := floorCond(floor, nil, nil)
	rows, err := db.Query(`SELECT severity, COUNT(*) FROM victims`+whereOf(conds)+
		` GROUP BY severity ORDER BY severity`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SeverityBin
	for rows.Next() {
		var b SeverityBin
		if err := rows.Scan(&b.Severity, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

type VictimFilter struct {
	Group       string
	Country     string
	Sector      string
	SeverityMin int
	Query       string
	Limit       int
	Offset      int
}

func (db *DB) Victims(f VictimFilter) ([]model.Victim, int, error) {
	var where []string
	var args []any
	if f.Group != "" {
		where = append(where, "ransomware_group = ?")
		args = append(args, f.Group)
	}
	if f.Country != "" {
		where = append(where, "country = ?")
		args = append(args, f.Country)
	}
	if f.Sector != "" {
		where = append(where, "target_sector = ?")
		args = append(args, f.Sector)
	}
	if f.SeverityMin > 0 {
		where = append(where, "severity >= ?")
		args = append(args, f.SeverityMin)
	}
	if f.Query != "" {
		where = append(where, "(victim LIKE ? OR domain LIKE ? OR ransomware_group LIKE ?)")
		q := "%" + f.Query + "%"
		args = append(args, q, q, q)
	}
	clause := whereOf(where)

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM victims`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if f.Limit <= 0 {
		f.Limit = 50
	}
	q := `SELECT id, date, ransomware_group, country, country_name, target_sector, attack_vector,
		technique_id, technique, severity, ioc_ip, ioc_hash, victim, description, domain, claim_url, source_url
		FROM victims` + clause + ` ORDER BY date DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := scanVictims(rows)
	return out, total, rows.Err()
}

type IOCResult struct {
	Query    string         `json:"query"`
	Matches  []model.IOC    `json:"matches"`
	Groups   []string       `json:"groups"`
	Victims  []model.Victim `json:"victims"`
	Severity struct {
		Count int     `json:"count"`
		Avg   float64 `json:"avg"`
		Min   int     `json:"min"`
		Max   int     `json:"max"`
	} `json:"severity"`
}

func (db *DB) IOCSearch(q string) (IOCResult, error) {
	q = strings.TrimSpace(q)
	res := IOCResult{Query: q, Matches: []model.IOC{}, Groups: []string{}, Victims: []model.Victim{}}
	if q == "" {
		return res, nil
	}
	like := q + "%"

	rows, err := db.Query(`SELECT value, type, ransomware_group, malware_family, confidence, first_seen, source
		FROM iocs WHERE value = ? OR value LIKE ? ORDER BY confidence DESC LIMIT 200`, q, like)
	if err != nil {
		return res, err
	}
	groupSet := map[string]bool{}
	for rows.Next() {
		var m model.IOC
		if err := rows.Scan(&m.Value, &m.Type, &m.Group, &m.MalwareFamily, &m.Confidence, &m.FirstSeen, &m.Source); err != nil {
			rows.Close()
			return res, err
		}
		res.Matches = append(res.Matches, m)
		if m.Group != "" {
			groupSet[m.Group] = true
		}
	}
	rows.Close()

	vrows, err := db.Query(`SELECT DISTINCT ransomware_group FROM victims WHERE ioc_ip = ? OR ioc_hash = ?`, q, q)
	if err == nil {
		for vrows.Next() {
			var g string
			if vrows.Scan(&g) == nil && g != "" {
				groupSet[g] = true
			}
		}
		vrows.Close()
	}

	if len(groupSet) == 0 {
		return res, nil
	}
	var groups []string
	var ph []string
	var args []any
	for g := range groupSet {
		groups = append(groups, g)
		ph = append(ph, "?")
		args = append(args, g)
	}
	res.Groups = groups

	vq := `SELECT id, date, ransomware_group, country, country_name, target_sector, attack_vector,
		technique_id, technique, severity, ioc_ip, ioc_hash, victim, description, domain, claim_url, source_url
		FROM victims WHERE ransomware_group IN (` + strings.Join(ph, ",") + `) ORDER BY date DESC LIMIT 100`
	vr, err := db.Query(vq, args...)
	if err != nil {
		return res, err
	}
	res.Victims = scanVictims(vr)
	vr.Close()

	srow := db.QueryRow(`SELECT COUNT(*), COALESCE(AVG(severity),0), COALESCE(MIN(severity),0), COALESCE(MAX(severity),0)
		FROM victims WHERE ransomware_group IN (`+strings.Join(ph, ",")+`)`, args...)
	_ = srow.Scan(&res.Severity.Count, &res.Severity.Avg, &res.Severity.Min, &res.Severity.Max)
	return res, nil
}
