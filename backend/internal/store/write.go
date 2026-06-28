package store

import (
	"ransomware-cti/internal/model"
)

func (db *DB) ReplaceAll(victims []model.Victim, iocs []model.IOC, meta map[string]string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, stmt := range []string{`DELETE FROM victims`, `DELETE FROM iocs`, `DELETE FROM meta`} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}

	vins, err := tx.Prepare(`INSERT INTO victims
		(date, ransomware_group, country, country_name, target_sector, attack_vector,
		 technique_id, technique, severity, ioc_ip, ioc_hash, victim, description, domain, claim_url, source_url)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer vins.Close()
	for _, v := range victims {
		if _, err := vins.Exec(v.Date, v.Group, v.Country, v.CountryName, v.Sector, v.AttackVector,
			v.TechniqueID, v.TechniqueName, v.Severity, v.IOCIP, v.IOCHash, v.Org, v.Description,
			v.Domain, v.ClaimURL, v.SourceURL); err != nil {
			return err
		}
	}

	iins, err := tx.Prepare(`INSERT INTO iocs
		(value, type, ransomware_group, malware_family, confidence, first_seen, source)
		VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer iins.Close()
	for _, ioc := range iocs {
		if _, err := iins.Exec(ioc.Value, ioc.Type, ioc.Group, ioc.MalwareFamily,
			ioc.Confidence, ioc.FirstSeen, ioc.Source); err != nil {
			return err
		}
	}

	mins, err := tx.Prepare(`INSERT INTO meta (key, value) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer mins.Close()
	for k, v := range meta {
		if _, err := mins.Exec(k, v); err != nil {
			return err
		}
	}

	return tx.Commit()
}
