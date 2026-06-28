package store

import (
	"database/sql"

	"ransomware-cti/internal/model"
)

func scanVictims(rows *sql.Rows) []model.Victim {
	out := []model.Victim{}
	for rows.Next() {
		var v model.Victim
		if err := rows.Scan(&v.ID, &v.Date, &v.Group, &v.Country, &v.CountryName, &v.Sector,
			&v.AttackVector, &v.TechniqueID, &v.TechniqueName, &v.Severity, &v.IOCIP, &v.IOCHash,
			&v.Org, &v.Description, &v.Domain, &v.ClaimURL, &v.SourceURL); err != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}
