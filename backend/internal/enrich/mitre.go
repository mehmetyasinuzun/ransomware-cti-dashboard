package enrich

import (
	"strings"

	"ransomware-cti/internal/model"
)

const tacticInitialAccess = "TA0001"

var impactTechniques = map[string]bool{
	"T1486": true,
	"T1490": true,
	"T1485": true,
	"T1489": true,
	"T1491": true,
	"T1561": true,
}

func baseTechnique(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return id
}

func HasImpact(techs []model.Technique) bool {
	for _, t := range techs {
		if impactTechniques[baseTechnique(t.TechniqueID)] {
			return true
		}
	}
	return false
}

func InitialAccess(techs []model.Technique) []model.Technique {
	var out []model.Technique
	for _, t := range techs {
		if t.TacticID == tacticInitialAccess {
			out = append(out, t)
		}
	}
	return out
}

func ImpactScore(p model.GroupProfile) float64 {
	if len(p.Techniques) == 0 {
		return 5
	}
	if p.HasImpact {
		return 10
	}
	return 6
}

func PrimaryTechnique(p model.GroupProfile, idx int) model.Technique {
	if len(p.Techniques) == 0 {
		return model.Technique{TacticID: "TA0040", TacticName: "Impact", TechniqueID: "T1486", TechniqueName: "Data Encrypted for Impact"}
	}
	return p.Techniques[idx%len(p.Techniques)]
}

var iaVectorNames = map[string]string{
	"T1566": "Phishing",
	"T1190": "Exploit Public-Facing Application",
	"T1078": "Valid Accounts",
	"T1133": "External Remote Services",
	"T1189": "Drive-by Compromise",
	"T1195": "Supply Chain Compromise",
	"T1199": "Trusted Relationship",
	"T1091": "Replication Through Removable Media",
	"T1200": "Hardware Additions",
}

var canonicalVectors = []string{
	"Phishing",
	"Exploit Public-Facing Application",
	"Valid Accounts",
	"External Remote Services",
}

func AttackVector(p model.GroupProfile, idx int) string {
	var found []string
	seen := map[string]bool{}
	for _, t := range p.Techniques {
		if name, ok := iaVectorNames[baseTechnique(t.TechniqueID)]; ok && !seen[name] {
			seen[name] = true
			found = append(found, name)
		}
	}
	if len(found) > 0 {
		return found[idx%len(found)]
	}
	return canonicalVectors[idx%len(canonicalVectors)]
}
