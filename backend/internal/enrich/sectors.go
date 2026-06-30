package enrich

import "strings"

var sectorScores = map[string]float64{
	"healthcare":                    10,
	"healthcare and public health":  10,
	"energy":                        10,
	"financial services":           10,
	"finance":                       10,
	"public sector":                 9,
	"government":                    9,
	"government services":           9,
	"water and wastewater":          10,
	"manufacturing":                 9,
	"critical manufacturing":        10,
	"defense":                       10,
	"defense industrial base":       10,
	"emergency services":            9,
	"telecommunication":             8,
	"telecommunications":            8,
	"communications":                8,
	"transportation/logistics":      8,
	"transportation":                8,
	"logistics":                     8,
	"agriculture and food production": 8,
	"food and agriculture":          8,
	"chemical":                      9,
	"nuclear":                       10,
	"technology":                    7,
	"information technology":        7,
	"education":                     7,
	"business services":             5,
	"consumer services":             5,
	"construction":                  5,
	"retail":                        5,
	"commercial facilities":         5,
	"hospitality":                   4,
	"real estate":                   4,
}

var criticalSectors = map[string]bool{
	"healthcare": true, "healthcare and public health": true, "energy": true,
	"financial services": true, "finance": true, "public sector": true,
	"government": true, "government services": true, "water and wastewater": true,
	"manufacturing": true, "critical manufacturing": true, "defense": true,
	"defense industrial base": true, "emergency services": true, "telecommunication": true,
	"telecommunications": true, "communications": true, "transportation/logistics": true,
	"transportation": true, "agriculture and food production": true,
	"food and agriculture": true, "chemical": true, "nuclear": true,
	"information technology": true, "technology": true,
}

func normSector(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func SectorScore(activity string) float64 {
	n := normSector(activity)
	if n == "" || n == "not found" || n == "unknown" {
		return 5
	}
	if v, ok := sectorScores[n]; ok {
		return v
	}
	for key, v := range sectorScores {
		if strings.Contains(n, key) {
			return v
		}
	}
	return 5
}

func IsCriticalSector(activity string) bool {
	return criticalSectors[normSector(activity)]
}

func SectorLabel(activity string) string {
	n := normSector(activity)
	if n == "" || n == "not found" {
		return "Unknown"
	}
	return strings.TrimSpace(activity)
}
