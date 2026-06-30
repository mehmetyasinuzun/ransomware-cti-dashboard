package enrich

import (
	"math"
	"time"
)

const (
	wSector    = 0.30
	wGroup     = 0.25
	wImpact    = 0.15
	wFreshness = 0.15
	wIOC       = 0.15
)

type SeverityInput struct {
	SectorScore    float64
	GroupScore     float64
	ImpactScore    float64
	FreshnessScore float64
	IOCScore       float64
}

func ComputeSeverity(in SeverityInput) int {
	raw := wSector*in.SectorScore +
		wGroup*in.GroupScore +
		wImpact*in.ImpactScore +
		wFreshness*in.FreshnessScore +
		wIOC*in.IOCScore
	s := int(math.Round(raw))
	if s < 1 {
		s = 1
	}
	if s > 10 {
		s = 10
	}
	return s
}

func FreshnessScore(date, maxDate time.Time) float64 {
	days := maxDate.Sub(date).Hours() / 24
	if days < 0 {
		days = 0
	}
	score := 10 * math.Exp(-days/120)
	if score < 1 {
		return 1
	}
	return score
}

func IOCScore(hasIOC bool) float64 {
	if hasIOC {
		return 10
	}
	return 2
}

func GroupScore(groupCount, maxGroupCount int) float64 {
	if maxGroupCount <= 1 {
		return 5
	}
	return 10 * math.Log1p(float64(groupCount)) / math.Log1p(float64(maxGroupCount))
}
