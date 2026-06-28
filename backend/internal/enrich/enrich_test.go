package enrich

import (
	"testing"
	"time"

	"ransomware-cti/internal/model"
)

func TestComputeSeverityClamp(t *testing.T) {
	high := ComputeSeverity(SeverityInput{10, 10, 10, 10, 10})
	if high != 10 {
		t.Fatalf("tum 10 girdisi 10 vermeli, %d aldim", high)
	}
	low := ComputeSeverity(SeverityInput{0, 0, 0, 0, 0})
	if low != 1 {
		t.Fatalf("tum 0 girdisi 1'e sikismali, %d aldim", low)
	}
	mid := ComputeSeverity(SeverityInput{5, 5, 5, 5, 5})
	if mid != 5 {
		t.Fatalf("tum 5 girdisi 5 vermeli, %d aldim", mid)
	}
}

func TestFreshnessScore(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if s := FreshnessScore(now, now); s < 9.9 {
		t.Fatalf("ayni gun tazelik ~10 olmali, %.2f aldim", s)
	}
	old := now.AddDate(-2, 0, 0)
	if s := FreshnessScore(old, now); s < 1 {
		t.Fatalf("tazelik 1'in altina dusmemeli, %.2f aldim", s)
	}
	recent := now.AddDate(0, 0, -3)
	if FreshnessScore(recent, now) <= FreshnessScore(old, now) {
		t.Fatal("yeni saldiri eski saldiridan daha taze olmali")
	}
}

func TestGroupScore(t *testing.T) {
	if s := GroupScore(100, 100); s < 9.9 {
		t.Fatalf("en aktif grup ~10 olmali, %.2f aldim", s)
	}
	if s := GroupScore(5, 1); s != 5 {
		t.Fatalf("maxCount<=1 icin notr 5 beklenir, %.2f aldim", s)
	}
	if GroupScore(2, 100) >= GroupScore(80, 100) {
		t.Fatal("daha cok kurbani olan grup daha yuksek puan almali")
	}
}

func TestSectorScore(t *testing.T) {
	if SectorScore("Healthcare") < 9 {
		t.Fatal("kritik sektor yuksek puan almali")
	}
	if SectorScore("Not Found") != 5 {
		t.Fatal("bilinmeyen sektor notr 5 almali")
	}
	if !IsCriticalSector("Energy") {
		t.Fatal("Energy kritik altyapi sayilmali")
	}
}

func TestAttackVector(t *testing.T) {
	p := model.GroupProfile{Techniques: []model.Technique{{TechniqueID: "T1566"}}}
	if v := AttackVector(p, 0); v != "Phishing" {
		t.Fatalf("T1566 -> Phishing beklenir, %q aldim", v)
	}
	empty := model.GroupProfile{}
	if v := AttackVector(empty, 0); v == "" || v == "Unknown" {
		t.Fatalf("bos profil canonical vektore dusmeli, %q aldim", v)
	}
}

func TestPrimaryTechnique(t *testing.T) {
	if tk := PrimaryTechnique(model.GroupProfile{}, 0); tk.TechniqueID != "T1486" {
		t.Fatalf("bos profil T1486'ya dusmeli, %q aldim", tk.TechniqueID)
	}
	p := model.GroupProfile{Techniques: []model.Technique{{TechniqueID: "T1078"}, {TechniqueID: "T1486"}}}
	if PrimaryTechnique(p, 0).TechniqueID == PrimaryTechnique(p, 1).TechniqueID {
		t.Fatal("teknik kayit indeksine gore donmeli (cesitlilik)")
	}
}

func TestHasImpact(t *testing.T) {
	if !HasImpact([]model.Technique{{TechniqueID: "T1486"}}) {
		t.Fatal("T1486 impact olarak taninmali")
	}
	if HasImpact([]model.Technique{{TechniqueID: "T1059.001"}}) {
		t.Fatal("T1059.001 impact degil")
	}
}

func TestCountryNames(t *testing.T) {
	if CountryEN("US") != "United States" {
		t.Fatalf("US -> United States beklenir, %q aldim", CountryEN("US"))
	}
	if CountryTR("DE") == "DE" {
		t.Fatal("DE icin Turkce ad cozulmeli")
	}
	if CountryEN("") != "" {
		t.Fatal("bos kod oldugu gibi donmeli")
	}
}

func TestSyntheticIOCsDeterministic(t *testing.T) {
	a := SyntheticIOCs("lockbit", 4)
	b := SyntheticIOCs("lockbit", 4)
	if len(a) != 4 || len(b) != 4 {
		t.Fatalf("4 IOC beklenir, %d/%d aldim", len(a), len(b))
	}
	for i := range a {
		if a[i].Value != b[i].Value {
			t.Fatal("sentetik IOC uretimi deterministik olmali")
		}
		if a[i].Source != "synthetic" {
			t.Fatal("sentetik IOC kaynagi 'synthetic' olmali")
		}
	}
}
