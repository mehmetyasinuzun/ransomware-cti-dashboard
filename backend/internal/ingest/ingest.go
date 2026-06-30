package ingest

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ransomware-cti/internal/config"
	"ransomware-cti/internal/enrich"
	"ransomware-cti/internal/httpx"
	"ransomware-cti/internal/model"
	"ransomware-cti/internal/sources/abusech"
	"ransomware-cti/internal/sources/ransomwarelive"
	"ransomware-cti/internal/store"
	"ransomware-cti/internal/util"
)

type Stats struct {
	Victims     int
	Groups      int
	IOCs        int
	AvgSeverity float64
	IOCMode     string
	GeneratedAt string
}

var mu sync.Mutex

func Run(ctx context.Context, cfg config.Config) (Stats, error) {
	mu.Lock()
	defer mu.Unlock()
	return runLocked(ctx, cfg)
}

func runLocked(ctx context.Context, cfg config.Config) (Stats, error) {
	var stats Stats
	if !cfg.Refresh {
		if _, err := os.Stat(cfg.DBPath); err == nil {
			log.Printf("snapshot mevcut (%s), atlaniyor. Yeniden cekmek icin REFRESH=true.", cfg.DBPath)
			return stats, nil
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return stats, err
	}
	cacheDir := filepath.Join(cfg.DataDir, "cache")
	_ = os.MkdirAll(cacheDir, 0o755)

	rlHTTP := httpx.New(cfg.ThrottleMS, cfg.MaxRetry, cfg.UserAgent)
	rl := ransomwarelive.New(cfg.RansomwareLiveBase, rlHTTP)

	months := monthRange(cfg.WindowFrom)
	log.Printf("ransomware.live: %s -> simdi (%d ay) cekiliyor", cfg.WindowFrom, len(months))
	floor := cfg.WindowFrom + "-01"
	var victims []model.Victim
	seen := map[string]bool{}
	for _, m := range months {
		vs, err := rl.Month(ctx, m.year, m.month)
		if err != nil {
			log.Printf("  %d/%02d atlandi: %v", m.year, m.month, err)
			continue
		}
		added := 0
		for _, v := range vs {
			if v.Date == "" || v.Date < floor {
				continue
			}
			key := v.SourceURL
			if key == "" {
				key = v.Group + "|" + v.Org + "|" + v.Date
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			victims = append(victims, v)
			added++
		}
		log.Printf("  %d/%02d: %d kayit (+%d benzersiz)", m.year, m.month, len(vs), added)
	}
	if len(victims) == 0 {
		return stats, fmt.Errorf("hic kurban kaydi cekilemedi")
	}
	log.Printf("toplam %d benzersiz kurban", len(victims))

	groups := distinctGroups(victims)
	log.Printf("%d benzersiz grup, MITRE profilleri (cache: %s)", len(groups), cacheDir)
	profiles := map[string]model.GroupProfile{}
	for i, g := range groups {
		p, err := loadGroupProfile(ctx, rl, cacheDir, g)
		if err != nil {
			p = model.GroupProfile{Name: g}
		}
		p.InitialAccess = enrich.InitialAccess(p.Techniques)
		p.HasImpact = enrich.HasImpact(p.Techniques)
		profiles[g] = p
		if (i+1)%25 == 0 {
			log.Printf("  ...%d/%d grup profili", i+1, len(groups))
		}
	}

	abHTTP := httpx.New(500, cfg.MaxRetry, cfg.UserAgent)
	ab := abusech.New(cfg.AbuseKey, abHTTP)
	var iocMode string
	var exportIdx map[string][]model.IOC
	if ab.Enabled() {
		iocMode = "real (abuse.ch API)"
	} else {
		wanted := map[string]bool{}
		for _, g := range groups {
			for _, fam := range abusech.CandidateFamilies(g) {
				wanted[fam] = true
			}
		}
		log.Printf("IOC: ThreatFox tam export indiriliyor (key'siz gercek veri)...")
		idx, err := ab.LoadExport(ctx, cacheDir, cfg.Refresh, wanted)
		if err != nil {
			log.Printf("  export alinamadi (%v); sentetik IOC'a dusuluyor", err)
			iocMode = "synthetic (export erisilemedi)"
		} else {
			exportIdx = idx
			iocMode = "real (abuse.ch ThreatFox)"
		}
	}
	log.Printf("IOC modu: %s", iocMode)

	groupIOCs := map[string][]model.IOC{}
	var allIOCs []model.IOC
	matched := 0
	for _, g := range groups {
		var iocs []model.IOC
		switch {
		case ab.Enabled():
			iocs = loadIOCs(ctx, ab, cacheDir, g, cfg.Refresh, cfg.IOCPerGroup)
		case exportIdx != nil:
			iocs = abusech.IOCsFromIndex(g, exportIdx, cfg.IOCPerGroup)
		default:
			iocs = enrich.SyntheticIOCs(g, 4)
		}
		if len(iocs) > 0 {
			matched++
		}
		groupIOCs[g] = iocs
		allIOCs = append(allIOCs, iocs...)
	}
	log.Printf("toplam %d IOC (%d/%d grup eslesti)", len(allIOCs), matched, len(groups))

	counts := map[string]int{}
	for _, v := range victims {
		counts[v.Group]++
	}
	maxCount := 1
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	maxDate := maxVictimDate(victims)

	perGroupIdx := map[string]int{}
	for i := range victims {
		v := &victims[i]
		v.CountryName = enrich.CountryEN(v.Country)
		v.Sector = enrich.SectorLabel(v.Sector)
		p := profiles[v.Group]
		idx := perGroupIdx[v.Group]
		perGroupIdx[v.Group]++

		v.AttackVector = enrich.AttackVector(p, idx)
		tech := enrich.PrimaryTechnique(p, idx)
		v.TechniqueID = tech.TechniqueID
		v.TechniqueName = tech.TechniqueName

		ips, hashes := splitIOC(groupIOCs[v.Group])
		if len(ips) > 0 {
			v.IOCIP = ips[idx%len(ips)]
		}
		if len(hashes) > 0 {
			v.IOCHash = hashes[idx%len(hashes)]
		}

		t, _ := util.ParseFlexible(v.Date)
		v.Severity = enrich.ComputeSeverity(enrich.SeverityInput{
			SectorScore:    enrich.SectorScore(v.Sector),
			GroupScore:     enrich.GroupScore(counts[v.Group], maxCount),
			ImpactScore:    enrich.ImpactScore(p),
			FreshnessScore: enrich.FreshnessScore(t, maxDate),
			IOCScore:       enrich.IOCScore(len(groupIOCs[v.Group]) > 0),
		})
	}

	last := months[len(months)-1]
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	meta := map[string]string{
		"generated_at": generatedAt,
		"victim_count": strconv.Itoa(len(victims)),
		"ioc_count":    strconv.Itoa(len(allIOCs)),
		"group_count":  strconv.Itoa(len(groups)),
		"window_from":  cfg.WindowFrom,
		"window_to":    fmt.Sprintf("%04d-%02d", last.year, last.month),
		"ioc_mode":     iocMode,
		"avg_severity": fmt.Sprintf("%.2f", avgSeverity(victims)),
		"sources":      "ransomware.live v2; abuse.ch ThreatFox & MalwareBazaar; MITRE ATT&CK",
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return stats, err
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		return stats, err
	}
	if err := db.ReplaceAll(victims, allIOCs, meta); err != nil {
		return stats, err
	}
	log.Printf("SQLite yazildi: %s", cfg.DBPath)

	if err := exportCSV(filepath.Join(cfg.DataDir, "dataset.csv"), victims); err != nil {
		return stats, err
	}
	if err := exportJSON(filepath.Join(cfg.DataDir, "dataset.json"), victims); err != nil {
		return stats, err
	}

	stats = Stats{
		Victims:     len(victims),
		Groups:      len(groups),
		IOCs:        len(allIOCs),
		AvgSeverity: avgSeverity(victims),
		IOCMode:     iocMode,
		GeneratedAt: generatedAt,
	}
	log.Printf("OZET: %d kurban | %d grup | %d IOC | ort. severity %.2f | %s",
		stats.Victims, stats.Groups, stats.IOCs, stats.AvgSeverity, stats.IOCMode)
	return stats, nil
}

func ReingestIOCs(ctx context.Context, cfg config.Config) (Stats, error) {
	mu.Lock()
	defer mu.Unlock()
	var stats Stats

	cacheDir := filepath.Join(cfg.DataDir, "cache")
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return stats, err
	}
	defer db.Close()

	victims, err := db.AllVictims()
	if err != nil {
		return stats, err
	}
	if len(victims) == 0 {
		return stats, fmt.Errorf("DB'de kurban yok; once tam pipeline calistirin")
	}
	groups := distinctGroups(victims)
	log.Printf("IOC yeniden-ingest: %d kurban / %d grup (kurban DB'den, sadece IOC yenileniyor)", len(victims), len(groups))

	abHTTP := httpx.New(500, cfg.MaxRetry, cfg.UserAgent)
	ab := abusech.New(cfg.AbuseKey, abHTTP)
	var iocMode string
	var exportIdx map[string][]model.IOC
	if ab.Enabled() {
		iocMode = "real (abuse.ch API)"
	} else {
		wanted := map[string]bool{}
		for _, g := range groups {
			for _, fam := range abusech.CandidateFamilies(g) {
				wanted[fam] = true
			}
		}
		idx, err := ab.LoadExport(ctx, cacheDir, cfg.Refresh, wanted)
		if err != nil {
			return stats, fmt.Errorf("ThreatFox export alinamadi: %w", err)
		}
		exportIdx = idx
		iocMode = "real (abuse.ch ThreatFox)"
	}

	groupIOCs := map[string][]model.IOC{}
	var allIOCs []model.IOC
	for _, g := range groups {
		var iocs []model.IOC
		if ab.Enabled() {
			iocs = loadIOCs(ctx, ab, cacheDir, g, true, cfg.IOCPerGroup)
		} else {
			iocs = abusech.IOCsFromIndex(g, exportIdx, cfg.IOCPerGroup)
		}
		groupIOCs[g] = iocs
		allIOCs = append(allIOCs, iocs...)
	}

	perGroupIdx := map[string]int{}
	for i := range victims {
		v := &victims[i]
		v.IOCIP, v.IOCHash = "", ""
		ips, hashes := splitIOC(groupIOCs[v.Group])
		idx := perGroupIdx[v.Group]
		perGroupIdx[v.Group]++
		if len(ips) > 0 {
			v.IOCIP = ips[idx%len(ips)]
		}
		if len(hashes) > 0 {
			v.IOCHash = hashes[idx%len(hashes)]
		}
	}

	meta, _ := db.Meta()
	if meta == nil {
		meta = map[string]string{}
	}
	meta["ioc_count"] = strconv.Itoa(len(allIOCs))
	meta["ioc_mode"] = iocMode
	meta["generated_at"] = time.Now().UTC().Format(time.RFC3339)
	if err := db.ReplaceAll(victims, allIOCs, meta); err != nil {
		return stats, err
	}
	if err := exportCSV(filepath.Join(cfg.DataDir, "dataset.csv"), victims); err != nil {
		return stats, err
	}
	if err := exportJSON(filepath.Join(cfg.DataDir, "dataset.json"), victims); err != nil {
		return stats, err
	}

	stats = Stats{Victims: len(victims), Groups: len(groups), IOCs: len(allIOCs), IOCMode: iocMode, GeneratedAt: meta["generated_at"]}
	log.Printf("IOC yeniden-ingest bitti: %d IOC | %s", stats.IOCs, iocMode)
	return stats, nil
}

type ym struct{ year, month int }

func monthRange(from string) []ym {
	t, ok := util.ParseFlexible(from + "-01")
	if !ok {
		t = time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)
	}
	now := time.Now().UTC()
	y, m := t.Year(), int(t.Month())
	var out []ym
	for {
		out = append(out, ym{y, m})
		if y == now.Year() && m == int(now.Month()) {
			break
		}
		m++
		if m > 12 {
			m = 1
			y++
		}
		if y > now.Year()+1 {
			break
		}
	}
	return out
}

func distinctGroups(vs []model.Victim) []string {
	set := map[string]bool{}
	var out []string
	for _, v := range vs {
		if !set[v.Group] {
			set[v.Group] = true
			out = append(out, v.Group)
		}
	}
	return out
}

func loadGroupProfile(ctx context.Context, rl *ransomwarelive.Client, cacheDir, g string) (model.GroupProfile, error) {
	path := filepath.Join(cacheDir, "group_"+safeName(g)+".json")
	if data, err := os.ReadFile(path); err == nil {
		var p model.GroupProfile
		if json.Unmarshal(data, &p) == nil {
			return p, nil
		}
	}
	p, err := rl.Group(ctx, g)
	if err != nil {
		return model.GroupProfile{Name: g}, err
	}
	if data, err := json.Marshal(p); err == nil {
		_ = os.WriteFile(path, data, 0o644)
	}
	return p, nil
}

func loadIOCs(ctx context.Context, ab *abusech.Client, cacheDir, g string, refresh bool, limit int) []model.IOC {
	path := filepath.Join(cacheDir, "ioc_"+safeName(g)+".json")
	if !refresh {
		if data, err := os.ReadFile(path); err == nil {
			var iocs []model.IOC
			if json.Unmarshal(data, &iocs) == nil {
				return iocs
			}
		}
	}
	iocs, _ := ab.FamilyIOCs(ctx, g, limit)
	if data, err := json.Marshal(iocs); err == nil {
		_ = os.WriteFile(path, data, 0o644)
	}
	return iocs
}

func splitIOC(iocs []model.IOC) (ips, hashes []string) {
	for _, i := range iocs {
		switch i.Type {
		case "ip":
			ips = append(ips, i.Value)
		case "hash":
			hashes = append(hashes, i.Value)
		}
	}
	return
}

func maxVictimDate(vs []model.Victim) time.Time {
	max := time.Time{}
	for _, v := range vs {
		if t, ok := util.ParseFlexible(v.Date); ok && t.After(max) {
			max = t
		}
	}
	if max.IsZero() {
		return time.Now().UTC()
	}
	return max
}

func avgSeverity(vs []model.Victim) float64 {
	if len(vs) == 0 {
		return 0
	}
	sum := 0
	for _, v := range vs {
		sum += v.Severity
	}
	return float64(sum) / float64(len(vs))
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

type datasetRow struct {
	Date         string `json:"date"`
	Group        string `json:"ransomware_group"`
	Country      string `json:"country"`
	Sector       string `json:"target_sector"`
	AttackVector string `json:"attack_vector"`
	Technique    string `json:"technique"`
	Severity     int    `json:"severity"`
	IOCIP        string `json:"ioc_ip"`
	IOCHash      string `json:"ioc_hash"`
}

func toRow(v model.Victim) datasetRow {
	return datasetRow{
		Date: v.Date, Group: v.Group, Country: v.Country, Sector: v.Sector,
		AttackVector: v.AttackVector, Technique: v.TechniqueName, Severity: v.Severity,
		IOCIP: v.IOCIP, IOCHash: v.IOCHash,
	}
}

func exportCSV(path string, vs []model.Victim) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"date", "ransomware_group", "country", "target_sector", "attack_vector", "technique", "severity", "ioc_ip", "ioc_hash"}); err != nil {
		return err
	}
	for _, v := range vs {
		r := toRow(v)
		if err := w.Write([]string{r.Date, r.Group, r.Country, r.Sector, r.AttackVector, r.Technique, strconv.Itoa(r.Severity), r.IOCIP, r.IOCHash}); err != nil {
			return err
		}
	}
	return w.Error()
}

func exportJSON(path string, vs []model.Victim) error {
	rows := make([]datasetRow, len(vs))
	for i, v := range vs {
		rows[i] = toRow(v)
	}
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
