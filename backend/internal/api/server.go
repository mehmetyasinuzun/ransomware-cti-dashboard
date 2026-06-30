package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"ransomware-cti/internal/config"
	"ransomware-cti/internal/ingest"
	"ransomware-cti/internal/store"
	"ransomware-cti/internal/util"
)

type Server struct {
	db  *store.DB
	cfg config.Config
	rf  refreshState
}

type refreshState struct {
	mu      sync.Mutex
	running bool
	lastRun string
	lastErr string
	stats   *ingest.Stats
}

func New(db *store.DB, cfg config.Config) *Server {
	return &Server{db: db, cfg: cfg}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/summary", s.summary)
	mux.HandleFunc("GET /api/groups", s.groups)
	mux.HandleFunc("GET /api/countries", s.countries)
	mux.HandleFunc("GET /api/sectors", s.sectors)
	mux.HandleFunc("GET /api/attack-vectors", s.vectors)
	mux.HandleFunc("GET /api/techniques", s.techniques)
	mux.HandleFunc("GET /api/timeseries", s.timeseries)
	mux.HandleFunc("GET /api/severity", s.severity)
	mux.HandleFunc("GET /api/victims", s.victims)
	mux.HandleFunc("GET /api/ioc", s.ioc)
	mux.HandleFunc("GET /api/iocs", s.iocs)
	mux.HandleFunc("GET /api/ioc-groups", s.iocGroups)
	mux.HandleFunc("POST /api/refresh", s.refresh)
	mux.HandleFunc("GET /api/refresh/status", s.refreshStatus)
	return cors(mux)
}

func (s *Server) floorFor(r *http.Request) string {
	var days int
	switch r.URL.Query().Get("window") {
	case "30d":
		days = 30
	case "180d":
		days = 180
	case "365d":
		days = 365
	default:
		return ""
	}
	maxd := s.db.MaxDate()
	if maxd == "" {
		return ""
	}
	t, ok := util.ParseFlexible(maxd)
	if !ok {
		return ""
	}
	return t.AddDate(0, 0, -days).Format("2006-01-02")
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	meta, _ := s.db.Meta()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "meta": meta})
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.Summary(s.floorFor(r))
	if err == nil {
		res.Window = r.URL.Query().Get("window")
	}
	respond(w, res, err)
}

func (s *Server) groups(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.GroupDist(qInt(r, "limit", 12), s.floorFor(r))
	respond(w, res, err)
}

func (s *Server) countries(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.CountryDist(qInt(r, "limit", 40), s.floorFor(r))
	respond(w, res, err)
}

func (s *Server) sectors(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.SectorDist(qInt(r, "limit", 20), s.floorFor(r))
	respond(w, res, err)
}

func (s *Server) vectors(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.VectorDist(s.floorFor(r))
	respond(w, res, err)
}

func (s *Server) techniques(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.TechniqueDist(qInt(r, "limit", 12), s.floorFor(r))
	respond(w, res, err)
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	daily := r.URL.Query().Get("window") == "30d"
	res, err := s.db.TimeSeries(s.floorFor(r), daily)
	respond(w, res, err)
}

func (s *Server) severity(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.SeverityDist(s.floorFor(r))
	respond(w, res, err)
}

func (s *Server) victims(w http.ResponseWriter, r *http.Request) {
	f := store.VictimFilter{
		Group:       r.URL.Query().Get("group"),
		Country:     r.URL.Query().Get("country"),
		Sector:      r.URL.Query().Get("sector"),
		SeverityMin: qInt(r, "severity_min", 0),
		Query:       r.URL.Query().Get("q"),
		Limit:       qInt(r, "limit", 50),
		Offset:      qInt(r, "offset", 0),
	}
	rows, total, err := s.db.Victims(f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "limit": f.Limit, "offset": f.Offset, "items": rows})
}

func (s *Server) ioc(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.IOCSearch(r.URL.Query().Get("q"))
	respond(w, res, err)
}

func (s *Server) iocs(w http.ResponseWriter, r *http.Request) {
	f := store.IOCFilter{
		Type:   r.URL.Query().Get("type"),
		Group:  r.URL.Query().Get("group"),
		Query:  r.URL.Query().Get("q"),
		Limit:  qInt(r, "limit", 50),
		Offset: qInt(r, "offset", 0),
	}
	items, total, err := s.db.IOCList(f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "limit": f.Limit, "offset": f.Offset, "items": items})
}

func (s *Server) iocGroups(w http.ResponseWriter, r *http.Request) {
	res, err := s.db.IOCGroups()
	respond(w, res, err)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	started := s.TriggerRefresh()
	st := s.statusMap()
	st["started"] = started
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) refreshStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.statusMap())
}

func (s *Server) statusMap() map[string]any {
	s.rf.mu.Lock()
	defer s.rf.mu.Unlock()
	m := map[string]any{
		"running":  s.rf.running,
		"last_run": s.rf.lastRun,
		"error":    s.rf.lastErr,
	}
	if s.rf.stats != nil {
		m["victims"] = s.rf.stats.Victims
		m["iocs"] = s.rf.stats.IOCs
		m["ioc_mode"] = s.rf.stats.IOCMode
	}
	return m
}

func (s *Server) TriggerRefresh() bool {
	s.rf.mu.Lock()
	if s.rf.running {
		s.rf.mu.Unlock()
		return false
	}
	s.rf.running = true
	s.rf.mu.Unlock()

	go func() {
		cfg := s.cfg
		cfg.Refresh = true
		log.Printf("veri tazeleme basladi")
		stats, err := ingest.Run(context.Background(), cfg)
		s.rf.mu.Lock()
		s.rf.running = false
		s.rf.lastRun = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			s.rf.lastErr = err.Error()
			log.Printf("veri tazeleme hatasi: %v", err)
		} else {
			s.rf.lastErr = ""
			st := stats
			s.rf.stats = &st
			log.Printf("veri tazeleme bitti: %d kurban", stats.Victims)
		}
		s.rf.mu.Unlock()
	}()
	return true
}

func (s *Server) StartScheduler() {
	if s.cfg.RefreshIntervalHrs <= 0 {
		return
	}
	d := time.Duration(s.cfg.RefreshIntervalHrs) * time.Hour
	log.Printf("otomatik tazeleme acik: her %d saatte bir", s.cfg.RefreshIntervalHrs)
	go func() {
		t := time.NewTicker(d)
		defer t.Stop()
		for range t.C {
			s.TriggerRefresh()
		}
	}()
}

func (s *Server) SeedIfEmpty() {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM victims`).Scan(&n); err == nil && n == 0 {
		log.Printf("veritabani bos, ilk veri cekimi tetikleniyor")
		s.TriggerRefresh()
	}
}

func respond(w http.ResponseWriter, v any, err error) {
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func qInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
