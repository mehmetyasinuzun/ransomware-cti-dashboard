package abusech

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"ransomware-cti/internal/httpx"
	"ransomware-cti/internal/model"
)

const (
	threatFoxURL    = "https://threatfox-api.abuse.ch/api/v1/"
	malwareBazaarURL = "https://mb-api.abuse.ch/api/v1/"
)

type Client struct {
	key  string
	http *httpx.Client
}

func New(key string, h *httpx.Client) *Client {
	return &Client{key: strings.TrimSpace(key), http: h}
}

func (c *Client) Enabled() bool { return c.key != "" }

type fam struct{ TF, MB string }

var familyMap = map[string]fam{
	"lockbit":     {"win.lockbit", "LockBit"},
	"lockbit3":    {"win.lockbit", "LockBit"},
	"alphv":       {"win.blackcat", "BlackCat"},
	"blackcat":    {"win.blackcat", "BlackCat"},
	"clop":        {"win.clop", "Clop"},
	"cl0p":        {"win.clop", "Clop"},
	"akira":       {"win.akira", "Akira"},
	"play":        {"win.play", "Play"},
	"playcrypt":   {"win.play", "Play"},
	"blackbasta":  {"win.black_basta", "BlackBasta"},
	"bianlian":    {"win.bianlian", "BianLian"},
	"royal":       {"win.royal_ransom", "Royal"},
	"rhysida":     {"win.rhysida", "Rhysida"},
	"medusa":      {"win.medusa", "Medusa"},
	"blacksuit":   {"win.blacksuit", "BlackSuit"},
	"qilin":       {"win.qilin", "Qilin"},
	"agenda":      {"win.qilin", "Qilin"},
	"hunters":     {"win.hunters_international", "HuntersInternational"},
	"8base":       {"win.phobos", "Phobos"},
	"phobos":      {"win.phobos", "Phobos"},
	"ransomhub":   {"win.ransomhub", "RansomHub"},
	"cactus":      {"win.cactus", "Cactus"},
	"incransom":   {"win.inc", "INC"},
	"inc":         {"win.inc", "INC"},
	"dragonforce": {"win.dragonforce", "DragonForce"},
	"safepay":     {"win.safepay", "SafePay"},
	"trigona":     {"win.trigona", "Trigona"},
	"darkside":    {"win.darkside", "DarkSide"},
	"revil":       {"win.revil", "REvil"},
	"conti":       {"win.conti", "Conti"},
}

func normGroup(g string) string {
	g = strings.ToLower(strings.TrimSpace(g))
	g = strings.ReplaceAll(g, " ", "")
	g = strings.ReplaceAll(g, "-", "")
	g = strings.ReplaceAll(g, "_", "")
	return g
}

func mapFamily(group string) (fam, bool) {
	n := normGroup(group)
	if f, ok := familyMap[n]; ok {
		return f, true
	}
	trimmed := strings.TrimRight(n, "0123456789")
	if f, ok := familyMap[trimmed]; ok {
		return f, true
	}
	return fam{}, false
}

type tfResp struct {
	QueryStatus string          `json:"query_status"`
	Data        json.RawMessage `json:"data"`
}

type tfEntry struct {
	IOC        string `json:"ioc"`
	IOCType    string `json:"ioc_type"`
	Confidence int    `json:"confidence_level"`
	FirstSeen  string `json:"first_seen"`
}

func (c *Client) threatFox(ctx context.Context, malware string, limit int) ([]model.IOC, error) {
	body, _ := json.Marshal(map[string]any{"query": "malwareinfo", "malware": malware, "limit": limit})
	headers := map[string]string{"Auth-Key": c.key, "Content-Type": "application/json"}
	status, data, err := c.http.Do(ctx, "POST", threatFoxURL, headers, body)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, nil
	}
	var r tfResp
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, nil
	}
	if r.QueryStatus != "ok" {
		return nil, nil
	}
	var entries []tfEntry
	if err := json.Unmarshal(r.Data, &entries); err != nil {
		return nil, nil
	}
	var out []model.IOC
	for _, e := range entries {
		typ, val := classifyTF(e.IOCType, e.IOC)
		if typ == "" {
			continue
		}
		out = append(out, model.IOC{
			Value: val, Type: typ, MalwareFamily: malware,
			Confidence: e.Confidence, FirstSeen: e.FirstSeen, Source: "ThreatFox (abuse.ch)",
		})
	}
	return out, nil
}

func classifyTF(iocType, ioc string) (string, string) {
	switch iocType {
	case "ip:port":
		host := ioc
		if i := strings.LastIndexByte(ioc, ':'); i > 0 {
			host = ioc[:i]
		}
		return "ip", host
	case "domain":
		return "domain", ioc
	case "url":
		return "url", ioc
	case "sha256_hash", "md5_hash", "sha1_hash":
		return "hash", ioc
	}
	return "", ""
}

type mbResp struct {
	QueryStatus string          `json:"query_status"`
	Data        json.RawMessage `json:"data"`
}

type mbEntry struct {
	SHA256    string `json:"sha256_hash"`
	MD5       string `json:"md5_hash"`
	FirstSeen string `json:"first_seen"`
}

func (c *Client) malwareBazaar(ctx context.Context, signature string, limit int) ([]model.IOC, error) {
	form := url.Values{}
	form.Set("query", "get_siginfo")
	form.Set("signature", signature)
	form.Set("limit", strconv.Itoa(limit))
	headers := map[string]string{"Auth-Key": c.key, "Content-Type": "application/x-www-form-urlencoded"}
	status, data, err := c.http.Do(ctx, "POST", malwareBazaarURL, headers, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, nil
	}
	var r mbResp
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, nil
	}
	if r.QueryStatus != "ok" {
		return nil, nil
	}
	var entries []mbEntry
	if err := json.Unmarshal(r.Data, &entries); err != nil {
		return nil, nil
	}
	var out []model.IOC
	for _, e := range entries {
		h := e.SHA256
		if h == "" {
			h = e.MD5
		}
		if h == "" {
			continue
		}
		out = append(out, model.IOC{
			Value: h, Type: "hash", MalwareFamily: signature,
			Confidence: 100, FirstSeen: e.FirstSeen, Source: "MalwareBazaar (abuse.ch)",
		})
	}
	return out, nil
}

func (c *Client) FamilyIOCs(ctx context.Context, group string, limit int) ([]model.IOC, bool) {
	f, ok := mapFamily(group)
	if !ok {
		return nil, false
	}
	var all []model.IOC
	if tf, err := c.threatFox(ctx, f.TF, limit); err == nil {
		all = append(all, tf...)
	}
	if mb, err := c.malwareBazaar(ctx, f.MB, limit); err == nil {
		all = append(all, mb...)
	}
	for i := range all {
		all[i].Group = group
	}
	return all, len(all) > 0
}
