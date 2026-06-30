package abusech

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ransomware-cti/internal/model"
)

const threatFoxExportURL = "https://threatfox.abuse.ch/export/json/full/"

type exportEntry struct {
	IOCValue   string `json:"ioc_value"`
	IOCType    string `json:"ioc_type"`
	Malware    string `json:"malware"`
	Confidence int    `json:"confidence_level"`
	FirstSeen  string `json:"first_seen_utc"`
}

func CandidateFamilies(group string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if f, ok := mapFamily(group); ok {
		add(f.TF)
	}
	n := normGroup(group)
	add("win." + n)
	add("elf." + n)
	add("osx." + n)
	return out
}

func (c *Client) LoadExport(ctx context.Context, cacheDir string, refresh bool, wanted map[string]bool) (map[string][]model.IOC, error) {
	jsonPath := filepath.Join(cacheDir, "threatfox_full.json")
	var data []byte
	if !refresh {
		if b, err := os.ReadFile(jsonPath); err == nil {
			data = b
		}
	}
	if data == nil {
		raw, err := c.downloadExport(ctx)
		if err != nil {
			return nil, err
		}
		data = raw
		_ = os.WriteFile(jsonPath, data, 0o644)
	}
	return indexExport(data, wanted)
}

func (c *Client) downloadExport(ctx context.Context) ([]byte, error) {
	status, body, err := c.http.Do(ctx, "GET", threatFoxExportURL, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("threatfox export: http %d", status)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, ".json") {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("threatfox export: zip icinde json bulunamadi")
}

func indexExport(data []byte, wanted map[string]bool) (map[string][]model.IOC, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	idx := map[string][]model.IOC{}
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		var arr []exportEntry
		if err := dec.Decode(&arr); err != nil {
			return nil, err
		}
		for _, e := range arr {
			if wanted != nil && !wanted[e.Malware] {
				continue
			}
			typ, val := classifyTF(e.IOCType, e.IOCValue)
			if typ != "ip" && typ != "hash" {
				continue
			}
			idx[e.Malware] = append(idx[e.Malware], model.IOC{
				Value:         val,
				Type:          typ,
				MalwareFamily: e.Malware,
				Confidence:    e.Confidence,
				FirstSeen:     e.FirstSeen,
				Source:        "ThreatFox (abuse.ch)",
			})
		}
	}
	return idx, nil
}

func IOCsFromIndex(group string, idx map[string][]model.IOC, limit int) []model.IOC {
	var out []model.IOC
	seen := map[string]bool{}
	for _, fam := range CandidateFamilies(group) {
		for _, ioc := range idx[fam] {
			if seen[ioc.Value] {
				continue
			}
			seen[ioc.Value] = true
			cp := ioc
			cp.Group = group
			out = append(out, cp)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}
