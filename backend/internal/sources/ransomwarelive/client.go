package ransomwarelive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"ransomware-cti/internal/httpx"
	"ransomware-cti/internal/model"
	"ransomware-cti/internal/util"
)

type Client struct {
	base string
	http *httpx.Client
}

func New(base string, h *httpx.Client) *Client {
	return &Client{base: strings.TrimRight(base, "/"), http: h}
}

type rawVictim struct {
	Victim      string `json:"victim"`
	Group       string `json:"group"`
	Country     string `json:"country"`
	Activity    string `json:"activity"`
	AttackDate  string `json:"attackdate"`
	Discovered  string `json:"discovered"`
	Description string `json:"description"`
	ClaimURL    string `json:"claim_url"`
	Domain      string `json:"domain"`
	URL         string `json:"url"`
}

func (c *Client) Month(ctx context.Context, year, month int) ([]model.Victim, error) {
	u := fmt.Sprintf("%s/victims/%d/%02d", c.base, year, month)
	status, data, err := c.http.Do(ctx, "GET", u, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("victims %d/%02d: http %d", year, month, status)
	}
	var raw []rawVictim
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("victims %d/%02d cozumleme: %w", year, month, err)
	}
	out := make([]model.Victim, 0, len(raw))
	for _, r := range raw {
		g := strings.TrimSpace(r.Group)
		if g == "" {
			continue
		}
		out = append(out, model.Victim{
			Date:        util.PickDate(r.AttackDate, r.Discovered),
			Group:       g,
			Country:     strings.ToUpper(strings.TrimSpace(r.Country)),
			Sector:      strings.TrimSpace(r.Activity),
			Org:         strings.TrimSpace(r.Victim),
			Description: strings.TrimSpace(r.Description),
			Domain:      strings.TrimSpace(r.Domain),
			ClaimURL:    strings.TrimSpace(r.ClaimURL),
			SourceURL:   strings.TrimSpace(r.URL),
		})
	}
	return out, nil
}

type rawGroup struct {
	Name string `json:"name"`
	TTPs []struct {
		TacticID   string `json:"tactic_id"`
		TacticName string `json:"tactic_name"`
		Techniques []struct {
			TechniqueID   string `json:"technique_id"`
			TechniqueName string `json:"technique_name"`
		} `json:"techniques"`
	} `json:"ttps"`
}

func (c *Client) Group(ctx context.Context, name string) (model.GroupProfile, error) {
	u := fmt.Sprintf("%s/group/%s", c.base, url.PathEscape(name))
	status, data, err := c.http.Do(ctx, "GET", u, nil, nil)
	if err != nil {
		return model.GroupProfile{}, err
	}
	if status != 200 {
		return model.GroupProfile{}, fmt.Errorf("group %s: http %d", name, status)
	}
	var rg rawGroup
	if err := json.Unmarshal(data, &rg); err != nil {
		return model.GroupProfile{}, fmt.Errorf("group %s cozumleme: %w", name, err)
	}
	p := model.GroupProfile{Name: name}
	for _, t := range rg.TTPs {
		for _, tech := range t.Techniques {
			if strings.TrimSpace(tech.TechniqueID) == "" {
				continue
			}
			p.Techniques = append(p.Techniques, model.Technique{
				TacticID:      t.TacticID,
				TacticName:    t.TacticName,
				TechniqueID:   strings.TrimSpace(tech.TechniqueID),
				TechniqueName: strings.TrimSpace(tech.TechniqueName),
			})
		}
	}
	return p, nil
}
