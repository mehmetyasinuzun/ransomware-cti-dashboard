package model

type Victim struct {
	ID            int64  `json:"id"`
	Date          string `json:"date"`
	Group         string `json:"ransomware_group"`
	Country       string `json:"country"`
	CountryName   string `json:"country_name"`
	Sector        string `json:"target_sector"`
	AttackVector  string `json:"attack_vector"`
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique"`
	Severity      int    `json:"severity"`
	IOCIP         string `json:"ioc_ip"`
	IOCHash       string `json:"ioc_hash"`
	Org           string `json:"victim"`
	Description   string `json:"description"`
	Domain        string `json:"domain"`
	ClaimURL      string `json:"claim_url"`
	SourceURL     string `json:"source_url"`
}

type Technique struct {
	TacticID      string
	TacticName    string
	TechniqueID   string
	TechniqueName string
}

type GroupProfile struct {
	Name          string
	Techniques    []Technique
	InitialAccess []Technique
	HasImpact     bool
}

type IOC struct {
	Value         string `json:"value"`
	Type          string `json:"type"`
	Group         string `json:"ransomware_group"`
	MalwareFamily string `json:"malware_family"`
	Confidence    int    `json:"confidence"`
	FirstSeen     string `json:"first_seen"`
	Source        string `json:"source"`
}
