package ldap

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

// Config defines fields parsed from wgad_config.json, used to configure API and LDAP access.
type Config struct {
	WGEasyAddress         string `json:"WG_Easy_Address"`
	WGEasyUsername        string `json:"WG_Easy_Username"`
	WGEasyPassword        string `json:"WG_Easy_Password"`
	WGEasyExternalAddress string `json:"WG_Easy_External_Address"`
	WGEasyDNS             string `json:"WG_Easy_DNS"`
	LDAPServerAddress     string `json:"LDAP_Server_Address"`
	LDAPbindUsername      string `json:"LDAP_bind_Username"`
	LDAPbindPassword      string `json:"LDAP_bind_Password"`
	LDAPBASEDN            string `json:"LDAP_BASEDN"`
	LDAPOUBASEDN          string `json:"LDAP_OUBASEDN"`
	LDAPGROUP             string `json:"LDAP_GROUP"`
	CONFPATH              string `json:"WG_CONF_PATH"`
	SYNCINTERVAL          int    `json:"SyncIntervalSeconds"`
}

// LDAPClientSummary holds essential info about LDAP computer objects.
type LDAPClientSummary struct {
	Name string
}

// memoized config loader
var (
	cachedConfig *Config
	configOnce   sync.Once
)

// GetConfig returns a singleton instance of the configuration loaded from wgad_config.json.
func GetConfig() (*Config, error) {
	var err error
	configOnce.Do(func() {
		var data []byte
		data, err = os.ReadFile("wgad_config.json")
		if err != nil {
			return
		}
		var cfg Config
		err = json.Unmarshal(data, &cfg)
		if err != nil {
			return
		}
		cachedConfig = &cfg
	})
	return cachedConfig, err
}

func GetADComputersAndGroupMembers() ([]LDAPClientSummary, error) {
	cfg, err := GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	host := cfg.LDAPServerAddress
	if !strings.Contains(host, ":") {
		host += ":389"
	}

	protocol := "ldap"
	if strings.HasSuffix(host, ":636") {
		protocol = "ldaps"
	}

	conn, err := ldap.DialURL(fmt.Sprintf("%s://%s", protocol, host))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if protocol == "ldap" {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		if err := conn.StartTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	if err := conn.Bind(cfg.LDAPbindUsername, cfg.LDAPbindPassword); err != nil {
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	combined := map[string]LDAPClientSummary{}

	// Search OU
	if cfg.LDAPOUBASEDN != "" {
		searchOU := ldap.NewSearchRequest(
			cfg.LDAPOUBASEDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=computer))",
			[]string{"cn"},
			nil,
		)

		ouResults, err := conn.Search(searchOU)
		if err != nil {
			fmt.Printf("Warning: OU search failed: %v\n", err)
		} else {
			for _, entry := range ouResults.Entries {
				cn := entry.GetAttributeValue("cn")
				combined[strings.ToLower(cn)] = LDAPClientSummary{Name: cn}
			}
		}
	}

	// Search group
	if cfg.LDAPGROUP != "" {
		searchGroup := ldap.NewSearchRequest(
			cfg.LDAPBASEDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(cfg.LDAPGROUP)),
			[]string{"member"},
			nil,
		)

		groupResults, err := conn.Search(searchGroup)
		if err != nil {
			fmt.Printf("Warning: group search failed: %v\n", err)
		} else if len(groupResults.Entries) > 0 {
			for _, dn := range groupResults.Entries[0].GetAttributeValues("member") {
				searchMember := ldap.NewSearchRequest(
					dn,
					ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
					"(objectClass=computer)",
					[]string{"cn"},
					nil,
				)
				memberEntry, err := conn.Search(searchMember)
				if err == nil && len(memberEntry.Entries) > 0 {
					cn := memberEntry.Entries[0].GetAttributeValue("cn")
					combined[strings.ToLower(cn)] = LDAPClientSummary{Name: cn}
				}
			}
		}
	}

	if len(combined) == 0 {
		return nil, fmt.Errorf("no computer objects found from OU or group")
	}

	var results []LDAPClientSummary
	for _, summary := range combined {
		results = append(results, summary)
	}

	return results, nil
}

// ClearComputerWGConfig searches the whole domain for the hostname and clears the "adminDescription" attribute.
func ClearComputerWGConfig(hostname string) error {
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	host := cfg.LDAPServerAddress
	if !strings.Contains(host, ":") {
		host += ":389"
	}

	protocol := "ldap"
	if strings.HasSuffix(host, ":636") {
		protocol = "ldaps"
	}

	conn, err := ldap.DialURL(fmt.Sprintf("%s://%s", protocol, host))
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if protocol == "ldap" {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		if err := conn.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	if err := conn.Bind(cfg.LDAPbindUsername, cfg.LDAPbindPassword); err != nil {
		return fmt.Errorf("failed to bind: %w", err)
	}

	searchReq := ldap.NewSearchRequest(
		cfg.LDAPBASEDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(&(objectClass=computer)(cn=%s))", ldap.EscapeFilter(hostname)),
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(sr.Entries) == 0 {
		return fmt.Errorf("computer %q not found in LDAP", hostname)
	}

	dn := sr.Entries[0].DN
	modReq := ldap.NewModifyRequest(dn, nil)
	modReq.Delete("adminDescription", nil)

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("failed to clear adminDescription attribute: %w", err)
	}

	return nil
}

// UpdateComputerWGConfig sets or replaces the "adminDescription" attribute for a computer object.
func UpdateComputerWGConfig(hostname, config string) error {
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	host := cfg.LDAPServerAddress
	if !strings.Contains(host, ":") {
		host += ":389"
	}

	protocol := "ldap"
	if strings.HasSuffix(host, ":636") {
		protocol = "ldaps"
	}

	conn, err := ldap.DialURL(fmt.Sprintf("%s://%s", protocol, host))
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if protocol == "ldap" {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		if err := conn.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	if err := conn.Bind(cfg.LDAPbindUsername, cfg.LDAPbindPassword); err != nil {
		return fmt.Errorf("failed to bind: %w", err)
	}

	searchReq := ldap.NewSearchRequest(
		cfg.LDAPBASEDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(&(objectClass=computer)(cn=%s))", ldap.EscapeFilter(hostname)),
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(sr.Entries) == 0 {
		return fmt.Errorf("computer %q not found in LDAP", hostname)
	}

	dn := sr.Entries[0].DN
	modReq := ldap.NewModifyRequest(dn, nil)
	modReq.Replace("adminDescription", []string{config})

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("failed to update adminDescription attribute: %w", err)
	}

	return nil

}
