package wgapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config defines fields parsed from wgad_config.json, used to configure API and LDAP access.
type Config struct {
	WGEasyAddress       string `json:"WG_Easy_Address"`
	WGEasyUsername      string `json:"WG_Easy_Username"`
	WGEasyPassword      string `json:"WG_Easy_Password"`
	LDAPServerAddress   string `json:"LDAP_Server_Address"`
	LDAPbindUsername    string `json:"LDAP_bind_Username"`
	LDAPbindPassword    string `json:"LDAP_bind_Password"`
	LDAPBASEDN          string `json:"LDAP_BASEDN"`
	LDAPOUBASEDN        string `json:"LDAP_OUBASEDN"`
	LDAPGROUP           string `json:"LDAP_GROUP"`
	CONFPATH            string `json:"WG_CONF_PATH"`
	SyncIntervalSeconds int    `json:"SyncIntervalSeconds"`
}

// VPNClient represents a WireGuard client as returned by WG-Easy API.
type VPNClient struct {
	ID               int      `json:"id"`
	UserID           int      `json:"userId"`
	InterfaceID      string   `json:"interfaceId"`
	Name             string   `json:"name"`
	Address          string   `json:"ipv4Address"`
	IPv6Address      string   `json:"ipv6Address"`
	PrivateKey       string   `json:"privateKey"`
	PublicKey        string   `json:"publicKey"`
	PreSharedKey     string   `json:"preSharedKey"`
	ServerAllowedIPs []string `json:"serverAllowedIps"`
	PersistentKeep   int      `json:"persistentKeepalive"`
	MTU              int      `json:"mtu"`
	DNS              *string  `json:"dns"`
	Endpoint         *string  `json:"serverEndpoint"`
	Enabled          bool     `json:"enabled"`
}

// ClientSummary holds basic WireGuard client information for syncing.
type ClientSummary struct {
	ID              int        `json:"id"`
	UserID          int        `json:"userId"`
	Name            string     `json:"name"`
	IPv4Address     string     `json:"ipv4Address"`
	IPv6Address     string     `json:"ipv6Address"`
	Enabled         bool       `json:"enabled"`
	LatestHandshake *time.Time `json:"latestHandshakeAt"`
}

// createClientPayload is used to send the POST body to /api/client to create a new VPN client.
type createClientPayload struct {
	Name      string      `json:"name"`
	ExpiresAt interface{} `json:"expiresAt"`
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

// CreateClient adds a new VPN client to WG-Easy.
func CreateClient(hostname string) error {
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	payload := createClientPayload{
		Name:      hostname,
		ExpiresAt: nil,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.WGEasyAddress+"/api/client", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create POST request: %w", err)
	}
	req.SetBasicAuth(cfg.WGEasyUsername, cfg.WGEasyPassword)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create client (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetClients fetches all VPN clients from WG-Easy and returns summarized data.
func GetClients() ([]ClientSummary, error) {
	cfg, err := GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	req, err := http.NewRequest("GET", cfg.WGEasyAddress+"/api/client", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GET request: %w", err)
	}
	req.SetBasicAuth(cfg.WGEasyUsername, cfg.WGEasyPassword)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var fullClients []struct {
		ID              int        `json:"id"`
		UserID          int        `json:"userId"`
		Name            string     `json:"name"`
		IPv4Address     string     `json:"ipv4Address"`
		IPv6Address     string     `json:"ipv6Address"`
		Enabled         bool       `json:"enabled"`
		LatestHandshake *time.Time `json:"latestHandshakeAt"`
	}
	if err := json.Unmarshal(body, &fullClients); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	summary := make([]ClientSummary, 0, len(fullClients))
	for _, c := range fullClients {
		summary = append(summary, ClientSummary{
			ID:              c.ID,
			UserID:          c.UserID,
			Name:            c.Name,
			IPv4Address:     c.IPv4Address,
			IPv6Address:     c.IPv6Address,
			Enabled:         c.Enabled,
			LatestHandshake: c.LatestHandshake,
		})
	}

	return summary, nil
}

// DeleteClient removes a VPN client from WG-Easy using its ID.
func DeleteClient(id int) error {
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/client/%d", cfg.WGEasyAddress, id), nil)
	if err != nil {
		return fmt.Errorf("failed to create DELETE request: %w", err)
	}
	req.SetBasicAuth(cfg.WGEasyUsername, cfg.WGEasyPassword)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete client (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteClientByName deletes a client by its name.
func DeleteClientByName(name string) error {
	client, err := GetClientByName(name)
	if err != nil {
		return err
	}
	return DeleteClient(client.ID)
}

// DeleteDuplicateClients removes duplicate client entries by name (keeps the most recent).
func DeleteDuplicateClients() error {
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	req, err := http.NewRequest("GET", cfg.WGEasyAddress+"/api/client", nil)
	if err != nil {
		return fmt.Errorf("failed to create GET request: %w", err)
	}
	req.SetBasicAuth(cfg.WGEasyUsername, cfg.WGEasyPassword)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET request failed: %w", err)
	}
	defer resp.Body.Close()

	var allClients []VPNClient
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &allClients); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	keep := make(map[string]VPNClient)
	toDelete := []int{}

	for _, client := range allClients {
		name := strings.ToLower(client.Name)
		existing, found := keep[name]
		if !found || client.ID > existing.ID {
			if found {
				toDelete = append(toDelete, existing.ID)
			}
			keep[name] = client
		} else {
			toDelete = append(toDelete, client.ID)
		}
	}

	for _, id := range toDelete {
		if err := DeleteClient(id); err != nil {
			log.Printf("Warning: failed to delete client ID %d: %v", id, err)
		} else {
			log.Printf("Deleted duplicate client ID %d", id)
		}
	}

	return nil
}

// GetClientSummaryByName returns a ClientSummary by name (case-insensitive).
func GetClientByName(name string) (ClientSummary, error) {
	clients, err := GetClients()
	if err != nil {
		return ClientSummary{}, err
	}

	for _, c := range clients {
		if strings.EqualFold(c.Name, name) {
			return c, nil
		}
	}

	return ClientSummary{}, fmt.Errorf("client %q not found", name)
}

// WriteClientConfigToFile retrieves the WireGuard config using the client's ID and writes it to hostname.conf
func WriteClientConfigToFile(hostname string) error {
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	client, err := GetClientByName(hostname)
	if err != nil {
		return fmt.Errorf("failed to get client info: %w", err)
	}

	url := fmt.Sprintf("%s/api/client/%d/configuration", cfg.WGEasyAddress, client.ID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create GET request: %w", err)
	}
	req.SetBasicAuth(cfg.WGEasyUsername, cfg.WGEasyPassword)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to fetch config (HTTP %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	outputPath := filepath.Join(cfg.CONFPATH, hostname+".conf")
	if err := os.WriteFile(outputPath, body, 0600); err != nil {
		return fmt.Errorf("failed to write config to file: %w", err)
	}

	return nil
}

// DeleteClientConfigFile deletes the WireGuard config file for a given client from CONFPATH
func DeleteClientConfigFile(hostname string) error {
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	configPath := filepath.Join(cfg.CONFPATH, hostname+".conf")

	if err := os.Remove(configPath); err != nil {
		if os.IsNotExist(err) {
			// File already gone, not an error
			return nil
		}
		return fmt.Errorf("failed to delete config file: %w", err)
	}

	return nil
}
