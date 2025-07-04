package main

import (
	"WireLDAP/modules/ldap"
	"WireLDAP/modules/wgapi"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/service"
)

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

var (
	cachedConfig *Config
	configOnce   sync.Once
)

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

type program struct{}

func (p *program) Start(s service.Service) error {
	go runSyncLoop()
	return nil
}

func (p *program) Stop(s service.Service) error {
	// You could add graceful shutdown logic here
	return nil
}

func runSyncLoop() {
	log.Println("== Starting sync between LDAP and WG-Easy ==")

	cfg, err := GetConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	interval := 30 * time.Second
	if cfg.SyncIntervalSeconds > 0 {
		interval = time.Duration(cfg.SyncIntervalSeconds) * time.Second
	}

	for {
		if err := wgapi.DeleteDuplicateClients(); err != nil {
			log.Printf("Error removing duplicates: %v", err)
		}

		ldapClients, err := ldap.GetADComputersAndGroupMembers()
		if err != nil {
			log.Printf("Failed to get LDAP computers: %v", err)
			time.Sleep(interval)
			continue
		}
		ldapMap := make(map[string]bool)
		for _, c := range ldapClients {
			ldapMap[strings.ToLower(c.Name)] = true
		}

		wgClients, err := wgapi.GetClients()
		if err != nil {
			log.Printf("Failed to get WG clients: %v", err)
			time.Sleep(interval)
			continue
		}
		wgMap := make(map[string]bool)
		for _, c := range wgClients {
			wgMap[strings.ToLower(c.Name)] = true
		}

		for _, c := range ldapClients {
			if !wgMap[strings.ToLower(c.Name)] {
				log.Printf("Creating new WG-Easy client for: %s", c.Name)
				if err := wgapi.CreateClient(c.Name); err != nil {
					log.Printf("Failed to create client %s: %v", c.Name, err)
					continue
				}

				if err := wgapi.WriteClientConfigToFile(c.Name); err != nil {
					log.Printf("Failed to write WG config for %s: %v", c.Name, err)
				}
			}
		}

		for _, c := range wgClients {
			if !ldapMap[strings.ToLower(c.Name)] {
				log.Printf("Removing stale WG client: %s", c.Name)
				if err := wgapi.DeleteClientByName(c.Name); err != nil {
					log.Printf("Failed to delete WG client %s: %v", c.Name, err)
				}
				if err := wgapi.DeleteClientConfigFile(c.Name); err != nil {
					log.Printf("Failed to delete WG Config for %s: %v", c.Name, err)
				}
			}
		}

		for _, c := range ldapClients {
			if err := wgapi.WriteClientConfigToFile(c.Name); err != nil {
				log.Printf("Failed to write WG config for %s: %v", c.Name, err)
			}
		}

		log.Println("== Sync complete ==")
		time.Sleep(interval)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := out.Close()
		if err == nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return out.Sync()
}

func main() {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get current executable path: %v", err)
	}

	targetDir := filepath.Join(os.Getenv("PROGRAMDATA"), "WGAD")
	targetExe := filepath.Join(targetDir, filepath.Base(exePath))

	svcConfig := &service.Config{
		Name:             "ADWireGuardSync",
		DisplayName:      "AD to WireGuard Sync Service",
		Description:      "Synchronizes Active Directory computer objects with WG-Easy clients.",
		Executable:       targetExe,
		WorkingDirectory: targetDir,
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
		cmd := os.Args[1]
		switch cmd {
		case "install":
			// Create service target directory if it doesn't exist
			err = os.MkdirAll(targetDir, 0755)
			if err != nil {
				log.Fatalf("Failed to create target directory: %v", err)
			}

			// Load config to get CONFPATH
			cfg, err := GetConfig()
			if err != nil {
				log.Fatalf("Failed to load config for CONFPATH: %v", err)
			}

			// Ensure CONFPATH directory exists
			err = os.MkdirAll(cfg.CONFPATH, 0755)
			if err != nil {
				log.Fatalf("Failed to create CONFPATH directory: %v", err)
			}
			log.Printf("Ensured CONFPATH exists: %s", cfg.CONFPATH)

			// Copy .exe to targetDir
			err = copyFile(exePath, targetExe)
			if err != nil {
				log.Fatalf("Failed to copy .exe: %v", err)
			}

			// Copy wgad_config.json if it exists
			if _, err := os.Stat("wgad_config.json"); err == nil {
				err = copyFile("wgad_config.json", "C:\\Windows\\System32\\wgad_config.json")
				if err != nil {
					log.Fatalf("Failed to copy wgad_config.json: %v", err)
				}
			} else {
				log.Println("wgad_config.json not found in current directory; service may fail without it.")
			}

			// Install and start the service
			err = s.Install()
			if err != nil {
				log.Fatalf("Failed to install service: %v", err)
			}
			log.Println("Service installed from:", targetExe)

			err = s.Start()
			if err != nil {
				log.Fatalf("Failed to start service after install: %v", err)
			}
			log.Println("Service started")

			return

		case "uninstall":
			err = s.Uninstall()
			if err != nil {
				log.Fatalf("Failed to uninstall service: %v", err)
			}
			log.Println("Service uninstalled")
			return

		case "start":
			err = s.Start()
			if err != nil {
				log.Fatalf("Failed to start service: %v", err)
			}
			log.Println("Service started")
			return

		case "stop":
			err = s.Stop()
			if err != nil {
				log.Fatalf("Failed to stop service: %v", err)
			}
			log.Println("Service stopped")
			return

		default:
			log.Fatalf("Unknown command: %s", cmd)
		}
	}

	// If no args, run as service
	err = s.Run()
	if err != nil {
		log.Fatal(err)
	}
}
