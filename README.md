# WireLDAP

**WireLDAP** is a headless Windows service that synchronizes Active Directory (AD) computer objects with [WG-Easy](https://github.com/WeeJeWel/wg-easy), a web-based WireGuard VPN manager. It continuously scans a specific OU and/or AD security group, and ensures that the set of WireGuard clients in WG-Easy matches the AD environment.

---

## 🚀 Features

- 🖥 **OU and group-based provisioning**  
  Automatically discovers computer objects in a specified **Organizational Unit** and **Security Group**.

- 🔁 **Syncs AD with WG-Easy**  
  - Creates clients via the WG-Easy API  
  - Deletes stale clients that no longer exist in AD  
  - Avoids duplication by tracking previously provisioned entries

- 🔐 **Stores WireGuard config in AD (not files)**  
  Saves the contents of each client's WireGuard `.conf` (including `[Interface]`, `[Peer]`, keys, and IPs) into the **`info` attribute** of the corresponding computer object in Active Directory. This enables client agents to retrieve and reconstruct their config directly from AD — no disk distribution needed.

- 🧰 **No GUI, runs headless as a service**  
  Silent, background operation. No user interaction required after setup.

---

## 🛠 Requirements

- WG-Easy VPN server (reachable by this tool)
- Active Directory Server (you maybe could use a regular LDAP server too)
- A read-only LDAP bind account
- Go 1.21+ (only if building from source)


## 📦 Installation

1. ✅ **Install WG-Easy**  
   Ensure it's running and accessible over HTTPS (required for API auth).

2. 🛠 **Create your config file**  
   Customize a file named `wgad_config.json` to match your environment. See the [example](https://github.com/gavinczzz/WireLDAP/blob/main/wgad_config.json) below.

3. 📁 **Place the config**  
   Put `wgad_config.json` in the same directory as `WGADSync.exe`.

4. 🚀 **Install the service**  
   Open an elevated command prompt or PowerShell window and run:

   ```powershell
   .\WGADSync.exe -install


## 🧹 Uninstallation

To fully remove the sync service:

1. ❌ **Stop and delete the service**

   Open an elevated PowerShell or Command Prompt and run:

   ```powershell
   sc stop "ADWireGuardSync"
   sc delete "ADWireGuardSync"
