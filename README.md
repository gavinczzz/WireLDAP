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

- 🔐 **Stores WireGuard config in location of your choice**  
  Saves the contents of each client's WireGuard `.conf` in the path you specify in the config.

- 🧰 **No GUI, runs headless as a service**  
  Silent, background operation. No user interaction required after setup.

---

## 🛠 Requirements

- [WG-Easy](https://github.com/weejewel/wg-easy) VPN server (reachable by this tool)
- Active Directory Server (you maybe could use a regular LDAP server too)
- A read-only LDAP bind account
- Go 1.21+ (only if building from source)


## 📦 Installation

1. ✅ **Install WG-Easy**  
   Ensure it's running and accessible over HTTPS (required for API auth).

2. 🛠 **Create your config file**  
   Customize a file named `wgad_config.json` to match your environment. See the [example](https://github.com/gavinczzz/WireLDAP/blob/main/wgad_config.json) below.
   **Keep in mind that you need to have accurate info in the "WG_Easy_DNS" and "WG_Easy_External_Address" as these go into every config that is generated.**

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
