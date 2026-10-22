# EAPHost prototype

Experimental Windows x64/ARM64 EAP-MD5 DLL using Wired AutoConfig instead of Npcap. Campus authentication, periodic renewal and hibernation recovery are not yet verified. The regular Rust app still uses Npcap; its GUI does not report this prototype's connection state.

Build from the repository root with the matching Rust toolchain and Windows SDK:

```powershell
cargo build --locked --release -p sysu-netauth-eap-peer --target x86_64-pc-windows-msvc
# ARM64: use aarch64-pc-windows-msvc
```

Close other authentication clients. In elevated PowerShell matching the Windows architecture, install the DLL and enter your NetID/password when prompted:

```powershell
./apps/rust/eap-peer/manage.ps1 -Action Install -DllPath ./target/x86_64-pc-windows-msvc/release/sysu_netauth_eap_peer.dll
```

Restart Windows, then select your Ethernet interface:

```powershell
./apps/rust/eap-peer/manage.ps1 -Action Enable -Interface 'Ethernet'
./apps/rust/eap-peer/manage.ps1 -Action Status
```

The trial saves the previous interface profile and service settings, disables the SYSUNetAuth service, and enables Wired AutoConfig. The profile uses machine context with your configured NetID, independent of Windows sign-in credentials. Credentials are stored under `%ProgramData%\SYSUNetAuth\EapHost\`, accessible to SYSTEM and Administrators. NetIDs must be ASCII; passwords use GBK. Windows manages EAPOL addressing and timing.

Before adopting this backend, verify initial login, repeated renewal over several hours, cable reconnect, sleep/hibernation, reboot and operation after signing out. Review **Event Viewer → Applications and Services Logs → Microsoft → Windows → Wired-AutoConfig → Operational** for failures.

Restore the saved profile and service settings, then remove the prototype:

```powershell
./apps/rust/eap-peer/manage.ps1 -Action Restore
./apps/rust/eap-peer/manage.ps1 -Action Uninstall
```

The registration uses example AuthorId `32473` for evaluation; public distribution requires an appropriate assigned author identifier. Setup installers do not include this prototype.

References: [EAP peer API](https://learn.microsoft.com/en-us/windows/win32/api/eapmethodpeerapis/), [binary profile configuration](https://learn.microsoft.com/en-us/windows/win32/eaphost/eaphostconfigschema-configblob-eaphostconfig-element).
