# Disconnected GPO Editor

## Introduction

Disconnected GPO Editor is a launcher for the official Group Policy Manager to bypass the domain joined requirement that is needed when using the official MMC snap-in.  

The tool works by injecting a C# library into MMC that will hook the `GetUserNameExW` API calls to trick GPM into believing that the logged on user is a domain user.  Hooks are also placed on the `NtCreateFile` API to redirect file paths that would typically be resolved via DFS to a specific domain controller instead.

## Prerequisites  

Since DGPOEdit relies on the gpmc.msc and gpme.msc snap-ins, you'll first need to install the Windows Remote Server Administration Tools (RSAT) on the non domain joined host you'll be operating from.

## Usage

mmc.exe is marked for auto elevation, therefore launching of `DGPOEdit.exe` should be performed from an elevated command prompt that has either got a relevant TGT with correct permissions imported into the same luid session or alternatively the session has been created using `runas /netonly`.  This will ensure that the relevant Kerberos tickets will be fetched automatically or NTLM credentials are used for outbound network connections when `runas /netonly` has been used.  

### Launching Group Policy Manager

To launch GPM to target a specific Active Directory domain, simply supply the DNS domain name of the target.

```
DGPOEdit ad.target.com
``` 

### Launching Group Policy Editor

You can also use DGPOEdit to edit a specific GPO without first using the manager snap-in.  

```
DGPOEdit /s /gpobject:"LDAP://dc.ad.target.com/cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=ad,DC=target,DC=com"
```
The LDAP path to the target GPO can be determined via your favorite LDAP explorer tool like ADExploer.





