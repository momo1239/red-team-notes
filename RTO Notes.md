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


# Domain Enumeration
- Get current domain: `Get-Domain`
- Get domain SID: `Get-DomainSID`


- Enumerating domain computers:
 `Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName`
 
- Get domain groups with "admin":
 `Get-DomainGroup | where Name -like "Admins" | select SamAccountName`

