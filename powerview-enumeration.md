## Domain Enum

```
Get-NetDomain
```

## SID
``` 
Get-DomainSID
```

## DC
```
Get-NetDomainController
```

## Domain Users

```
Get-NetUser | select samaccountname
```

## Domain Computers

```
Get-NetComputer
```

## Domain Groups
```
Get-NetGroup
```

## Domain Admin Groups

```
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
```

## Local Groups
```
Get-NetLocalGroup
```

## OU

```
Get-NetOU
```

## Forest

```
Get-NetForest
```

## Forest Trust
```
Get-NetForestTrust
```

## Forest Catalog
```
Get-NetForestCatalog
```

## Kerberos SPN
```
Get-NetUsers -SPN | select samaccountname, serviceprincipalname
```


