# Introduction

## <mark style="color:red;">**Active Directory expliqué**</mark>

Active Directory (AD) est un <mark style="color:orange;">**service d'annuaire pour les environnements Windows**</mark> introduit en 2000 avec Windows Server 2000. Basé sur les protocoles x.500 et LDAP, AD permet une gestion centralisée des ressources comme les utilisateurs, ordinateurs, groupes, fichiers, et politiques réseau. Il fournit des fonctions d'authentification, d'autorisation, et d'audit dans les entreprises.

***

<mark style="color:green;">**Objectifs lors d'une attaque AD**</mark>

Dans un réseau sans failles évidentes via des applications ou services, AD offre souvent des points d'entrée. L'objectif peut varier : obtenir l'accès à un serveur, une boîte mail, ou compromettre tout le domaine. Les attaquants utilisent des outils intégrés aux systèmes (technique _living off the land_) ou des méthodes manuelles pour maximiser leurs chances. Cela demande une bonne compréhension des nuances d'AD pour s'adapter même avec des outils limités.

***

### <mark style="color:blue;">Scénarios d'attaques réels</mark>

{% hint style="info" %}
**Scenario 1 - Waiting On An Admin**

During this engagement, I compromised a single host and gained **`SYSTEM`** level access. Because this was a **domain-joined host**, I was able to use this access to enumerate the domain. I went through all of the standard enumeration, but did not find much. There were **`Service Principal Names`** (SPNs) present within the environment, and I was able to perform a **Kerberoasting attack** and retrieve TGS tickets for a few accounts. I attempted to crack these with Hashcat and some of my standard wordlists and rules, but was unsuccessful at first. I ended up leaving a cracking job running overnight with a very large wordlist combined with the [d3ad0ne](https://github.com/hashcat/hashcat/blob/master/rules/d3ad0ne.rule) rule that ships with Hashcat. The next morning I had a hit on one ticket and retrieved the cleartext password for a user account. This account did not give me significant access, but it did give me write access on certain file shares. I used this access to **drop SCF files** around the shares and left Responder going. After a while, I got a single hit, the `NetNTLMv2 hash` of a user. I checked through the BloodHound output and noticed that this user was actually a domain admin! Easy day from here.

***

**Scenario 2 - Spraying The Night Away**

Password spraying can be an extremely effective way to gain a foothold in a domain, but we must exercise great care not to lock out user accounts in the process. On one engagement, I found an SMB NULL session using the [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) tool and retrieved both a listing of `all` users from the domain, and the domain `password policy`. Knowing the password policy was crucial because I could ensure that I was staying within the parameters to not lock out any accounts and also knew that the policy was a minimum eight-character password and password complexity was enforced (meaning that a user's password required 3/4 of special character, number, uppercase, or lower case number, i.e., Welcome1). I tried several common weak passwords such as Welcome1, `Password1`, Password123, `Spring2018`, etc. but did not get any hits. Finally, I made an attempt with `Spring@18` and got a hit! Using this account, I ran BloodHound and found several hosts where this user had local admin access. I noticed that a domain admin account had an active session on one of these hosts. I was able to use the Rubeus tool and extract the Kerberos TGT ticket for this domain user. From there, I was able to perform a `pass-the-ticket` attack and authenticate as this domain admin user. As a bonus, I was able to take over the trusting domain as well because the Domain Administrators group for the domain that I took over was a part of the Administrators group in the trusting domain via nested group membership, meaning I could use the same set of credentials to authenticate to the other domain with full administrative level access.

***

**Scenario 3 - Fighting In The Dark**

I had tried all of my standard ways to obtain a foothold on this third engagement, and nothing had worked. I decided that I would use the [Kerbrute](https://github.com/ropnop/kerbrute) tool to attempt to enumerate valid usernames and then, if I found any, attempt a targeted password spraying attack since I did not know the password policy and didn't want to lock any accounts out. I used the [linkedin2username](https://github.com/initstring/linkedin2username) tool to first mashup potential usernames from the company's LinkedIn page. I combined this list with several username lists from the [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo and, after using the `userenum` feature of Kerbrute, ended up with **516** valid users. I knew I had to tread carefully with password spraying, so I tried with the password `Welcome2021` and got a single hit! Using this account, I ran the Python version of BloodHound from my attack host and found that all domain users had RDP access to a single box. I logged into this host and used the PowerShell tool [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) to spray again. I was more confident this time around because I could a) view the password policy and b) the DomainPasswordSpray tool will remove accounts close to lockout from the target list. Being that I was authenticated within the domain, I could now spray with all domain users, which gave me significantly more targets. I tried again with the common password Fall2021 and got several hits, all for users not in my initial wordlist. I checked the rights for each of these accounts and found that one was in the Help Desk group, which had [GenericAll](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall) rights over the [Enterprise Key Admins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#enterprise-key-admins) group. The Enterprise Key Admins group had GenericAll privileges over a domain controller, so I added the account I controlled to this group, authenticated again, and inherited these privileges. Using these rights, I performed the [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) attack and retrieved the NT hash for the domain controller machine account. With this NT hash, I was then able to perform a DCSync attack and retrieve the NTLM password hashes for all users in the domain because a domain controller can perform replication, which is required for DCSync.
{% endhint %}

***
