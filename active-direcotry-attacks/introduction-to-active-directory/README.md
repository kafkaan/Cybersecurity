# Introduction to Active Directory

***

### <mark style="color:blue;">🎯 Définition rapide</mark>

* **Active Directory (AD)** = service d’annuaire Windows
* Sert à :
  * Authentifier (qui es-tu ?)
  * Autoriser (as-tu le droit ?)
* Centralise :
  * Utilisateurs
  * Ordinateurs
  * Groupes
  * GPO
  * Partages
  * Relations de confiance (trusts)

👉 **Cœur de la sécurité Windows en entreprise**

***

### <mark style="color:blue;">🏗️ Structure d’Active Directory</mark>

* **Hiérarchique**
* **Distribuée**
* **Scalable** (millions d’objets)

#### <mark style="color:green;">Composants principaux</mark>

* <mark style="color:orange;">**Forest**</mark> : ensemble logique (le plus haut niveau)
* <mark style="color:orange;">**Domain**</mark> : frontière de sécurité
* <mark style="color:orange;">**OU**</mark>**&#x20;(Organizational Units)** : organisation logique
* <mark style="color:orange;">**Objects**</mark> :
  * Users
  * Computers
  * Groups
  * Service Accounts

***

### <mark style="color:blue;">🔐 Rôle principal d’AD</mark>

* **Authentification**
  * Kerberos
  * NTLM (legacy)
* **Autorisation**
  * Groupes
  * ACL
  * GPO

👉 AD décide **qui peut faire quoi, où, et comment**

***

### <mark style="color:blue;">📚 AD = base de données lisible par tous</mark>

* AD est **quasi read-only pour tous les utilisateurs**
* Même un **simple user** peut :
  * Lister les utilisateurs
  * Voir les groupes
  * Lire les ACL
  * Identifier des misconfigs

⚠️ **Énorme surface d’attaque**

***

### <mark style="color:blue;">⚠️ Pourquoi AD est une cible majeure</mark>

* \~ **95 % des entreprises Fortune 500**
* Très :
  * ancien
  * complexe
  * rétro-compatible
* ❌ Pas sécurisé par défaut
* ❌ Souvent mal configuré

👉 **Un compte utilisateur standard suffit souvent pour attaquer**

***

### <mark style="color:blue;">🧨 Attaques célèbres liées à AD</mark>

* **Zerologon** (CVE-2020-1472)
* **PrintNightmare** (CVE-2021-34527)
* **noPac**
* **Kerberoasting**
* **ADCS abuses (ESC1 → ESC15)**

🎯 Objectif attaquant :

* Mouvement latéral
* Escalade de privilèges
* Contrôle total du domaine

***

### <mark style="color:blue;">🧪 Exemple réaliste d’attaque</mark>

1. Phishing → compte user standard
2. Énumération AD (LDAP)
3. Découverte :
   * Mauvais droits
   * Certificats vulnérables
   * Services faibles
4. Escalade → Domain Admin
5. Ransomware / persistance

***

### <mark style="color:blue;">🧠 Pourquoi apprendre AD en profondeur</mark>

* Les **outils ne suffisent pas**
* Comprendre AD permet :
  * Trouver des failles subtiles
  * Exploiter sans bruit
  * Donner des remédiations crédibles

🧠 _Un bon pentester AD comprend avant d’exploiter_

***

### <mark style="color:blue;">🧬 Protocoles clés d’AD (à connaître)</mark>

* **LDAP** : annuaire
* **Kerberos** : authentification principale
* **DNS** : indispensable à AD
* **SMB** : partages, GPO
* **RPC** : communications internes
* **NTLM** : legacy (encore présent)

***

### <mark style="color:blue;">☁️ Évolution d’Active Directory</mark>

* **2000** : AD intégré à Windows
* **2003** : Forest
* **2008** : ADFS (SSO)
* **2016** :
  * gMSA
  * Sécurité renforcée
* **Azure AD / Entra ID**
  * Hybride on-prem + cloud

⚠️ Hybride = **nouvelle surface d’attaque**

***

### <mark style="color:blue;">🛡️ Défense (vue rapide)</mark>

* Patchs réguliers
* Principe du moindre privilège
* Segmentation réseau
* Monitoring AD
* Sécurisation ADCS
* Audit des ACL et templates

***

### <mark style="color:blue;">🧠 À retenir absolument (exam / pentest)</mark>

* AD est :
  * partout
  * complexe
  * fragile
* **Un simple user peut tout voir**
* Les misconfigs > vulnérabilités
* ADCS est une mine d’or pour l’attaquant
* Comprendre AD = devenir dangereux 😈

***

### <mark style="color:blue;">🧾 Résumé ultra court</mark>

```
AD = cœur de l’entreprise
Lisible par tous
Mal configuré = compromis total
Comprendre > outils
```

***

## <mark style="color:red;">RECHERCHE & ATTAQUES ACTIVE DIRECTORY (HISTORIQUE)</mark>

***

### <mark style="color:blue;">🎯 Objectif de cette partie</mark>

* Montrer que **Active Directory est une surface d’attaque vivante**
* Comprendre :
  * d’où viennent les attaques modernes
  * pourquoi de nouvelles failles sortent encore
* Connaître les **attaques & outils “classiques” indispensables**

👉 AD ≠ “ancien et stable”\
👉 AD = **cible en évolution permanente**

***

### <mark style="color:red;">🧠 Idée clé à retenir</mark>

* Les **pires attaques AD** :
  * partent souvent d’un **simple user**
  * exploitent :
    * des misconfigurations
    * des failles logiques
    * des vieux choix de design
* Les chercheurs ont **transformé AD en graphe d’attaque**

***

## <mark style="color:red;">🗓️ Timeline essentielle (à connaître en pentest)</mark>

***

### <mark style="color:blue;">🔴 2013 – Début de l’attaque réseau interne</mark>

#### <mark style="color:green;">🔹 Responder (Laurent Gaffié)</mark>

* Poisoning :
  * LLMNR
  * NBT-NS
  * mDNS
* Permet :
  * capture de hashes
  * SMB Relay
  * mouvement latéral

👉 **Encore utilisé aujourd’hui**

***

### <mark style="color:blue;">🔴 2014 – Kerberos devient une cible</mark>

#### <mark style="color:green;">🔹 Kerberoasting (Tim Medin)</mark>

* Attaque offline des comptes service
* Exploite :
  * SPN
  * mots de passe faibles

#### <mark style="color:green;">🔹 PowerView (Veil / PowerSploit)</mark>

* Énumération AD avancée
* Base de **tous les outils modernes**

***

### <mark style="color:blue;">🔴 2015 – L’année fondatrice</mark>

#### <mark style="color:green;">🔹 Empire (PowerShell Empire)</mark>

* Framework post-exploitation
* Command & Control AD

#### <mark style="color:green;">🔹 DCSync (Mimikatz)</mark>

* Extraction des hashes du domaine
* Abus des droits de réplication AD

#### <mark style="color:green;">🔹 CrackMapExec</mark>

* “Swiss Army Knife” AD
* Enum, auth, exec, lateral movement

#### <mark style="color:green;">🔹 Impacket</mark>

* Outils Python AD
* smbexec, wmiexec, secretsdump, etc.

#### <mark style="color:green;">🔹 Kerberos Unconstrained Delegation</mark>

* Présenté par Sean Metcalf
* Compromission massive possible

***

### <mark style="color:blue;">🔴 2016 – Révolution visuelle</mark>

#### 🔹 <mark style="color:green;">BloodHound</mark>

* Graphes de chemins d’attaque
* Basé sur :
  * ACL
  * Groupes
  * Délégations
* Change totalement la manière d’attaquer AD

👉 **Outil indispensable**

***

### <mark style="color:blue;">🔴 2017 – ACL & Kerberos</mark>

#### <mark style="color:green;">🔹 AS-REP Roasting</mark>

* Comptes sans pré-auth Kerberos
* Hashs récupérables sans mot de passe

#### <mark style="color:green;">🔹 ACL Attacks (“ACE Up the Sleeve”)</mark>

* Exploitation des permissions AD
* Abus de WriteDACL / GenericAll

***

### <mark style="color:blue;">🔴 2018 – Attaques avancées & trusts</mark>

🔹 Printer Bug / SpoolSample

* Forcer une authentification machine
* Coercion NTLM

🔹 Rubeus

* Toolkit Kerberos
* Tickets, delegation, roasting

🔹 DCShadow

* Faux DC
* Injection de changements AD

🔹 Attaques cross-forest trusts

* “Not a Security Boundary”

🔹 PingCastle

* Audit défensif AD
* Détection de misconfigs

***

### <mark style="color:blue;">🔴 2019 – Délégation moderne</mark>

🔹 RBCD (Resource-Based Constrained Delegation)

* Abus de msDS-AllowedToAct
* Très fréquent en lab & réel

🔹 Kerberoasting revisité

* Nouvelles techniques d’opsec

***

### <mark style="color:blue;">🔴 2020 – Catastrophe totale</mark>

🔹 Zerologon

* Compromission DC
* Pas de credentials
* Impact critique (CVE-2020-1472)

***

### <mark style="color:blue;">🔴 2021 – L’enfer</mark>

🔹 PrintNightmare

* RCE via Print Spooler
* Compromission massive

🔹 Shadow Credentials

* Ajout de clés sur comptes AD
* Login sans mot de passe

🔹 noPac

* Chaînage de failles
* Domain Admin depuis simple user

***

### <mark style="color:blue;">🔁 Leçons importantes</mark>

* Les attaques AD :
  * ne disparaissent pas
  * se combinent
  * se chaînent
* Les outils évoluent
* Azure AD + hybride = **nouvelle surface**

***

### <mark style="color:blue;">🧠 Pour un pentester AD</mark>

Tu dois connaître :

* Les **attaques historiques**
* Les **outils classiques**
* Les **patterns d’abus**

👉 Parce que :

> “Les attaques modernes sont des variantes d’anciennes”

***

### <mark style="color:blue;">🛠️ Outils AD indispensables (à mémoriser)</mark>

* Responder
* BloodHound
* Impacket
* CrackMapExec
* Rubeus
* Mimikatz
* Certipy
* PingCastle (défense)

***

### <mark style="color:blue;">🧾 Résumé ultra court</mark>

```
AD est attaqué depuis 10+ ans
Les attaques évoluent mais se recyclent
Un simple user suffit souvent
Les outils reflètent la recherche
```

***

### <mark style="color:blue;">🧠 Phrase à retenir (exam / interview)</mark>

> “Active Directory n’est pas cassé par un bug unique,\
> mais par l’accumulation de choix historiques et de mauvaises configurations.”

***
