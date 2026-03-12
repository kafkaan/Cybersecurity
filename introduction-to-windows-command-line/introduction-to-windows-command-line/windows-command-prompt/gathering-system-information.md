# Gathering System Information

***

## <mark style="color:red;">🧠 Gathering System Information (Host Enumeration)</mark>

***

### <mark style="color:blue;">🔍 Qu’est-ce que l’énumération système ?</mark>

L’énumération système (host enumeration) consiste à :

* **observer**
* **cartographier**
* **comprendre**\
  un système et ses interactions (réseau, utilisateurs, domaine).

🎯 But : obtenir une **vision globale** de la machine compromise.

***

### <mark style="color:blue;">🗂️ Types d’informations à collecter</mark>

#### <mark style="color:green;">1️⃣ Informations système générales</mark>

📌 Données sur l’OS et la machine

* Nom de l’hôte
* Version de Windows
* Build / Patchs installés
* Architecture (x86 / x64)
* Type de machine (workstation, serveur)

***

#### <mark style="color:green;">2️⃣ Informations réseau</mark>

📌 Comment la machine communique

* Adresse IP
* Interfaces réseau
* Passerelle par défaut
* DNS
* Sous-réseaux accessibles
* Autres hôtes connus

***

#### <mark style="color:green;">3️⃣ Informations de domaine (si AD)</mark>

📌 Intégration Active Directory

* Nom du domaine
* DC accessibles
* Groupes domaine
* Ressources réseau

***

#### <mark style="color:green;">4️⃣ Informations utilisateur</mark>

📌 Ce que **notre compte** peut faire

* Utilisateur courant
* Groupes
* Privilèges&#x20;
* Autres utilisateurs
* Tâches, services, partages accessibles

***

### <mark style="color:blue;">🧭 Méthodologie mentale (très important)</mark>

Pose-toi toujours ces questions :

* 🖥️ **Sur quelle machine suis-je ?**
* 🌐 **À quels réseaux est-elle connectée ?**
* 👤 **Quel utilisateur suis-je ?**
* 🔑 **Quels privilèges ai-je ?**
* 📁 **À quelles ressources puis-je accéder ?**

👉 Ça évite l’énumération “au hasard”.

***

## <mark style="color:red;">Commandes essentielles CMD</mark>

***

### <mark style="color:blue;">🖥️ Informations système</mark>

#### <mark style="color:green;">🔹 systeminfo (commande clé)</mark>

```cmd
systeminfo
```

📌 Donne :

* OS
* Build
* Hotfixes
* Domaine
* Carte réseau
* RAM / CPU

✅ **Très utile**\
❌ **Très bruyante (logs)**

***

#### <mark style="color:green;">🔹 hostname</mark>

```cmd
hostname
```

➡️ Nom de la machine

***

#### <mark style="color:green;">🔹 ver</mark>

```cmd
ver
```

➡️ Version exacte de Windows

***

### <mark style="color:blue;">🌐 Informations réseau</mark>

#### <mark style="color:green;">🔹 ipconfig</mark>

```cmd
ipconfig
```

Affiche :

* IPv4 / IPv6
* Gateway
* DNS suffix

***

#### <mark style="color:green;">🔹 ipconfig /all</mark>

```cmd
ipconfig /all
```

📌 Infos complètes :

* MAC address
* DNS servers
* DHCP
* Description interfaces

***

#### <mark style="color:green;">🔹 arp /a</mark>

```cmd
arp /a
```

📌 Montre :

* Hôtes récemment contactés
* Mapping IP ↔ MAC

💡 Très utile pour **cartographier le réseau interne**

***

### <mark style="color:blue;">👤 Informations utilisateur</mark>

#### <mark style="color:green;">🔹 whoami</mark>

```cmd
whoami
```

➡️ Utilisateur courant (domaine\user)

***

#### <mark style="color:green;">🔹 whoami /priv</mark>

```cmd
whoami /priv
```

📌 Liste les privilèges :

* SeShutdownPrivilege
* SeImpersonatePrivilege
* etc.

🔥 **Clé pour l’escalade de privilèges**

***

#### <mark style="color:green;">🔹 whoami /groups</mark>

```cmd
whoami /groups
```

📌 Groupes :

* Built-in
* Groupes custom
* Niveaux d’intégrité

***

#### <mark style="color:green;">🔹 whoami /all</mark>

```cmd
whoami /all
```

➡️ Tout en un (user + groupes + privilèges)

***

### <mark style="color:blue;">👥 Autres utilisateurs & groupes</mark>

#### <mark style="color:green;">🔹 net user</mark>

```cmd
net user
```

➡️ Liste des comptes locaux

***

#### <mark style="color:green;">🔹 net user</mark>

```cmd
net user bob
```

➡️ Détails sur un utilisateur

***

#### <mark style="color:green;">🔹 net localgroup</mark>

```cmd
net localgroup
```

➡️ Groupes locaux

***

#### <mark style="color:green;">🔹 net group</mark>

```cmd
net group
```

⚠️ Fonctionne **uniquement sur un DC**

***

### <mark style="color:blue;">📁 Ressources réseau & partages</mark>

#### <mark style="color:green;">🔹 net share</mark>

```cmd
net share
```

📌 Affiche :

* Partages locaux
* C$, ADMIN$, IPC$
* Partages custom (souvent intéressants)

***

#### <mark style="color:green;">🔹 net view</mark>

```cmd
net view
```

➡️ Découverte globale des ressources réseau visibles

***

### <mark style="color:blue;">🧠 Résumé ultra rapide</mark>

| Catégorie   | Commandes clés                       |
| ----------- | ------------------------------------ |
| Système     | systeminfo, hostname, ver            |
| Réseau      | ipconfig, ipconfig /all, arp /a      |
| Utilisateur | whoami, whoami /priv, whoami /groups |
| Comptes     | net user                             |
| Groupes     | net localgroup                       |
| Partages    | net share, net view                  |

***
