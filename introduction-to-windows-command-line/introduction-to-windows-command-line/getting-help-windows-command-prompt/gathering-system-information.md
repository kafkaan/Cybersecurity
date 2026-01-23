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

#### 1️⃣ Informations système générales

📌 Données sur l’OS et la machine

* Nom de l’hôte
* Version de Windows
* Build / Patchs installés
* Architecture (x86 / x64)
* Type de machine (workstation, serveur)

***

#### 2️⃣ Informations réseau

📌 Comment la machine communique

* Adresse IP
* Interfaces réseau
* Passerelle par défaut
* DNS
* Sous-réseaux accessibles
* Autres hôtes connus

***

#### 3️⃣ Informations de domaine (si AD)

📌 Intégration Active Directory

* Nom du domaine
* DC accessibles
* Groupes domaine
* Ressources réseau

***

#### 4️⃣ Informations utilisateur

📌 Ce que **notre compte** peut faire

* Utilisateur courant
* Groupes
* Privilèges
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

### <mark style="color:blue;">🧾 Commandes essentielles CMD</mark>

***

### 🖥️ Informations système

#### 🔹 systeminfo (commande clé)

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

#### 🔹 hostname

```cmd
hostname
```

➡️ Nom de la machine

***

#### 🔹 ver

```cmd
ver
```

➡️ Version exacte de Windows

***

### <mark style="color:blue;">🌐 Informations réseau</mark>

#### 🔹 ipconfig

```cmd
ipconfig
```

Affiche :

* IPv4 / IPv6
* Gateway
* DNS suffix

***

#### 🔹 ipconfig /all

```cmd
ipconfig /all
```

📌 Infos complètes :

* MAC address
* DNS servers
* DHCP
* Description interfaces

***

#### 🔹 arp /a

```cmd
arp /a
```

📌 Montre :

* Hôtes récemment contactés
* Mapping IP ↔ MAC

💡 Très utile pour **cartographier le réseau interne**

***

### <mark style="color:blue;">👤 Informations utilisateur</mark>

#### 🔹 whoami

```cmd
whoami
```

➡️ Utilisateur courant (domaine\user)

***

#### 🔹 whoami /priv

```cmd
whoami /priv
```

📌 Liste les privilèges :

* SeShutdownPrivilege
* SeImpersonatePrivilege
* etc.

🔥 **Clé pour l’escalade de privilèges**

***

#### 🔹 whoami /groups

```cmd
whoami /groups
```

📌 Groupes :

* Built-in
* Groupes custom
* Niveaux d’intégrité

***

#### 🔹 whoami /all

```cmd
whoami /all
```

➡️ Tout en un (user + groupes + privilèges)

***

### <mark style="color:blue;">👥 Autres utilisateurs & groupes</mark>

#### 🔹 net user

```cmd
net user
```

➡️ Liste des comptes locaux

***

#### 🔹 net user

```cmd
net user bob
```

➡️ Détails sur un utilisateur

***

#### 🔹 net localgroup

```cmd
net localgroup
```

➡️ Groupes locaux

***

#### 🔹 net group

```cmd
net group
```

⚠️ Fonctionne **uniquement sur un DC**

***

### <mark style="color:blue;">📁 Ressources réseau & partages</mark>

#### 🔹 net share

```cmd
net share
```

📌 Affiche :

* Partages locaux
* C$, ADMIN$, IPC$
* Partages custom (souvent intéressants)

***

#### 🔹 net view

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
