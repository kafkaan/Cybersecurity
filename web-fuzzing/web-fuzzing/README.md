---
icon: globe-wifi
---

# Web Fuzzing

***

### <mark style="color:blue;">🔎 Définition</mark>

**Web fuzzing** = technique de sécurité consistant à tester automatiquement une application web en lui envoyant des entrées **inattendues**, **invalides** ou **aléatoires** afin de détecter des comportements anormaux → potentiels **vulnérabilités**.

***

## <mark style="color:blue;">🔐 Fuzzing vs Brute-forcing</mark>

#### <mark style="color:green;">✔️ Fuzzing</mark>

* Approche **large**, exploratoire
* Envoie **tout type d’entrées**, même totalement incorrectes
* Objectif : **provoquer des erreurs**, des comportements inattendus
* Utilise : wordlists, mutations, données aléatoires
* → Détection de bugs et failles liées à la mauvaise gestion des entrées

**Exemple (concept) :**

Essayer des chaînes bizarres, caractères spéciaux, SQL, etc.

***

#### <mark style="color:green;">✔️ Brute-forcing</mark>

* Approche **ciblée**
* Teste **toutes les possibilités** pour une valeur précise
* Utilise des dictionnaires ou ranges prévisibles
* → Trouver un mot de passe, un ID, un fichier existant

**Analogie :**

* **Fuzzing** = tester n’importe quel objet pour voir si la porte s’ouvre
* **Brute-force** = essayer toutes les clés du trousseau

***

## <mark style="color:blue;">🎯 Pourquoi fuzzing une application web ?</mark>

**Avantages principaux**

* 🔍 **Découverte de vulnérabilités cachées**
* 🔁 **Automatisation des tests de sécurité**
* 🛡️ **Simulation d’attaques réelles**
* 🧹 **Amélioration de la validation des entrées**
* 🧩 **Amélioration générale de la qualité du code**
* 🔧 **Intégration dans un pipeline CI/CD** → sécurité continue

***

## <mark style="color:red;">🧠 Concepts essentiels à connaître</mark>

| Concept               | Définition                                       | Exemple                                  |
| --------------------- | ------------------------------------------------ | ---------------------------------------- |
| **Wordlist**          | Liste de mots/chemins/valeurs testés             | `admin`, `backup`, `config`, `productID` |
| **Payload**           | Donnée envoyée à l’application                   | `' OR 1=1 --`                            |
| **Response Analysis** | Analyse des réponses HTTP pour repérer anomalies | `500 Internal Server Error` suspect      |
| **Fuzzer**            | Outil automatisant fuzzing & analyse             | `ffuf`, `wfuzz`, `Burp Intruder`         |
| **False Positive**    | Résultat signalé à tort comme vulnérable         | 404 normal                               |
| **False Negative**    | Vulnérabilité existante mais non détectée        | bug logique subtil                       |
| **Fuzzing Scope**     | Zone ciblée par le test                          | login, API spécifique, endpoint précis   |

***

Voici **une fiche de révision synthétique et claire** sur la partie _Tooling_ du cours Web Fuzzing.

***

## <mark style="color:red;">Web Fuzzing : Tooling</mark>

***

### <mark style="color:blue;">⚙️ FFUF</mark>

**Fuzz Faster U Fool** — fuzzer rapide écrit en Go.

**Installation**

```bash
go install github.com/ffuf/ffuf/v2@latest
```

**🎯 Principaux cas d’usage**

| Use Case                   | Description                              |
| -------------------------- | ---------------------------------------- |
| Directory/File Enumeration | Trouver dossiers et fichiers cachés      |
| Parameter Discovery        | Identifier des paramètres non documentés |
| Brute-Force                | Essayer des valeurs (ex: identifiants)   |

***

### <mark style="color:blue;">⚙️ GoBuster</mark>

Outil simple et rapide pour la découverte de contenu web.

**Installation**

```bash
go install github.com/OJ/gobuster/v3@latest
```

**🎯 Principaux cas d’usage**

| Use Case                  | Description                             |
| ------------------------- | --------------------------------------- |
| Content Discovery         | Détection de dossiers, fichiers, vhosts |
| DNS Subdomain Enumeration | Trouver des sous-domaines               |
| WordPress Detection       | Détection de contenu WordPress          |

***

### <mark style="color:blue;">⚙️ FeroxBuster</mark>

Outil de content discovery écrit en Rust → très performant.

**Installation**

```bash
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin
```

**🎯 Principaux cas d’usage**

| Use Case                   | Description                               |
| -------------------------- | ----------------------------------------- |
| Recursive Scanning         | Explore automatiquement les sous-dossiers |
| Unlinked Content Discovery | Trouve du contenu non référencé           |
| High-Performance Scans     | Très rapide grâce à Rust                  |

***

### <mark style="color:blue;">⚙️ wfuzz / wenum</mark>

**wenum** = fork moderne et maintenu de **wfuzz**, outil très flexible pour le fuzzing de paramètres.

Installation avec pipx

```bash
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

🎯 Principaux cas d’usage

| Use Case                   | Description                          |
| -------------------------- | ------------------------------------ |
| Directory/File Enumeration | Trouver des ressources web cachées   |
| Parameter Discovery        | Tester de multiples valeurs d’entrée |
| Brute-Force                | Attaques par force brute ciblées     |

***
