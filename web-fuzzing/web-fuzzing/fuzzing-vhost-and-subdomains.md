# Fuzzing VHost & Subdomains

### <mark style="color:blue;">📋 Concepts Clés</mark>

#### <mark style="color:green;">Virtual Hosts (VHosts)</mark>

* Permettent d'héberger plusieurs sites web sur un seul serveur/IP
* Identifiés par l'en-tête `Host` dans les requêtes HTTP
* Risque : exposition d'applications internes si mal configurés

#### <mark style="color:green;">Subdomains</mark>

* Extensions d'un domaine principal (ex: `blog.example.com`)
* Résolus via DNS vers des IPs spécifiques
* Risque : takeover de sous-domaines si DNS mal géré

| Critère            | Virtual Hosts                           | Subdomains                            |
| ------------------ | --------------------------------------- | ------------------------------------- |
| **Identification** | En-tête Host HTTP                       | Enregistrements DNS                   |
| **Usage**          | Héberger plusieurs sites sur un serveur | Organiser sections/services d'un site |

***

### <mark style="color:blue;">🛠️ Outil : Gobuster</mark>

**Gobuster** = outil en ligne de commande pour découvrir :

* Répertoires et fichiers cachés
* Subdomains
* Virtual Hosts

***

### <mark style="color:blue;">🎯 Fuzzing de Virtual Hosts</mark>

#### <mark style="color:green;">1. Préparation du fichier hosts</mark>

```bash
echo "94.237.59.242 inlanefreight.htb" | sudo tee -a /etc/hosts
```

> Remplace `IP` par l'adresse de ta cible

#### <mark style="color:green;">2. Commande Gobuster VHost</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
gobuster vhost -u http://94.237.59.242:53195-w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain
```
{% endcode %}

**Options expliquées :**

* `gobuster vhost` → Mode découverte de vhosts
* `-u http://inlanefreight.htb:81` → URL cible de base
* `-w /path/wordlist.txt` → Wordlist pour générer les noms
* `--append-domain` → **CRUCIAL** : ajoute le domaine de base à chaque mot (ex: `admin.inlanefreight.htb`)

#### <mark style="color:green;">3. Exemple de sortie</mark>

```bash
===============================================================
Gobuster v3.6
===============================================================
[+] Url:             http://inlanefreight.htb:81
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.inlanefreight.htb:81 Status: 200 [Size: 100]
Found: dev.inlanefreight.htb:81 Status: 200 [Size: 150]
...
Progress: 4730 / 4730 (100.00%)
===============================================================
```

**🔍 Analyse :**

* **Status 200** = vhost valide et accessible ✅
* **Status 400/404** = vhost invalide ou inaccessible ❌

***

### <mark style="color:blue;">🌐 Fuzzing de Subdomains</mark>

#### <mark style="color:green;">Commande Gobuster DNS</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
{% endcode %}

**Options expliquées :**

* `gobuster dns` → Mode énumération DNS/subdomains
* `-d inlanefreight.com` → Domaine cible
* `-w /path/wordlist.txt` → Wordlist de subdomains

⚠️ **Note :** Dans les dernières versions, `-d` = délai entre requêtes. Utilise `--domain` ou `--do` pour le domaine.

#### <mark style="color:green;">Exemple de sortie</mark>

```bash
===============================================================
Gobuster v3.6
===============================================================
[+] Domain:     inlanefreight.com
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: www.inlanefreight.com
Found: blog.inlanefreight.com
Found: api.inlanefreight.com
...
Progress: 4989 / 4990 (99.98%)
===============================================================
```

**Fonctionnement :**

1. Génère des noms de subdomains depuis la wordlist
2. Les ajoute au domaine cible
3. Tente de résoudre via DNS
4. Si résolution réussie → subdomain valide

***

### <mark style="color:blue;">📚 Wordlists Recommandées</mark>

#### Pour VHosts

```
/usr/share/seclists/Discovery/Web-Content/common.txt
```

#### Pour Subdomains

```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

***

### <mark style="color:blue;">💡 Astuces Pro</mark>

1. **Toujours analyser les codes HTTP** :
   * 200 = succès
   * 301/302 = redirection (peut être intéressant)
   * 403 = accès interdit (existe mais protégé)
   * 404 = non trouvé
2. **Filtrer les résultats** : Utilise `--exclude-length` ou `-b` pour exclure certaines tailles/codes
3. **Ajuster les threads** : `-t 50` pour accélérer (mais attention à la détection)
4. **Combiner les techniques** : VHosts + Subdomains = cartographie complète
