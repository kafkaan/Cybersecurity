---
cover: >-
  https://upload.wikimedia.org/wikipedia/commons/thumb/f/f9/Mitmproxy_logo.svg/1280px-Mitmproxy_logo.svg.png
coverY: 0
---

# MITPROXY

***

### <mark style="color:red;">🧩 Qu’est-ce que mitmproxy ?</mark>

* **mitmproxy** est un proxy interactif en Python.
* Permet :
  * Interception & modification des requêtes/réponses HTTP(S).
  * Proxy inverse (_reverse proxy_) pour se placer devant une appli (utile avec un certificat forgé).
  * Analyse et sauvegarde de trafic (ex: pour rejouer ou analyser offline).
  * Scripts d’automatisation en Python.

***

### <mark style="color:red;">🔐 Modes principaux</mark>

#### <mark style="color:blue;">1. Proxy classique (interception navigateur/app)</mark>

```bash
mitmproxy -p 8080
```

➡️ Configure ton navigateur/app à utiliser `127.0.0.1:8080` comme proxy.

#### <mark style="color:blue;">2. Transparent proxy (redirection réseau via iptables)</mark>

```bash
mitmproxy --mode transparent -p 8080
```

➡️ Tout le trafic est capturé, même sans configuration proxy côté client.

#### <mark style="color:blue;">3. Reverse proxy (ton cas dans le CTF)</mark>

```bash
mitmproxy --mode reverse:https://git.sorcery.htb \
          --certs match.sorcery.htb.pem \
          --save-stream-file traffic.raw \
          -k -p 443
```

➡️ Fonctionne comme un **reverse proxy TLS** :

* `match.sorcery.htb.pem` est ton **certificat frauduleux signé par la CA compromise**.
* Tu interposes ton proxy sur `443` pour que la victime pense parler à `git.sorcery.htb`.

***

### <mark style="color:red;">🛠 Options importantes</mark>

* `--mode reverse:<URL>` : proxy inverse vers la vraie cible.
* `--certs <domain.pem>` : charger un certificat personnalisé.
* `--save-stream-file traffic.raw` : sauvegarde brute du trafic intercepté.
* `-k` : ignorer la vérification de certificat côté client.
* `-p <port>` : port d’écoute du proxy.
* `-s <script.py>` : lancer un script Python d’automatisation.

***

### <mark style="color:red;">📂 Utilisation typique en pentest</mark>

#### <mark style="color:blue;">1. Interception HTTPS classique</mark>

* Installer le **certificat mitmproxy** côté client.
*   Lancer :

    ```bash
    mitmproxy -p 8080
    ```
* Observer requêtes/réponses en direct (`mitmweb` pour interface web).

***

#### <mark style="color:blue;">2. MITM avec certificat volé / forgé</mark>

Exemple CTF :

1. Tu compromises une CA → tu signes `match.sorcery.htb.pem`.
2.  Tu lances un reverse proxy :

    ```bash
    mitmproxy --mode reverse:https://git.sorcery.htb \
              --certs match.sorcery.htb.pem \
              -p 443
    ```
3. Les clients font confiance car ton certificat est valide.
4. Tu interceptes et peux **voler des tokens JWT, cookies, credentials Git**.

***

#### <mark style="color:blue;">3. Automatisation avec script Python</mark>

Exemple `inject.py` :

```python
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if "password" in flow.response.text:
        print("[+] Password found:", flow.response.text)
```

Lancer avec :

```bash
mitmproxy -s inject.py -p 8080
```

***

### <mark style="color:red;">🔎 Cas d’usage offensifs en CTF/Pentest</mark>

* **Intercept Git over HTTPS** : dump credentials Basic Auth ou tokens OAuth.
* **Modifier des réponses API** pour contourner restrictions (auth bypass).
* **Injecter payloads XSS/SQLi** dans des requêtes envoyées par le client.
* **Rejouer un trafic sensible** avec `mitmdump -nr traffic.raw`.

***
