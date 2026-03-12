# CERTIFICATS HTTPS

***

### <mark style="color:blue;">🧩 Concepts clés</mark>

#### <mark style="color:green;">1. Les acteurs</mark>

* **CA (Certificate Authority)** : Autorité de Certification (ex : RootCA.crt). Elle signe des certificats pour prouver leur authenticité.
* **Serveur** : Présente un certificat (`server.crt`) pour prouver son identité au client.
* **Client (navigateur)** : Vérifie que le certificat est signé par une CA de confiance.

***

#### <mark style="color:green;">2. Les fichiers importants</mark>

* **.key** → clé privée (gardée secrète, ex: `server.key`)
* **.crt / .cer** → certificat signé (clé publique + signature CA)
* **.csr** → _Certificate Signing Request_, demande de signature envoyée à la CA
* **.pem** → format conteneur texte (peut contenir clé + cert + CA)
* **.der** → format binaire (souvent utilisé côté Windows)

***

#### <mark style="color:green;">3. La chaîne de confiance</mark>

```
Root CA (RootCA.crt + RootCA.key)
   │
   ├── Intermediate CA (signée par Root CA)
   │        └── Server Certificate (ex: match.sorcery.htb.crt)
   │
Client (navigateur) → Vérifie la signature remonte bien à une Root CA de confiance
```

***

### <mark style="color:blue;">🔐 Cycle de vie d’un certificat (avec OpenSSL)</mark>

#### <mark style="color:green;">1. Générer une clé privée</mark>

```bash
openssl genrsa -out server.key 2048
```

#### <mark style="color:green;">2. Créer une CSR (demande de signature)</mark>

```bash
openssl req -new -key server.key -out server.csr -subj "/CN=match.sorcery.htb"
```

#### <mark style="color:green;">3. Signer avec une CA</mark>

**a) Déchiffrer une clé CA protégée**

```bash
openssl rsa -in RootCA.key -out RootCA-unenc.key
```

(→ ici, tu as bruteforcé la passphrase `password`)

**b) Générer le certificat serveur signé par la CA**

{% code fullWidth="true" %}
```bash
openssl x509 -req -in server.csr -CA RootCA.crt -CAkey RootCA-unenc.key -CAcreateserial -out server.crt -days 365
```
{% endcode %}

#### <mark style="color:green;">4. Combiner en fichier PEM (clé privée + certificat)</mark>

```bash
cat server.key server.crt > server.pem
```

➡️ Utile pour configurer Apache, Nginx, stunnel, etc.

#### Résumé ultra simple

| Fichier      | C'est quoi                         | Secret ?                        |
| ------------ | ---------------------------------- | ------------------------------- |
| `server.key` | Ta clé privée                      | ✅ oui, ne jamais partager       |
| `server.csr` | Ta demande de certificat           | ❌ non, tu l'envoies à la CA     |
| `RootCA.key` | Clé privée de la CA                | ✅ oui (bruteforcée ici)         |
| `RootCA.crt` | Certificat public de la CA         | ❌ non, tout le monde le voit    |
| `server.crt` | Ton certificat signé               | ❌ non, tu le donnes aux clients |
| `server.pem` | `server.key` + `server.crt` collés | ✅ oui (contient la clé privée)  |

***

### <mark style="color:blue;">🛠 Commandes OpenSSL utiles en pentest/CTF</mark>

#### <mark style="color:green;">🔎 Inspection</mark>

* Lire un certificat :

```bash
openssl x509 -in server.crt -text -noout
```

* Vérifier une clé privée :

```bash
openssl rsa -in server.key -check
```

* Vérifier correspondance clé ↔ certificat :

```bash
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
```

#### <mark style="color:green;">🔑 Attaques / Exfiltration</mark>

* Bruteforce passphrase d’une clé :

```bash
while read pass; do
  openssl rsa -in RootCA.key -out /dev/null -passin pass:"$pass" 2>/dev/null \
  && echo "Found: $pass" && break
done < rockyou.txt
```

* Créer un certificat malveillant pour usurper un domaine (MITM, Auth bypass si certs sont utilisés pour login).

#### 🌐 Tests SSL/TLS

* Tester un service TLS :

```bash
openssl s_client -connect target:443 -servername match.sorcery.htb
```

* Dump certificat reçu :

```bash
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -text
```

***

### <mark style="color:blue;">🎯 Exemple d’exploitation en CTF (ton cas)</mark>

1. Récupération de `RootCA.key` (protégé par passphrase).
2. Bruteforce → passphrase = `password`.
3. Déchiffrement clé CA : `RootCA-unenc.key`.
4. Génération clé + CSR pour domaine cible `match.sorcery.htb`.
5. Signature du CSR avec la CA compromise.
6. Utilisation du certificat forgé pour :
   * Soit **MITM TLS** (attaque type proxy).
   * Soit **authentification mutuelle TLS** (si le serveur demande un client cert signé par la CA).

***

✅ En résumé :

* `.key` = clé privée
* `.csr` = demande de signature
* `.crt` = certificat signé
* `.pem` = conteneur mixte
* Avec une CA compromise, on peut forger des certificats valides et usurper l’identité d’un serveur ou d’un client.

***
