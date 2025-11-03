# Certificate Cracking (PFX/PEM)

***

### <mark style="color:red;">Certificate Cracking (PFX/PEM)</mark>

#### 📖 Concept

Les certificats `.pfx` et clés `.key` sont souvent protégés par mot de passe. Le cracking permet d'extraire les informations d'authentification.

#### 🔧 Outils

* `pfx2john` : Extraire le hash d'un PFX
* `pem2john` : Extraire le hash d'une clé PEM
* `john` : Cracker les hashes
* `hashcat` : Alternative plus rapide

#### 💣 Exploitation

**Cracker un fichier PFX**

```bash
# Extraire le hash
pfx2john clark.pfx > clark.hash

# Cracker avec John
john --wordlist=/usr/share/wordlists/rockyou.txt clark.hash

# Cracker avec Hashcat (mode 24420)
hashcat -m 24420 clark.hash rockyou.txt
```

**Cracker une clé PEM chiffrée**

```bash
# Extraire le hash
pem2john.py baker.key > baker.hash

# Nettoyer le hash (retirer les métadonnées)
# Retirer: $pbkdf2$sha256$aes256_cbc
sed 's/\$pbkdf2\$sha256\$aes256_cbc//' baker.hash > baker_clean.hash

# Cracker
hashcat -m 24420 baker_clean.hash rockyou.txt
```

#### 📊 Extraction d'informations

```bash
# Lire un certificat .crt
openssl x509 -in baker.crt -text -noout

# Extraire le certificat d'un PFX
openssl pkcs12 -in clark.pfx -clcerts -nokeys -out clark.crt

# Extraire la clé d'un PFX
openssl pkcs12 -in clark.pfx -nocerts -out clark.key -nodes

# Créer un PFX sans mot de passe
openssl pkcs12 -export -out output.pfx -inkey key.pem -in cert.crt -passout pass:
```

#### 🎯 Informations clés dans un certificat

```bash
# Username
subject=DC=htb, DC=scepter, CN=Users, CN=d.baker

# Email (important pour ESC14)
emailAddress=d.baker@scepter.htb

# Issuer (CA)
issuer=DC=htb, DC=scepter, CN=scepter-DC01-CA
```

***
