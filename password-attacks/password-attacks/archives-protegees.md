# Archives Protégées

### <mark style="color:blue;">Introduction aux Archives Protégées</mark>

Les fichiers d'archives (ou fichiers compressés) permettent de regrouper plusieurs fichiers dans un format unique, souvent pour faciliter le transfert ou l'organisation. Ils peuvent être protégés par mot de passe pour garantir la sécurité des données.

#### Extensions courantes des fichiers d'archives

* **Formats classiques** : `.tar`, `.gz`, `.rar`, `.zip`
* **Autres formats** : `.7z`, `.pkg`, `.rpm`, `.war`, `.gzip`
* **Chiffrement et protection** : `.bitlocker`, `.truecrypt`, `.kdbx`
* **Commandes pour récupérer une liste complète** :

{% code overflow="wrap" fullWidth="true" %}
```bash
curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```
{% endcode %}

***

### <mark style="color:blue;">Manipulation des Archives Protégées</mark>

#### Création et protection d'une archive avec `tar` et `openssl`

**Commande pour créer une archive compressée :**

```bash
tar -cvf archive.tar dossier/
```

**Ajout d'une protection par chiffrement :**

```bash
openssl enc -aes-256-cbc -salt -in archive.tar -out archive.tar.enc -k "motdepasse"
```

***

### <mark style="color:blue;">Méthodes de Cassage des Archives Protégées</mark>

Pour casser des archives protégées, on extrait les hachages puis on les utilise pour deviner le mot de passe via des outils comme `john` ou `hashcat`.

#### Extraction et cassage des ZIP

**Extraction des hachages avec `zip2john`**

```bash
zip2john fichier.zip > zip.hash
```

**Exemple de sortie :**

```
ZIP.zip/customers.csv:$pkzip2$1*2*2*0*2a*1e*...
```

**Cassage du hachage avec `john`**

```bash
john --wordlist=rockyou.txt zip.hash
```

**Affichage des mots de passe trouvés :**

```bash
john zip.hash --show
```

#### Crackage des fichiers chiffrés avec OpenSSL

Pour les fichiers chiffrés avec `openssl`, on peut utiliser un script ou une boucle pour tester les mots de passe.

**Identification du fichier**

```bash
file fichier.gzip
```

**Exemple de sortie :**

```
fichier.gzip: openssl enc'd data with salted password
```

**Boucle pour tester les mots de passe**

{% code fullWidth="true" %}
```bash
for i in $(cat rockyou.txt); do openssl enc -aes-256-cbc -d -in fichier.gzip -k $i 2>/dev/null | tar xz; done
```
{% endcode %}

***

### <mark style="color:blue;">Cassage des Archives BitLocker</mark>

BitLocker est un programme de chiffrement de partitions et de disques externes. Le hachage est extrait avec `bitlocker2john` puis cassé avec `hashcat`.

#### Extraction des hachages avec `bitlocker2john`

{% code fullWidth="true" %}
```bash
bitlocker2john -i fichier.vhd > backup.hashes
```
{% endcode %}

**Filtrage des hachages pertinents :**

```bash
grep "bitlocker\$0" backup.hashes > backup.hash
```

#### Cassage avec `hashcat`

{% code fullWidth="true" %}
```bash
hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
```
{% endcode %}

**Exemple de sortie :**

```
Session..........: hashcat
Status...........: Cracked
Hash.Name........: BitLocker
Hash.Target......: $bitlocker$0$16$02b329c...
```

***

### <mark style="color:blue;">Outils Clés pour les Archives Protégées</mark>

| Outil            | Usage                                 |
| ---------------- | ------------------------------------- |
| `zip2john`       | Extraction de hachages pour les ZIP   |
| `bitlocker2john` | Extraction de hachages pour BitLocker |
| `john`           | Cassage des mots de passe             |
| `hashcat`        | Cassage avancé avec GPU               |
| `openssl`        | Chiffrement et déchiffrement          |

***
