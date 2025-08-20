# John the Ripper (JTR)

## <mark style="color:red;">1.</mark> <mark style="color:red;"></mark><mark style="color:red;">**Introduction à John the Ripper (JTR)**</mark>

John the Ripper (JTR), souvent abrégé "john", est un outil essentiel utilisé dans le pentesting pour tester la robustesse des mots de passe et cracker les mots de passe chiffrés ou hachés.&#x20;

***

## <mark style="color:red;">2.</mark> <mark style="color:red;"></mark><mark style="color:red;">**Technologies de chiffrement prises en charge**</mark>

* **Crypt(3) UNIX** : Utilise une clé de 56 bits pour chiffrer.
* **DES-based** : Standard de chiffrement des données (clé de 56 bits).
* **Blowfish (OpenBSD)** : Clé de 448 bits pour le chiffrement.
* **MD5 (FreeBSD, Linux, Cisco)** : Clé de 128 bits.
* **SHA-crypt** : Hachage avec clé de 256 bits (Fedora, Ubuntu).
* **Kerberos, Windows LM, MS SQL** : Hachages liés à l’authentification des systèmes.

***

## <mark style="color:red;">3.</mark> <mark style="color:red;"></mark><mark style="color:red;">**Méthodes d'attaque**</mark>

### <mark style="color:blue;">**3.1 Attaque par dictionnaire**</mark>

L’attaque par dictionnaire consiste à utiliser une liste pré-générée de mots (dictionnaire) pour tenter de cracker un mot de passe. Elle repose sur des mots courants ou des mots de passe précédemment fuités.

### <mark style="color:blue;">**3.2 Attaque par force brute**</mark>

Cette méthode teste toutes les combinaisons possibles de caractères. Elle est efficace mais très lente et devient impraticable avec des mots de passe complexes et longs.

### <mark style="color:blue;">**3.3 Attaque par table arc-en-ciel**</mark>

Une attaque par table arc-en-ciel utilise des tables de hachages pré-calculées pour accélérer le processus de décryptage des mots de passe. Cependant, cette méthode est limitée par la taille de la table.

***

## <mark style="color:red;">4.</mark> <mark style="color:red;"></mark><mark style="color:red;">**Modes de cracking de John the Ripper**</mark>

### <mark style="color:blue;">**4.1 Mode Single Crack**</mark>

* Il s’agit de la méthode la plus simple, où John tente de cracker un mot de passe à partir d'une liste de mots. La commande de base est :

```
john --format=<hash_type> <hash_file>
```

Par exemple, pour cracker des hachages SHA-256, utilisez :

```
john --format=sha256 hashes_to_crack.txt
```

### <mark style="color:blue;">4.2 Mode Wordlist</mark>

* Le mode Wordlist utilise plusieurs listes de mots pour essayer de cracker des hachages en les comparant à des mots de passe dans ces listes. La commande est :

```
john --wordlist=<wordlist_file> --rules <hash_file>
```

* Le paramètre --rules applique des règles de transformation aux mots (ajouter des chiffres, mettre en majuscule, etc.).&#x20;

### <mark style="color:blue;">4.3 Mode Incremental</mark>

* Le mode Incremental est une attaque hybride qui génère toutes les combinaisons possibles de caractères à partir d'un jeu de caractères donné. C'est le mode le plus complet mais également le plus lent.

```
john --incremental <hash_file>
```

Le mode incrémental fonctionne mieux pour des mots de passe faibles ou lorsque le jeu de caractères est limité.&#x20;

***

## <mark style="color:red;">5. Cracking de fichiers protégés</mark>

John the Ripper peut cracker des fichiers protégés en utilisant des outils externes pour générer des hachages exploitables par John. Exemple de commande pour cracker un fichier PDF protégé :

```
cry0l1t3@htb:~$ <tool> <file_to_crack> > file.hash
cry0l1t3@htb:~$ pdf2john server_doc.pdf > server_doc.hash
cry0l1t3@htb:~$ john server_doc.hash
                # OR
cry0l1t3@htb:~$ john --wordlist=<wordlist.txt> server_doc.hash 
```

D'autres outils de conversion incluent :

```
ssh2john : Pour les clés SSH.
rar2john : Pour les archives RAR.
zip2john : Pour les fichiers ZIP.
keepass2john : Pour les bases de données KeePass.
wpa2john : Pour les captures WPA/WPA2.
```

***

## <mark style="color:red;">6. Formats de hachage pris en charge par John the Ripper</mark>

John the Ripper supporte de nombreux formats de hachages, dont :

```
LM, NT : Windows (NT LAN Manager).
MySQL, MSSQL : Bases de données SQL.
MD5, SHA1 : Algorithmes courants de hachage.
PDF, ZIP, RAR : Pour les fichiers protégés par mot de passe.
Kerberos, Oracle : Systèmes d'authentification sécurisés.
SSH, OpenSSL : Clés SSH et certificats.
```

***
