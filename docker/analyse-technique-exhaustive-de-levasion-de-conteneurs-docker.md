# Analyse Technique Exhaustive de l'Évasion de Conteneurs Docker

## <mark style="color:red;">Analyse Technique Exhaustive de l'Évasion de Conteneurs Docker</mark>&#x20;

L'essor de la conteneurisation a radicalement transformé le cycle de vie du développement logiciel, offrant une agilité et une efficacité sans précédent. Cependant, cette technologie repose sur une abstraction de l'isolation qui, contrairement à la virtualisation matérielle, partage le même noyau que l'hôte. L'évasion de conteneur, souvent désignée sous le terme de "Docker Escape" ou "Container Breakout", représente l'ultime compromission d'un environnement conteneurisé, permettant à un acteur malveillant de franchir les barrières logicielles pour accéder aux ressources du système hôte ou à d'autres conteneurs adjacents. Cette analyse approfondie explore les mécanismes fondamentaux de l'isolation Linux, les phases critiques d'énumération, l'exploitation des mauvaises configurations, ainsi que les vulnérabilités du noyau et du runtime documentées jusqu'en 2026.

***

### <mark style="color:blue;">Fondements de l'Isolation et Architecture des Conteneurs</mark>

Pour comprendre les vecteurs d'évasion, il est impératif d'analyser les piliers de l'isolation Linux sur lesquels Docker s'appuie. L'isolation n'est pas une barrière physique mais une construction logique orchestrée par plusieurs primitives du noyau.

#### <mark style="color:green;">Les Espaces de Nommage (Namespaces)</mark>

Les espaces de nommage définissent la vision qu'un processus a du système. Ils compartimentent les ressources globales en instances isolées. Le tableau suivant récapitule les principaux types d'espaces de nommage et leur rôle dans la sécurité des conteneurs.

| **Type de Namespace** | **Ressource Isolée**                                | **Impact en cas de Partage avec l'Hôte**                   |
| --------------------- | --------------------------------------------------- | ---------------------------------------------------------- |
| PID                   | Arbre des processus                                 | Visibilité et interaction avec les processus de l'hôte     |
| NET                   | Pile réseau (interfaces, tables de routage)         | Capacité de reniflage et d'attaque sur le réseau de l'hôte |
| MNT                   | Points de montage du système de fichiers            | Accès direct aux fichiers et répertoires de l'hôte         |
| UTS                   | Nom d'hôte et nom de domaine NIS                    | Usurpation d'identité réseau                               |
| IPC                   | Communication inter-processus (mémoire partagée)    | Interception de communications sensibles                   |
| USER                  | Identifiants d'utilisateurs et de groupes (UID/GID) | Escalade de privilèges vers le root de l'hôte              |

L'absence d'activation des espaces de nommage utilisateur (User Namespaces) dans les configurations par défaut de nombreuses distributions Docker signifie que le compte root à l'intérieur d'un conteneur possède le même identifiant (UID 0) que le root sur l'hôte, augmentant considérablement le risque en cas de faille de cloisonnement.

***

#### <mark style="color:green;">Groupes de Contrôle (Cgroups)</mark>

Les cgroups gèrent l'allocation des ressources telles que le CPU, la mémoire et les entrées/sorties. Ils jouent également un rôle crucial dans les mécanismes d'évasion, notamment via la gestion des notifications de libération de groupe (release\_agent) dans la version 1 des cgroups.

***

#### <mark style="color:green;">Capacités Linux (Capabilities)</mark>

Le noyau Linux décompose les privilèges traditionnels du root en unités granulaires appelées capacités. Docker restreint par défaut ces capacités pour limiter la surface d'attaque. Néanmoins, l'attribution excessive de capacités, souvent pour des besoins de débogage ou d'administration, crée des vecteurs d'évasion directs.

***

### <mark style="color:blue;">Phase I : Énumération et Reconnaissance de l'Environnement</mark>

L'énumération est la première étape critique d'une tentative d'évasion. Elle vise à cartographier les privilèges du conteneur, les vulnérabilités du noyau hôte et les points de contact entre le conteneur et son environnement de runtime.

#### <mark style="color:green;">Identification de la Plateforme et du Runtime</mark>

L'attaquant cherche d'abord à confirmer la présence d'un environnement conteneurisé. Des indicateurs classiques incluent l'existence du fichier `.dockerenv` à la racine ou l'analyse des entrées dans `/proc/1/cgroup` qui contiennent souvent l'identifiant unique du conteneur. L'utilisation de commandes telles que `uname -a` permet d'identifier l'architecture de l'hôte (x64, ARM) et la version du noyau, guidant ainsi le choix des exploits potentiels.

#### <mark style="color:green;">Audit des Capacités et Privilèges</mark>

L'identification des capacités actives est primordiale. L'outil `capsh --print` est la méthode de référence pour lister les privilèges effectifs. En l'absence de cet outil, l'attaquant peut décoder le masque binaire présent dans `/proc/self/status` sous l'entrée `CapEff`.

Certaines capacités sont particulièrement dangereuses :

* `CAP_SYS_ADMIN` : Permet de monter des systèmes de fichiers et de manipuler les cgroups.
* `CAP_SYS_PTRACE` : Autorise le débogage de processus, permettant l'injection de code dans des processus s'exécutant sur l'hôte si le namespace PID est partagé.
* `CAP_SYS_MODULE` : Permet le chargement de modules noyau arbitraires sur l'hôte.
* `CAP_DAC_OVERRIDE` : Permet de contourner les restrictions de lecture/écriture de fichiers, facilitant l'accès à des données sensibles sur l'hôte via des montages.

#### <mark style="color:green;">Énumération Réseau et Mouvements Latéraux</mark>

L'énumération réseau interne permet de découvrir d'autres conteneurs sur le même pont (bridge) Docker. Des outils comme `nmap` ou des scripts `sh` purs comme DEEPCE effectuent des balayages de ports vers l'adresse IP de la passerelle (souvent l'hôte) et les segments adjacents. La recherche de sockets exposés, comme le socket Docker (`/var/run/docker.sock`) ou des interfaces API non authentifiées, constitue une priorité stratégique.

***

### <mark style="color:blue;">Phase II : Mauvaises Configurations et Abus de Privilèges</mark>

La majorité des évasions réussies ne proviennent pas de vulnérabilités "zero-day", mais de configurations trop permissives destinées à faciliter le développement ou l'administration système.

#### <mark style="color:green;">Le Risque du Mode Privilégié</mark>

L'exécution d'un conteneur avec l'option `--privileged` désactive pratiquement toutes les protections de sécurité du noyau. Le conteneur reçoit toutes les capacités Linux et un accès direct aux périphériques de l'hôte via `/dev`. Dans ce mode, l'évasion est triviale : l'attaquant peut simplement monter la partition racine de l'hôte à l'intérieur du conteneur et accéder à l'intégralité du système de fichiers de l'hôte.

#### <mark style="color:green;">Montage du Socket Docker (</mark><mark style="color:green;">`docker.sock`</mark><mark style="color:green;">)</mark>

Le montage du socket UNIX Docker (`/var/run/docker.sock`) à l'intérieur d'un conteneur est une pratique courante pour permettre à un conteneur de gérer d'autres conteneurs (modèle "Docker-in-Docker"). Cependant, quiconque possède des droits d'écriture sur ce socket dispose de l'équivalent d'un accès root sur l'hôte.

L'attaquant peut utiliser le client Docker (ou `curl` si le client n'est pas installé) pour communiquer avec le démon Docker de l'hôte et créer un nouveau conteneur doté des privilèges maximums, montant le système de fichiers hôte dans `/mnt`. Une simple commande `chroot /mnt` permet alors de basculer définitivement sur l'hôte.

#### <mark style="color:green;">Abus de CAP\_SYS\_ADMIN et du mécanisme Release Agent</mark>

L'une des techniques les plus sophistiquées issues des forums spécialisés concerne l'abus de la capacité `CAP_SYS_ADMIN` combinée aux cgroups v1. Ce vecteur repose sur le fichier `release_agent`, un mécanisme du noyau qui exécute un programme spécifique lorsqu'un cgroup devient vide.

La méthodologie d'exploitation suit un processus rigoureux :

1. Montage du cgroup : L'attaquant monte un système de fichiers cgroup de type RDMA ou autre.
2. Création d'un sous-groupe : Un nouveau répertoire est créé dans ce montage pour isoler l'attaque.
3. Configuration du déclencheur : La valeur `1` est écrite dans `notify_on_release`.
4. Injection du payload : Le chemin d'un script malveillant (situé dans le conteneur mais référencé par son chemin sur l'hôte) est écrit dans le fichier `release_agent`.
5. Déclenchement : L'attaquant lance un processus éphémère dans le cgroup et le laisse se terminer. Le noyau exécute alors le script avec les privilèges root de l'hôte.

L'astuce cruciale réside dans la détermination du chemin d'accès au script sur l'hôte. Les attaquants utilisent souvent `/etc/mtab` pour identifier le chemin de montage `overlay2` ou effectuent une recherche brute de PIDs via `/proc/<pid>/root`.

***

### <mark style="color:blue;">Phase III : Vulnérabilités du Noyau (Kernel Exploits)</mark>

Comme les conteneurs partagent le noyau de l'hôte, toute vulnérabilité de type élévation de privilèges locaux (LPE) dans le noyau peut être utilisée pour briser l'isolation.

#### Dirty Pipe (CVE-2022-0847)

Dirty Pipe est l'une des vulnérabilités les plus marquantes de ces dernières années, affectant les noyaux 5.8 et supérieurs. Elle permet à un processus non privilégié d'écrire dans n'importe quel fichier lisible, en exploitant une faille dans la gestion du cache de page (page cache) par les tubes (pipes) Linux.

Dans un contexte de conteneur, un attaquant peut utiliser Dirty Pipe pour :

* Écraser des binaires sur l'hôte si des fichiers sont montés en lecture seule.
* Modifier `/etc/passwd` pour ajouter un utilisateur root.
* Injecter du code malveillant dans le binaire `runc` utilisé par l'hôte, déclenchant l'exécution de code lors de la prochaine interaction avec un conteneur.

#### La Technique DirtyCred

DirtyCred n'est pas une vulnérabilité unique, mais une technique d'exploitation générique ciblant les structures de données du noyau. Elle utilise des vulnérabilités de type Use-After-Free (UAF) pour échanger des structures `cred` (identifiants de privilèges) ou des structures de fichiers sur le tas (heap) du noyau. Cette approche est particulièrement redoutable car elle est agnostique de la version du noyau et contourne de nombreuses protections modernes comme KASLR ou SMEP en se concentrant sur la manipulation de données légitimes plutôt que sur l'exécution de code malveillant direct.

#### Failles Speculative Execution (Spectre/Meltdown)

Bien que moins fréquentes dans les rapports d'attaques immédiates, les vulnérabilités matérielles liées à l'exécution spéculative (Spectre, Meltdown, L1TF) constituent une menace de fond pour l'isolation. Elles permettent d'extraire des données sensibles de la mémoire du noyau ou d'autres conteneurs via des canaux auxiliaires (side-channels). Les recherches récentes en 2025 mettent en avant des variantes capables de contourner les isolations logicielles des invités avec une grande fiabilité.

***

### <mark style="color:blue;">Phase IV : Failles du Runtime et de l'Infrastructure</mark>

Le runtime de conteneur (runc, containerd) est le logiciel responsable de la création et de la gestion des conteneurs selon les spécifications OCI. Ses vulnérabilités sont critiques car elles affectent les mécanismes fondamentaux de création de l'isolation.

#### Leaky Vessels (CVE-2024-21626)

Cette faille majeure dans `runc` (versions <= 1.1.11) est due à une fuite de descripteur de fichier lors du traitement de la directive `WORKDIR` dans un Dockerfile. Lors de l'initialisation du processus du conteneur, `runc` change de répertoire de travail (`fchdir`) avant de fermer certains descripteurs de fichiers privilégiés pointant vers le système de fichiers de l'hôte.

Un attaquant peut spécifier un chemin malveillant tel que `/proc/self/fd/7/../../../../` dans l'instruction `WORKDIR`. Cela permet au conteneur de démarrer avec un répertoire de travail situé directement sur le système de fichiers de l'hôte, brisant instantanément l'isolation `chroot` et permettant la modification de n'importe quel fichier sur l'hôte.

#### Les Vulnérabilités runc de fin 2025

En novembre 2025, trois nouvelles vulnérabilités critiques ont été révélées, soulignant la persistance des risques de conditions de course (race conditions) et de manipulations de liens symboliques.

| **Identifiant CVE** | **Nature de la Faille**                  | **Mécanisme d'Exploitation**                                                                                                                                                                        |
| ------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE-2025-31133      | Abus de `maskedPaths`                    | Remplacement de `/dev/null` par un lien symbolique vers `/proc/sys/kernel/core_pattern` pour forcer un montage read-write sur un fichier critique de l'hôte.                                        |
| CVE-2025-52565      | Course au montage `/dev/console`         | Exploitation d'une condition de course lors de l'initialisation pour rediriger le montage de la console vers des fichiers protégés de `procfs` avant l'application des protections.                 |
| CVE-2025-52881      | Contournement LSM via gadgets d'écriture | Utilisation de montages partagés pour tromper `runc` et le forcer à écrire des étiquettes de sécurité ou des paramètres `sysctl` dans des fichiers arbitraires, contournant ainsi AppArmor/SELinux. |

Ces vulnérabilités sont particulièrement dangereuses dans les environnements multi-locataires où les utilisateurs peuvent fournir leurs propres images de conteneurs ou Dockerfiles.

***

### <mark style="color:blue;">Techniques Avancées et Méthodes Issues de la Communauté</mark>

Au-delà des CVEs classiques, la communauté de la sécurité offensive a développé des méthodes ingénieuses pour exploiter les moindres faiblesses structurelles des conteneurs.

#### Injection de Processus via CAP\_SYS\_PTRACE

Si un conteneur dispose de la capacité `CAP_SYS_PTRACE` et partage le namespace PID avec l'hôte (`--pid=host`), l'évasion devient un exercice de manipulation de mémoire. L'attaquant peut lister les processus de l'hôte avec `ps aux`, identifier un processus root (comme `init` ou un terminal) et utiliser des outils de débogage pour injecter un code shell (shellcode) directement dans l'espace mémoire de ce processus. Le code injecté s'exécutera avec les privilèges du processus cible sur l'hôte, ouvrant souvent un shell inverse (reverse shell).

#### Détournement du `core_pattern`

La gestion des dumps de mémoire (coredumps) par le noyau est un vecteur d'évasion puissant. Le fichier `/proc/sys/kernel/core_pattern` définit le programme exécuté par le noyau lorsqu'un processus plante. Si un conteneur peut écrire dans ce fichier (via une capacité excessive ou une faille de runtime), il peut y spécifier le chemin d'un binaire malveillant situé dans le conteneur. En provoquant délibérément un plantage (segmentation fault), l'attaquant force le noyau de l'hôte à exécuter son payload avec les privilèges root de l'hôte.

#### Évasions Réseau et API SSRF

Des vulnérabilités récentes comme la faille CVE-2025-9074 sur Docker Desktop démontrent que l'évasion peut aussi passer par des services mal sécurisés sur le réseau interne. Dans ce cas précis, une interface API Docker Engine non authentifiée était exposée sur le réseau virtuel. Un attaquant, via une simple requête HTTP POST depuis l'intérieur d'un conteneur, pouvait demander au démon Docker de l'hôte de créer un nouveau conteneur avec un accès complet au disque `C:` de l'hôte, rendant l'isolation totalement inopérante.
