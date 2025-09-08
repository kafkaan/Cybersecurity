# Ptrace (Process Trace) - Cours Complet

## <mark style="color:red;">Ptrace (Process Trace)</mark>

### <mark style="color:blue;">Introduction</mark>

Linux fournit ptrace comme un outil de traçage de processus, qui peut intercepter les appels système à leurs points d'entrée et de sortie, effectués par un autre processus. ptrace fournit un mécanisme par lequel un processus parent peut observer et contrôler l'exécution d'un autre processus. Il peut examiner et modifier l'image mémoire centrale et les registres d'un processus enfant, et est principalement utilisé pour implémenter le débogage par points d'arrêt et le traçage d'appels système.

### <mark style="color:blue;">Syntaxe de ptrace</mark>

ptrace prend les arguments suivants :

```c
long ptrace(enum __ptrace_request request,
            pid_t pid,
            void *addr,
            void *data);
```

Où :

* **request** = type de comportement de ptrace. Par exemple, nous pouvons nous attacher ou nous détacher d'un processus, lire/écrire des registres, lire/écrire le segment de code et le segment de données.
* **pid** = identifiant du processus tracé
* **addr** = adresse
* **data** = données

<figure><img src="../../.gitbook/assets/Screenshot From 2025-09-07 18-42-00.png" alt=""><figcaption></figcaption></figure>

### <mark style="color:blue;">Deux méthodes pour tracer un processus</mark>

#### <mark style="color:green;">1. Méthode par processus enfant</mark>

L'application tracée peut être exécutée comme un enfant, en exécutant fork() dans le processus parent, ou l'application traceur. Dans ce cas, l'application tracée doit appeler ptrace avec les paramètres suivants :

```c
ptrace(PTRACE_TRACEME, 0, NULL, NULL);
```

**Important :** Cela signifie que nous devons modifier le code source de l'application tracée pour ajouter cette ligne de code.

#### <mark style="color:green;">2. Méthode par attachement</mark>

Si une application est déjà en cours d'exécution et que nous voulons la tracer, alors l'application traceur peut utiliser le format suivant de ptrace :

```c
ptrace(PTRACE_ATTACH, pid_of_traced_process, NULL, NULL);
```

Dans ce cas, l'application tracée n'a pas besoin d'ajouter de code. Dans les deux cas, tout ce dont nous avons besoin est l'identifiant du processus ou pid pour tracer une application. Le pid d'un processus en cours d'exécution est obtenu en exécutant la commande `ps` sous Linux. Une fois tracée, l'application tracée devient un processus enfant de l'application traceur.

### <mark style="color:blue;">Fonctionnement du traçage</mark>

Une fois qu'un processus est tracé, chaque fois que le processus tracé exécute un appel système ou revient d'un appel système, le contrôle d'exécution est transféré à l'application traceur. Alors l'application traceur peut vérifier les arguments de l'appel système ou faire d'autres choses, telles que regarder dans les registres, modifier les valeurs des registres, injecter du code dans le segment de code.

De plus, les valeurs retournées par l'appel système peuvent être accessibles et modifiées de manière similaire. Une fois que l'application traceur a fini d'examiner l'appel système, l'application tracée peut continuer avec l'appel système.

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

Une fois que le client se connecte au serveur, il affiche quelques informations de base du socket. Par exemple, il affiche la taille du buffer et l'algorithme de contrôle de congestion utilisé pour cette connexion. Ensuite, le client demande le message à l'utilisateur, qui est plus tard transmis au serveur et affiché.

**Note :** Pour distinguer entre les sorties affichées par le client et l'application ptrace (intercepteur), qui est expliquée plus tard, les commandes d'affichage exécutées par le client commencent par `CLIENT:`. De même, les sorties de l'application intercepteur commencent par `INTERCEPTOR:`.

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

### <mark style="color:blue;">Code de l'intercepteur</mark>

Le segment de code suivant de l'application intercepteur décrit l'idée sur comment tracer une application :

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

#### <mark style="color:green;">Explication du code</mark>

1. **Préparation des arguments :** D'abord, les arguments passés à l'intercepteur sont copiés dans un tableau.
2. **Création du processus enfant :** Ensuite, un processus enfant est créé en exécutant la commande fork. À ce point, le processus enfant est juste une image du processus parent (intercepteur), mais il ne fait rien de significatif.
3. **Activation du traçage :** Avant d'exécuter réellement l'application cliente (qui est passée dans la liste de commandes), le traçage du processus enfant est démarré en appelant la fonction ptrace. Par conséquent, l'intercepteur piègera chaque appel système dès le début qui sera fait par ce processus enfant.
4. **Exécution de l'application :** Une fois que le traçage est démarré, l'application cliente est exécutée par la commande execvp.

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

#### Qu'est-ce qu'un processus ?

* Un **processus** = un programme qui s'exécute en mémoire
* Chaque processus a un **PID** (Process ID) unique
* Un processus peut créer d'autres processus

#### La relation parent-enfant

```
Processus Parent (PID: 1234)
    |
    └── Processus Enfant (PID: 5678)
```

### <mark style="color:blue;">2. La fonction fork() - Comment créer un enfant</mark>

#### Avant fork() :

```
[Processus A] - PID: 1234
```

#### Après fork() :

```
[Processus A - Parent] - PID: 1234
    |
    └── [Processus A - Enfant] - PID: 5678
```

#### Code exemple de fork :

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

### <mark style="color:blue;">3. L'histoire complète avec ptrace</mark>

#### Scénario : On veut tracer le programme "client"

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

