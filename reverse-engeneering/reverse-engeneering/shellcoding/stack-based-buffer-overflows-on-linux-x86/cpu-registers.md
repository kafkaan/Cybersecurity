# CPU Registers



## <mark style="color:red;">**Introduction aux Registres CPU**</mark>

Les registres sont les composants essentiels d'un CPU. Presque tous les registres offrent une petite quantité d'espace de stockage où les données peuvent être temporairement stockées. Cependant, certains d'entre eux ont une fonction particulière.

Ces registres sont divisés en **registres généraux**, **registres de contrôle** et **registres de segment**. Les registres les plus critiques dont nous avons besoin sont les **registres généraux**. Dans ceux-ci, il y a d'autres subdivisions en registres de données, registres de pointeurs et registres d'index.

***

### <mark style="color:blue;">Registres de Données</mark>

<table data-full-width="true"><thead><tr><th>Registre 32-bit</th><th>Registre 64-bit</th><th>Description</th></tr></thead><tbody><tr><td>EAX</td><td>RAX</td><td>Accumulateur utilisé pour les entrées/sorties et les opérations arithmétiques</td></tr><tr><td>EBX</td><td>RBX</td><td>Base utilisé dans l'adressage indexé</td></tr><tr><td>ECX</td><td>RCX</td><td>Compteur utilisé pour les instructions de rotation et le comptage des boucles</td></tr><tr><td>EDX</td><td>RDX</td><td>Données utilisé pour les E/S et dans les opérations arithmétiques pour les opérations de multiplication et division impliquant de grandes valeurs</td></tr></tbody></table>

***

### <mark style="color:blue;">Registres de Pointeurs</mark>

<table data-full-width="true"><thead><tr><th>Registre 32-bit</th><th>Registre 64-bit</th><th>Description</th></tr></thead><tbody><tr><td>EIP</td><td>RIP</td><td>Pointeur d'instruction stocke l'adresse de décalage de la prochaine instruction à exécuter</td></tr><tr><td>ESP</td><td>RSP</td><td>Pointeur de pile pointe vers le sommet de la pile</td></tr><tr><td>EBP</td><td>RBP</td><td>Pointeur de base également connu sous le nom de pointeur de base de pile ou pointeur de cadre qui pointe vers la base de la pile</td></tr></tbody></table>

***

### <mark style="color:blue;">Cadres de Pile (Stack Frames)</mark>

Puisque la pile commence avec une adresse haute et grandit vers les adresses mémoire basses lorsque des valeurs sont ajoutées, le **Pointeur de Base** pointe vers le début (base) de la pile contrairement au **Pointeur de Pile**, qui pointe vers le sommet de la pile.

Au fur et à mesure que la pile grandit, elle est logiquement divisée en régions appelées **Cadres de Pile**, qui allouent la mémoire requise dans la pile pour la fonction correspondante. Un cadre de pile définit un cadre de données avec le début (EBP) et la fin (ESP) qui est poussé sur la pile lorsqu'une fonction est appelée.

***

### <mark style="color:blue;">Analyse Détaillée du Code Assembleur - Fonction bowfunc</mark>

Puisque la mémoire de la pile est construite sur une structure de données **Last-In-First-Out (LIFO)**, la première étape consiste à stocker la position EBP précédente sur la pile, qui peut être restaurée après que la fonction soit terminée.

#### <mark style="color:green;">Code Assembleur Complet avec Commentaires Ligne par Ligne :</mark>

{% code fullWidth="true" %}
```nasm
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:     push   ebp      # PROLOGUE - Étape 1 : Sauvegarde l'ancien EBP sur la pile
                                        # Cette instruction pousse la valeur actuelle du registre EBP sur la pile
                                        # pour la préserver avant de créer un nouveau cadre de pile
                                        # ESP = ESP - 4, puis [ESP] = EBP

   0x0000054e <+1>:     mov    ebp,esp  # PROLOGUE - Étape 2 : Crée un nouveau cadre de pile
                                        # Copie la valeur du pointeur de pile (ESP) dans le pointeur de base (EBP)
                                        # Ceci établit la base du nouveau cadre de pile
                                        # EBP = ESP (maintenant EBP pointe vers le même endroit qu'ESP)

   0x00000550 <+3>:     push   ebx      # PROLOGUE - Étape 3 : Sauvegarde du registre EBX
                                        # Pousse le registre EBX sur la pile pour le préserver
                                        # ESP = ESP - 4, puis [ESP] = EBX
                                        # Ceci est fait pour éviter de corrompre la valeur dans EBX

   0x00000551 <+4>:     sub    esp,0x404 # PROLOGUE - Étape 4 : Alloue de l'espace pour les variables locales
                                         # Soustrait 0x404 (1028 en décimal) octets du pointeur de pile
                                         # ESP = ESP - 0x404
                                         # Ceci réserve 1028 octets sur la pile pour les variables locales de la fonction
                                         # Cette valeur importante (1028 octets) suggère un buffer de taille significative

   <...SNIP...>                        # Ici se trouvent les instructions principales de la fonction
                                        # (opérations sur les données, appels de fonctions, etc.)

   0x00000580 <+51>:    leave           # ÉPILOGUE - Étape 1 : Nettoie le cadre de pile
                                        # Cette instruction est équivalente à :
                                        # mov esp, ebp (restaure ESP à la base du cadre actuel)
                                        # pop ebp (restaure l'ancien EBP depuis la pile)
                                        # Elle défait tout ce qui a été fait dans le prologue

   0x00000581 <+52>:    ret             # ÉPILOGUE - Étape 2 : Retourne à la fonction appelante
                                        # Pop l'adresse de retour depuis la pile dans EIP
                                        # EIP = [ESP], puis ESP = ESP + 4
                                        # Le programme continue l'exécution à l'adresse de retour
```
{% endcode %}

#### <mark style="color:green;">Explication Détaillée du Prologue</mark>

Le **prologue** de la fonction comprend les quatre premières instructions :

1. **`push ebp`** : Sauvegarde l'ancien pointeur de base
2. **`mov ebp,esp`** : Établit un nouveau cadre de pile
3. **`push ebx`** : Sauvegarde le registre EBX (préservation)
4. **`sub esp,0x404`** : Réserve l'espace pour les variables locales

#### <mark style="color:green;">Explication Détaillée de l'Épilogue</mark>

L'**épilogue** de la fonction comprend les deux dernières instructions :

1. **`leave`** : Nettoie le cadre de pile et restaure l'ancien EBP
2. **`ret`** : Retourne le contrôle à la fonction appelante

***

### <mark style="color:blue;">Registres d'Index</mark>

<table data-full-width="true"><thead><tr><th>Registre 32-bit</th><th>Registre 64-bit</th><th>Description</th></tr></thead><tbody><tr><td>ESI</td><td>RSI</td><td>Index Source utilisé comme pointeur depuis une source pour les opérations de chaîne</td></tr><tr><td>EDI</td><td>RDI</td><td>Destination utilisé comme pointeur vers une destination pour les opérations de chaîne</td></tr></tbody></table>

***

### <mark style="color:blue;">Compilation 64-bit vs 32-bit</mark>

#### <mark style="color:green;">Compilation en Format 64-bit :</mark>

```bash
student@nix-bow:~$ gcc bow.c -o bow64 -fno-stack-protector -z execstack -m64
student@nix-bow:~$ file bow64 | tr "," "\n"

bow64: ELF 64-bit LSB shared object
 x86-64
 version 1 (SYSV)
 dynamically linked
 interpreter /lib64/ld-linux-x86-64.so.2
 for GNU/Linux 3.2.0
 BuildID[sha1]=9503477016e8604e808215b4babb250ed25a7b99
 not stripped
```

#### <mark style="color:$success;">Code Assembleur 64-bit avec Commentaires :</mark>

{% code fullWidth="true" %}
```nasm
student@nix-bow:~$ gdb -q bow64
(gdb) disas main

Dump of assembler code for function main:
   0x00000000000006bc <+0>:     push   rbp              # Sauvegarde l'ancien pointeur de base (64-bit)
                                                        # [RSP-8] = RBP, RSP = RSP - 8

   0x00000000000006bd <+1>:     mov    rbp,rsp          # Établit le nouveau cadre de pile
                                                        # RBP = RSP (base du nouveau cadre)

   0x00000000000006c0 <+4>:     sub    rsp,0x10         # Alloue 16 octets pour les variables locales
                                                        # RSP = RSP - 0x10 (alignement 16-byte en 64-bit)

   0x00000000000006c4 <+8>:     mov    DWORD PTR [rbp-0x4],edi    # Stocke le premier argument (argc) sur la pile
                                                                  # [RBP-4] = EDI (nombre d'arguments)

   0x00000000000006c7 <+11>:    mov    QWORD PTR [rbp-0x10],rsi   # Stocke le second argument (argv) sur la pile
                                                                  # [RBP-16] = RSI (tableau des arguments)

   0x00000000000006cb <+15>:    mov    rax,QWORD PTR [rbp-0x10]   # Charge argv dans RAX
                                                                  # RAX = [RBP-16] (pointeur vers argv)

   0x00000000000006cf <+19>:    add    rax,0x8                    # Ajoute 8 à RAX pour pointer vers argv[1]
                                                                  # RAX = RAX + 8 (saut vers le 2ème élément)

   0x00000000000006d3 <+23>:    mov    rax,QWORD PTR [rax]        # Charge la valeur pointée par RAX
                                                                  # RAX = [RAX] (contenu de argv[1])

   0x00000000000006d6 <+26>:    mov    rdi,rax                    # Copie l'argument dans RDI pour l'appel de fonction
                                                                  # RDI = RAX (premier paramètre pour bowfunc)

   0x00000000000006d9 <+29>:    call   0x68a <bowfunc>           # Appelle la fonction bowfunc
                                                                  # Pousse l'adresse de retour sur la pile
                                                                  # RIP = 0x68a (saut vers bowfunc)

   0x00000000000006de <+34>:    lea    rdi,[rip+0x9f]            # Charge l'adresse effective d'une chaîne
                                                                  # RDI = RIP + 0x9f (adresse de la chaîne)

   0x00000000000006e5 <+41>:    call   0x560 <puts@plt>          # Appelle la fonction puts pour l'affichage
                                                                  # Affiche la chaîne pointée par RDI

   0x00000000000006ea <+46>:    mov    eax,0x1                   # Définit la valeur de retour à 1
                                                                  # EAX = 1 (code de retour du programme)

   0x00000000000006ef <+51>:    leave                            # Nettoie le cadre de pile
                                                                  # RSP = RBP, puis pop RBP

   0x00000000000006f0 <+52>:    ret                              # Retourne au système d'exploitation
                                                                  # RIP = [RSP], RSP = RSP + 8
```
{% endcode %}

***

### <mark style="color:blue;">L'instruction CALL - Analyse Détaillée</mark>

L'instruction **call** est utilisée pour appeler une fonction et effectue deux opérations critiques :

1. **Elle pousse l'adresse de retour sur la pile** pour que l'exécution du programme puisse continuer après que la fonction ait accompli son objectif avec succès
2. **Elle change le pointeur d'instruction (EIP)** vers la destination de l'appel et commence l'exécution là-bas

#### <mark style="color:green;">Exemple d'Analyse GDB - Syntaxe Intel :</mark>

{% code fullWidth="true" %}
```nasm
student@nix-bow:~$ gdb ./bow32 -q
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>:     lea    ecx,[esp+0x4]           # Calcule l'adresse effective : ECX = ESP + 4
                                                       # Charge l'adresse du premier argument dans ECX

   0x00000586 <+4>:     and    esp,0xfffffff0          # Aligne ESP sur une frontière 16-byte
                                                       # ESP = ESP & 0xfffffff0 (alignement mémoire)

   0x00000589 <+7>:     push   DWORD PTR [ecx-0x4]     # Pousse la valeur à [ECX-4] sur la pile
                                                       # [ESP-4] = [ECX-4], ESP = ESP - 4

   0x0000058c <+10>:    push   ebp                     # Sauvegarde l'ancien pointeur de base
                                                       # [ESP-4] = EBP, ESP = ESP - 4

   0x0000058d <+11>:    mov    ebp,esp                 # Établit le nouveau cadre de pile
                                                       # EBP = ESP

   0x0000058f <+13>:    push   ebx                     # Sauvegarde le registre EBX
                                                       # [ESP-4] = EBX, ESP = ESP - 4

   0x00000590 <+14>:    push   ecx                     # Sauvegarde le registre ECX
                                                       # [ESP-4] = ECX, ESP = ESP - 4

   0x00000591 <+15>:    call   0x450 <__x86.get_pc_thunk.bx>  # Appel à une fonction thunk
                                                               # Pousse l'adresse de retour, RIP = 0x450

   0x00000596 <+20>:    add    ebx,0x1a3e              # Ajoute un offset à EBX
                                                       # EBX = EBX + 0x1a3e (calcul d'adresse)

   0x0000059c <+26>:    mov    eax,ecx                 # Copie ECX dans EAX
                                                       # EAX = ECX

   0x0000059e <+28>:    mov    eax,DWORD PTR [eax+0x4] # Charge la valeur à [EAX+4]
                                                       # EAX = [EAX+4] (accès aux arguments)

   0x000005a1 <+31>:    add    eax,0x4                 # Ajoute 4 à EAX
                                                       # EAX = EAX + 4 (passage au prochain argument)

   0x000005a4 <+34>:    mov    eax,DWORD PTR [eax]     # Déréférence le pointeur dans EAX
                                                       # EAX = [EAX] (obtient la valeur finale)

   0x000005a6 <+36>:    sub    esp,0xc                 # Alloue 12 octets sur la pile
                                                       # ESP = ESP - 0xc (espace pour les paramètres)

   0x000005a9 <+39>:    push   eax                     # Pousse l'argument sur la pile
                                                       # [ESP-4] = EAX, ESP = ESP - 4

   0x000005aa <+40>:    call   0x54d <bowfunc>         # *** APPEL DE FONCTION CRITIQUE ***
                                                       # 1. Pousse l'adresse de retour (0x000005af) sur la pile
                                                       # 2. [ESP-4] = 0x000005af, ESP = ESP - 4  
                                                       # 3. EIP = 0x54d (saut vers bowfunc)
                                                       # C'est ici que le débordement peut se produire !
```
{% endcode %}

***

### <mark style="color:blue;">Endianness (Ordre des Octets)</mark>

Pendant les opérations de chargement et de sauvegarde dans les registres et mémoires, les octets sont lus dans un ordre différent. Cet ordre d'octets est appelé **endianness**. L'endianness se distingue entre le format **little-endian** et le format **big-endian**.

**Big-endian** et **little-endian** concernent l'ordre de valence. En **big-endian**, les chiffres avec la plus haute valence sont au début. En **little-endian**, les chiffres avec la plus faible valence sont au début.

#### <mark style="color:green;">Exemple Pratique d'Endianness :</mark>

**Adresse :** `0xffff0000`\
**Mot :** `\xAA\xBB\xCC\xDD`

| Adresse Mémoire   | 0xffff0000 | 0xffff0001 | 0xffff0002 | 0xffff0003 |
| ----------------- | ---------- | ---------- | ---------- | ---------- |
| **Big-Endian**    | AA         | BB         | CC         | DD         |
| **Little-Endian** | DD         | CC         | BB         | AA         |

#### <mark style="color:green;">Importance pour l'Exploitation :</mark>

Ceci est **très important** pour nous permettre d'entrer notre code dans le bon ordre plus tard lorsque nous devons dire au CPU vers quelle adresse il doit pointer. En architecture x86, le format **little-endian** est utilisé, ce qui signifie que :

* L'octet le moins significatif est stocké en premier
* Les adresses doivent être écrites à l'envers dans nos exploits
* Une adresse comme `0x08040000` sera stockée en mémoire comme `\x00\x40\x08\x08`

***

### <mark style="color:blue;">Points Clés à Retenir</mark>

1. **Registres critiques** : EAX, EBX, ECX, EDX pour les données ; EIP, ESP, EBP pour les pointeurs
2. **Structure LIFO** : La pile fonctionne en Last-In-First-Out
3. **Prologue et Épilogue** : Gèrent la création et destruction des cadres de pile
4. **Instruction CALL** : Point d'entrée critique pour les exploitations
5. **Endianness** : Format little-endian en x86 - les adresses sont inversées
6. **Différences 32/64-bit** : Taille des registres et instructions différentes
