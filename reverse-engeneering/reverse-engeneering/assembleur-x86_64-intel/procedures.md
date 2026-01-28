# Procédures

***

## <mark style="color:blue;">⚙️</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Procédures**</mark>

***

À mesure que notre code devient plus complexe, nous devons commencer à **refactoriser notre code** pour utiliser les instructions de manière plus efficace et rendre le code plus **facile à lire et à comprendre**.\
Une manière courante de faire cela est d’utiliser des **fonctions** et des **procédures**.

Alors que les **fonctions** nécessitent une procédure d’appel pour les invoquer et leur passer des arguments (ce que nous aborderons dans la section suivante),\
les **procédures** sont généralement **plus simples** et principalement utilisées pour **refactoriser le code**.

***

### <mark style="color:blue;">🧩</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Qu’est-ce qu’une procédure ?**</mark>

Une **procédure** (parfois appelée **sous-routine**) est généralement un **ensemble d'instructions** que l’on souhaite exécuter à des **points spécifiques** dans le programme.

👉 Au lieu de **réécrire le même code à plusieurs endroits**, on le définit sous une **étiquette (label)** de procédure,\
et on l’**appelle à chaque fois** qu’on veut l’utiliser.

> Ainsi, on n’a besoin d’**écrire le code qu’une seule fois**, mais on peut l’utiliser plusieurs fois.

De plus, on peut utiliser les procédures pour **diviser un code plus grand et plus complexe** en **blocs plus petits et plus simples**.

***

### <mark style="color:blue;">🔙 Revenons à notre code :</mark>

```asm
global  _start

section .data
    message db "Fibonacci Sequence:", 0x0a

section .text
_start:
    mov rax, 1        ; rax : numéro du syscall write
    mov rdi, 1        ; rdi : stdout
    mov rsi, message  ; rsi : pointeur vers la chaîne
    mov rdx, 20       ; rdx : longueur
    syscall           ; afficher le message

    xor rax, rax      ; initialiser rax à 0
    xor rbx, rbx      ; initialiser rbx à 0
    inc rbx           ; rbx = 1

loopFib:
    add rax, rbx
    xchg rax, rbx
    cmp rbx, 10
    js loopFib

    mov rax, 60
    mov rdi, 0
    syscall
```

On remarque que notre code fait plusieurs choses en **un seul gros bloc** :

* Affiche le message d’introduction
* Initialise les valeurs de Fibonacci à 0 et 1
* Calcule les nombres suivants avec une boucle
* Quitte le programme

La **boucle** est déjà définie sous un **label** (`loopFib`),mais les **trois autres parties** peuvent être **transformées en procédures**,pour **améliorer la lisibilité et l’efficacité du code**.

***

### <mark style="color:blue;">✍️</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Définir des procédures**</mark>

Première étape :\
On ajoute un **label au-dessus de chaque bloc** de code qu’on veut transformer en procédure :

```asm
global  _start

section .data
    message db "Fibonacci Sequence:", 0x0a

section .text
_start:

printMessage:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, 20
    syscall

initFib:
    xor rax, rax
    xor rbx, rbx
    inc rbx

loopFib:
    add rax, rbx
    xchg rax, rbx
    cmp rbx, 10
    js loopFib

Exit:
    mov rax, 60
    mov rdi, 0
    syscall
```

➡️ Notre code est déjà **plus lisible**,\
mais **pas encore plus efficace**, car on pourrait faire la même chose avec des **commentaires**.

***

### <mark style="color:blue;">📞</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**CALL / RET**</mark>

Quand on veut **exécuter une procédure**, on peut utiliser **`call`**,qui va **pousser (sauvegarder) le pointeur d’instruction `rip` sur la pile**,puis **sauter à la procédure** spécifiée.

Ensuite, la procédure se termine avec l’instruction **`ret`**,qui **retire l’adresse du sommet de la pile** pour la **recharger dans `rip`**→ le programme **reprend là où il s’était arrêté** avant d’appeler la procédure.

***

| Instruction | Description                                                   | Exemple             |
| ----------- | ------------------------------------------------------------- | ------------------- |
| `call`      | empile `rip` (instruction suivante) puis saute à la procédure | `call printMessage` |
| `ret`       | dépile l’adresse du sommet de la pile dans `rip`              | `ret`               |

***

### <mark style="color:blue;">🧠 Appliquer</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`call`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">dans le code</mark>

```asm
global  _start

section .data
    message db "Fibonacci Sequence:", 0x0a

section .text
_start:
    call printMessage   ; afficher l’intro
    call initFib        ; initialiser Fib
    call loopFib        ; calculer la suite
    call Exit           ; quitter le programme

printMessage:
    mov rax, 1
    mov rdi, 1
    mov rsi, message
    mov rdx, 20
    syscall
    ret

initFib:
    xor rax, rax
    xor rbx, rbx
    inc rbx
    ret

loopFib:
    add rax, rbx
    xchg rax, rbx
    cmp rbx, 10
    js loopFib
    ret

Exit:
    mov rax, 60
    mov rdi, 0
    syscall
```

***

### <mark style="color:red;">✅ Résultat</mark>

Ce code **exécute exactement la même chose qu’avant**,mais :

* plus **propre**
* plus **modulaire**
* plus **facile à modifier**

Par exemple, si on veut modifier uniquement `printMessage`,on n’a **pas besoin de relire tout le fichier**.

> Remarque :\
> La procédure `Exit` ne contient **pas de `ret`**,car on **ne veut pas revenir** après un `exit`.

***

### <mark style="color:blue;">📌 Note importante</mark>

En assembleur, **l’exécution se fait ligne par ligne**.\
Si tu **n’utilises pas `ret`** dans une procédure, le code continue simplement avec la ligne suivante.

Exemple :\
Si `Exit` avait un `ret`, il retournerait à l’appelant → ici, ce serait `call Exit`, donc il sauterait à la ligne suivante (première ligne de `printMessage`) → ce qui n’aurait aucun sens.

***

### <mark style="color:blue;">📦</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`enter`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">et</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`leave`</mark>

Il existe aussi les instructions `enter` et `leave` pour :

* sauvegarder/restaurer `rbp` et `rsp`
* allouer une zone de pile pour une procédure

Mais on **ne les utilise pas dans ce module**.

***
