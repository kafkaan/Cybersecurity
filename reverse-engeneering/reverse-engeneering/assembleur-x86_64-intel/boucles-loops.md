# Boucles (Loops)

Maintenant que nous avons couvert les instructions de base, nous pouvons commencer à apprendre les **instructions de contrôle de programme**.<br>

* Comme nous le savons déjà, le code en assembleur est **exécuté ligne par ligne**, donc il regarde toujours **la ligne suivante** pour les instructions à traiter.

Cependant, comme on peut s'y attendre, **la plupart des programmes ne suivent pas une simple suite d'étapes séquentielles**, mais ont souvent une structure beaucoup plus complexe.

{% hint style="danger" %}
C’est là qu’interviennent les **instructions de contrôle**. Ces instructions permettent de **changer le flux d’exécution** du programme et de l’envoyer vers une autre ligne.
{% endhint %}

***

#### <mark style="color:green;">🧭 Types d'instructions de contrôle</mark>

* **Boucles (Loops)**
* **Branchements (Branching)**
* **Appels de fonctions (Function Calls)**

***

### <mark style="color:red;">🔄 Structure de boucle</mark>

Commençons par discuter des **boucles (loops)**.\
<mark style="color:orange;">Une</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**boucle en assembleur**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">est un ensemble d’instructions qui se répète</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**autant de fois que la valeur contenue dans le registre**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`rcx`**</mark><mark style="color:orange;">.</mark>

Prenons l’exemple suivant :

**📜 Code NASM :**

```asm
exampleLoop:
    instruction 1
    instruction 2
    instruction 3
    instruction 4
    instruction 5
    loop exampleLoop
```

Quand le code assembleur atteint `exampleLoop`, il va commencer à exécuter les instructions qui suivent.\
Il faut **initialiser `rcx` avec le nombre d’itérations** désirées.\
Chaque fois que l’instruction `loop` est exécutée, **`rcx` est décrémenté de 1 (`dec rcx`)** et si ce n’est pas encore 0, le programme saute de nouveau à l’étiquette `exampleLoop`.

***

#### <mark style="color:green;">📘 Table des instructions</mark>

<table data-full-width="true"><thead><tr><th>Instruction</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td><code>mov rcx, x</code></td><td>Définit le compteur de boucle <code>rcx</code> à <code>x</code></td><td><code>mov rcx, 3</code></td></tr><tr><td><code>loop</code></td><td>Retourne au début de la boucle jusqu’à ce que <code>rcx == 0</code></td><td><code>loop exampleLoop</code></td></tr></tbody></table>

***

### <mark style="color:red;">🧪 Exemple : Boucle Fibonacci (</mark><mark style="color:red;">`loopFib`</mark><mark style="color:red;">)</mark>

Pour illustrer cela, reprenons notre code `fib.s` :

**📜 Code NASM :**

```asm
global  _start

section .text
_start:
    xor rax, rax
    xor rbx, rbx
    inc rbx
    add rax, rbx
```

Chaque nombre Fibonacci courant est la **somme des deux nombres précédents**.\
On peut **automatiser cela avec une boucle**.

On suppose :

* `rax` contient le **nombre courant Fn**
* `rbx` contient le **suivant Fn+1**

***

#### <mark style="color:green;">🧮 Étapes de la boucle Fibonacci</mark>

1. Calculer le prochain nombre : `Fn + Fn+1`
2. Déplacer `Fn+1` dans `Fn`
3. Déplacer le résultat dans `Fn+1`
4. Boucler

***

🧠 Remarque :\
On a le résultat dans `rax`, l'ancien dans `rbx`, donc pour **échanger les deux**, on utilise :

```asm
xchg rax, rbx
```

Avant d’entrer dans une boucle, on initialise `rcx` :

```asm
mov rcx, 10
```

***

#### <mark style="color:green;">📜 Code complet :</mark>

{% code fullWidth="true" %}
```asm
global  _start

section .text
_start:
    xor rax, rax    ; initialiser rax à 0
    xor rbx, rbx    ; initialiser rbx à 0
    inc rbx         ; incrémenter rbx à 1
    mov rcx, 10     ; compteur de boucle à 10
loopFib:
    add rax, rbx    ; obtenir le prochain nombre
    xchg rax, rbx   ; échanger les valeurs
    loop loopFib    ; répéter jusqu’à rcx == 0
```
{% endcode %}

***

#### <mark style="color:green;">🧪 Exécution avec GDB</mark>

```bash
gdb
$ ./assembler.sh fib.s -g
gef➤  b loopFib
Breakpoint 1 at 0x40100e
gef➤  r
```

```asm
────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x1
$rcx   : 0xa
```

***

➡️ Appuie sur `c` pour continuer une itération :

```asm
────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x1
$rcx   : 0x9
```

Encore une fois :

```asm
────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x2
$rcx   : 0x8
```

Encore 3 itérations :

```asm
────────────────────────────────────────────────────────────── registers ────
$rax   : 0x2
$rbx   : 0x3
$rcx   : 0x7
────────────────────────────────────────────────────────────── registers ────
$rax   : 0x3
$rbx   : 0x5
$rcx   : 0x6
────────────────────────────────────────────────────────────── registers ────
$rax   : 0x5
$rbx   : 0x8
$rcx   : 0x5
```

***

On voit bien que le programme calcule la **suite de Fibonacci** :

```asm
0, 1, 1, 2, 3, 5, 8, ...
```

À la dernière itération, on obtient `rbx = 0x37`, soit 55 en décimal :

```asm
────────────────────────────────────────────────────────────── registers ────
$rax   : 0x22
$rbx   : 0x37
$rcx   : 0x1
```

Vérification :

```asm
gef➤  p/d $rbx
$3 = 55
```

***

✅ On a bien utilisé une **boucle avec `loop`** pour automatiser le calcul de la suite de Fibonacci.

***
