# Conditional Branching

***

## <mark style="color:red;">🔀</mark> <mark style="color:red;"></mark><mark style="color:red;">**Branchement conditionnel (Conditional Branching)**</mark>

Contrairement aux **instructions de branchement inconditionnel**, les instructions de <mark style="color:orange;">**branchement conditionnel**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">ne sont exécutées</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**que lorsqu’une condition spécifique est remplie**</mark>, basée sur les opérandes _**Destination**_**&#x20;et&#x20;**_**Source**_**.**

Une instruction de saut conditionnel prend plusieurs formes sous le nom de `Jcc`, où `cc` représente le **code de condition (Condition Code)**.

***

#### <mark style="color:green;">📘 Tableau des conditions</mark>

<table data-full-width="true"><thead><tr><th>Instruction</th><th>Condition</th><th>Description</th></tr></thead><tbody><tr><td><code>jz</code></td><td>D = 0</td><td>Destination est égale à zéro</td></tr><tr><td><code>jnz</code></td><td>D ≠ 0</td><td>Destination n’est pas égale à zéro</td></tr><tr><td><code>js</code></td><td>D &#x3C; 0</td><td>Destination est négative</td></tr><tr><td><code>jns</code></td><td>D ≥ 0</td><td>Destination n’est pas négative (0 ou positif)</td></tr><tr><td><code>jg</code></td><td>D > S</td><td>Destination supérieure à Source</td></tr><tr><td><code>jge</code></td><td>D ≥ S</td><td>Destination supérieure ou égale à Source</td></tr><tr><td><code>jl</code></td><td>D &#x3C; S</td><td>Destination inférieure à Source</td></tr><tr><td><code>jle</code></td><td>D ≤ S</td><td>Destination inférieure ou égale à Source</td></tr></tbody></table>

***

{% hint style="warning" %}
Il existe beaucoup d’autres conditions similaires.\
Pour la liste complète, voir le **manuel Intel x86\_64**, section **Jcc – Jump if Condition is Met**.
{% endhint %}

<mark style="color:green;">**Les instructions conditionnelles ne se limitent pas aux**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`jmp`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**:**</mark>

* `CMOVcc` : **mov conditionnel**
* `SETcc` : **assignation conditionnelle (0 ou 1)**

***

#### <mark style="color:green;">📌 Exemples</mark>

* `cmovz rax, rbx` → fait `mov` seulement si **ZF = 1** (i.e. égal à zéro)
* `cmovl rax, rbx` → fait `mov` si **résultat < 0**
* `setz al` → met `al = 1` si la condition est remplie, sinon `al = 0`

***

### <mark style="color:red;">🏁 Registre RFLAGS</mark>

Les conditions sont vérifiées à partir des <mark style="color:orange;">**flags du registre RFLAGS**</mark><mark style="color:orange;">.</mark>

Le registre `RFLAGS` est un **registre 64 bits**, mais il **ne stocke pas des valeurs**, il stocke **des indicateurs (flags)**.

Les **instructions arithmétiques** mettent à jour ces flags.\
Par exemple :

* `dec` qui donne 0 → met `ZF = 1`
* `sub` qui donne un résultat négatif → met `SF = 1`
* `div` qui dépasse → met `CF = 1`

***

#### <mark style="color:green;">📘 Extrait des flags importants dans RFLAGS</mark>

<table data-full-width="true"><thead><tr><th>Bit</th><th>Nom</th><th>Signification</th></tr></thead><tbody><tr><td>0</td><td>CF</td><td>Carry Flag (dépassement non signé)</td></tr><tr><td>2</td><td>PF</td><td>Parity Flag (nombre pair/impair de bits)</td></tr><tr><td>4</td><td>AF</td><td>Auxiliary Flag</td></tr><tr><td>6</td><td>ZF</td><td>Zero Flag (résultat == 0)</td></tr><tr><td>7</td><td>SF</td><td>Sign Flag (résultat négatif)</td></tr><tr><td>11</td><td>OF</td><td>Overflow Flag (dépassement signé)</td></tr></tbody></table>

Les noms `ZR` (ZF=1) et `NZ` (ZF=0) sont utilisés pour représenter **Zéro** et **Non-Zéro**.

{% hint style="info" %}
***

Le registre **RFLAGS** (ou EFLAGS dans les architectures 32 bits) est un registre spécial dans les processeurs x86/x64 qui contient des bits appelés **flags**. Ces bits sont mis à jour par le processeur après certaines instructions (comme `ADD`, `SUB`, `CMP`, etc.) pour indiquer des informations sur le résultat de l'opération. Les flags influencent les sauts conditionnels (ex. : `JZ`, `JNZ`) et sont souvent analysés en reverse engineering pour comprendre la logique d'un programme.

Les flags que tu as mentionnés sont :

* **CF** : Carry Flag (Drapeau de retenue)
* **PF** : Parity Flag (Drapeau de parité)
* **AF** : Auxiliary Carry Flag (Drapeau de retenue auxiliaire)
* **ZF** : Zero Flag (Drapeau de zéro)
* **SF** : Sign Flag (Drapeau de signe)
* **OF** : Overflow Flag (Drapeau de dépassement)

***

<mark style="color:green;">**1. CF (Carry Flag) - Drapeau de retenue**</mark>

**Rôle** : Le **Carry Flag** est activé (mis à 1) quand une opération arithmétique produit une **retenue** (carry) ou un **emprunt** (borrow) dans les calculs impliquant des nombres non signés. Il est souvent utilisé pour les additions ou soustractions.

* **Quand est-il modifié ?** Par des instructions comme `ADD`, `SUB`, `CMP`.
* **Utilité** : Détecter si un résultat dépasse la taille du registre (ex. : additionner deux nombres trop grands pour un registre 8 bits).

**Exemple simple** : Imaginons qu'on additionne deux nombres 8 bits dans un registre (par exemple, `AL`) :

```asm
MOV AL, 0xFF  ; AL = 255 (maximum pour 8 bits)
ADD AL, 1     ; AL = AL + 1
```

* **Résultat** : `255 + 1 = 256`, mais un registre 8 bits ne peut contenir que 255 max. Donc, `AL` revient à `0`, et le **CF** est mis à **1** pour indiquer qu'il y a une retenue.
* **Vérification** : Une instruction comme `JC` (Jump if Carry) peut être utilisée pour sauter si `CF = 1`.

**Analogie** : C'est comme si tu comptes sur tes doigts (0 à 9). Si tu ajoutes 9 + 1, tu dépasses 9, donc tu remets à 0 et tu "retiens" 1 (le carry).

***

<mark style="color:green;">**2. PF (Parity Flag) - Drapeau de parité**</mark>

**Rôle** : Le **Parity Flag** indique si le nombre de bits à **1** dans le résultat d'une opération est **pair** ou **impair**. Il est mis à **1** si le nombre de bits à 1 est pair, sinon à **0**.

* **Quand est-il modifié ?** Par des instructions comme `ADD`, `SUB`, `AND`, `OR`.
* **Utilité** : Principalement utilisé dans les anciens systèmes pour vérifier l'intégrité des données (par exemple, dans les communications série).

**Exemple simple** :

```asm
MOV AL, 0x05  ; AL = 00000101 en binaire (3 bits à 1)
SUB AL, 0x01  ; AL = 00000100 (4 en binaire, 2 bits à 1)
```

* **Résultat** : Le résultat (`0x04`) a 2 bits à 1 (pair), donc **PF = 1**.
* Si on fait :

```asm
MOV AL, 0x07  ; AL = 00000111 (3 bits à 1)
```

* **Résultat** : 3 bits à 1 (impair), donc **PF = 0**.

**Analogie** : Imagine que tu comptes les billes dans un sac. Si tu as un nombre pair de billes, le drapeau de parité est "activé". Sinon, il est "désactivé".

***

<mark style="color:green;">**3. AF (Auxiliary Carry Flag) - Drapeau de retenue auxiliaire**</mark>

**Rôle** : Le **Auxiliary Carry Flag** est activé (mis à 1) quand il y a une retenue ou un emprunt entre les **4 bits inférieurs** (nibble inférieur) et les 4 bits supérieurs d’un registre 8 bits. Il est utilisé principalement pour les calculs en **BCD** (Binary-Coded Decimal, décimal codé en binaire).

* **Quand est-il modifié ?** Par des instructions comme `ADD`, `SUB`.
* **Utilité** : Rarement utilisé en programmation moderne, mais important pour les systèmes anciens qui manipulent des nombres décimaux codés.

**Exemple simple** :

```asm
MOV AL, 0x09  ; AL = 9 en BCD
ADD AL, 0x01  ; AL = 9 + 1 = 10
```

* **Résultat** : En BCD, 9 + 1 donne `0x10` (10 en décimal), mais dans les 4 bits inférieurs, on passe de `1001` (9) à `0000` avec une retenue dans les 4 bits supérieurs. Donc, **AF = 1**.
* Une instruction comme `DAA` (Decimal Adjust after Addition) utilise **AF** pour ajuster le résultat en BCD.

**Analogie** : Imagine que tu fais une addition sur une calculatrice à 4 chiffres. Si tu dépasses 9 dans un chiffre, tu portes une retenue au chiffre suivant. **AF** indique cette retenue entre les groupes de 4 bits.

***

<mark style="color:green;">**4. ZF (Zero Flag) - Drapeau de zéro**</mark>

**Rôle** : Le **Zero Flag** est mis à **1** si le résultat d’une opération est **zéro**, sinon à **0**.

* **Quand est-il modifié ?** Par des instructions comme `ADD`, `SUB`, `CMP`, `AND`.
* **Utilité** : Très courant pour tester si deux valeurs sont égales (ex. : avec `CMP`) ou si un résultat est nul.

**Exemple simple** :

```asm
MOV EAX, 5
SUB EAX, 5   ; EAX = 5 - 5 = 0
```

* **Résultat** : Le résultat est `0`, donc **ZF = 1**.
* Une instruction comme `JZ` (Jump if Zero) peut sauter si **ZF = 1**.

**Exemple avec CMP** :

```asm
MOV EAX, 10
MOV EBX, 10
CMP EAX, EBX  ; Compare EAX et EBX (effectue EAX - EBX sans stocker)
```

* **Résultat** : `10 - 10 = 0`, donc **ZF = 1**, ce qui indique que les deux valeurs sont égales.

**Analogie** : C’est comme vérifier si ton portefeuille est vide après avoir dépensé tout ton argent. Si c’est vide (zéro), **ZF** est activé.

***

<mark style="color:green;">**5. SF (Sign Flag) - Drapeau de signe**</mark>

**Rôle** : Le **Sign Flag** reflète le bit de signe du résultat (le bit le plus significatif). Il est mis à **1** si le résultat est **négatif** (bit de signe = 1) et à **0** si le résultat est **positif** ou **zéro** (bit de signe = 0).

* **Quand est-il modifié ?** Par des instructions comme `ADD`, `SUB`, `MUL`.
* **Utilité** : Utilisé pour les opérations sur des nombres signés (entiers avec signe).

**Exemple simple** :

```asm
MOV AL, 0x80  ; AL = 10000000 en binaire (-128 en signé, 8 bits)
```

* **Résultat** : Le bit le plus significatif est `1`, donc **SF = 1** (indique un nombre négatif).

**Autre exemple** :

```asm
MOV EAX, -5
ADD EAX, 2    ; EAX = -5 + 2 = -3
```

* **Résultat** : Le résultat est négatif (`-3`), donc **SF = 1**.

**Analogie** : C’est comme regarder le panneau « + » ou « - » sur un thermomètre. Si la température est négative, **SF** est activé.

***

<mark style="color:green;">**6. OF (Overflow Flag) - Drapeau de dépassement**</mark>

**Rôle** : Le **Overflow Flag** est activé (mis à 1) quand une opération sur des nombres **signés** produit un résultat incorrect à cause d’un **débordement** (overflow). Cela se produit quand le résultat dépasse les limites des nombres signés dans le registre.

* **Quand est-il modifié ?** Par des instructions comme `ADD`, `SUB`.
* **Utilité** : Détecter des erreurs dans les calculs avec des nombres signés.

**Exemple simple** : Imaginons un registre 8 bits (plage pour les nombres signés : -128 à +127) :

```asm
MOV AL, 0x7F  ; AL = 127 (maximum positif en 8 bits signé)
ADD AL, 1     ; AL = 127 + 1
```

* **Résultat** : `127 + 1 = 128`, mais en 8 bits signé, cela donne `-128` (car `0x80` est `-128` en signé). Le résultat est incorrect, donc **OF = 1**.
* Une instruction comme `JO` (Jump if Overflow) peut sauter si **OF = 1**.

**Analogie** : Imagine que tu remplis un verre d’eau (la capacité du verre = 127 ml). Si tu ajoutes 1 ml de plus, le verre déborde, et **OF** signale ce débordement.

***

<mark style="color:green;">**Exemple complet : Analyse d’un programme avec les flags**</mark>

Voici un petit programme en assembleur pour illustrer comment les flags fonctionnent ensemble :

```asm
MOV EAX, 10
MOV EBX, 15
SUB EAX, EBX  ; EAX = 10 - 15 = -5
```

Après l’instruction `SUB`, les flags sont mis à jour :

* **CF = 1** : Il y a un emprunt (10 < 15, donc un borrow).
* **PF** : Dépend du nombre de bits à 1 dans `-5` (`0xFB` = `11111011`, 7 bits à 1, donc **PF = 0**).
* **AF** : Dépend des 4 bits inférieurs (pas de retenue ici, donc **AF = 0**).
* **ZF = 0** : Le résultat n’est pas zéro (`-5`).
* **SF = 1** : Le résultat est négatif (`-5`).
* **OF = 0** : Pas de débordement, car `-5` est dans la plage des nombres signés.

**Vérification** : Si le programme utilise `JS` (Jump if Sign), il sautera car **SF = 1**.

***

***
{% endhint %}

***

### <mark style="color:blue;">🧪 Exemple :</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`jnz loopFib`</mark>

L’instruction `loop` vue précédemment est **équivalente à** :

```nasm
dec rcx
jnz loopFib
```

Mais `loop` est juste une optimisation de syntaxe.

***

#### <mark style="color:green;">📜 Nouveau code avec</mark> <mark style="color:green;"></mark><mark style="color:green;">`jnz`</mark>

```nasm
global  _start

section .text
_start:
    xor rax, rax    ; initialise rax à 0
    xor rbx, rbx    ; initialise rbx à 0
    inc rbx         ; incrémente rbx à 1
    mov rcx, 10

loopFib:
    add rax, rbx    ; calcul du nombre suivant
    xchg rax, rbx   ; échange les valeurs
    dec rcx         ; décrémente rcx
    jnz loopFib     ; saute si rcx ≠ 0
```

***

#### <mark style="color:green;">🧪 Exécution GDB :</mark>

```bash
$ ./assembler.sh fib.s -g
gef➤  b loopFib
gef➤  r
```

{% code fullWidth="true" %}
```gdb
──────────────────────────────────────────────────── registers ────
$rax   : 0x0
$rbx   : 0x1
$rcx   : 0xa
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]

$rax   : 0x1
$rbx   : 0x1
$rcx   : 0x9

$rax   : 0x1
$rbx   : 0x2
$rcx   : 0x8
```
{% endcode %}

***

📌 Le programme calcule toujours la **suite de Fibonacci** correctement.

À chaque itération :

* `rcx` est décrémenté
* `ZF` n’est pas activé tant que `rcx ≠ 0`

Quand `rcx = 0`, alors `ZF = 1` → `jnz` ne saute plus → sortie de boucle.

***

### <mark style="color:red;">🧠 Instruction</mark> <mark style="color:red;"></mark><mark style="color:red;">`cmp`</mark>

On peut aussi utiliser des sauts conditionnels **après un test personnalisé**.

Exemple : on veut **arrêter l’exécution quand le Fibonacci dépasse 10**.

***

#### <mark style="color:green;">🎯</mark> <mark style="color:green;"></mark><mark style="color:green;">`cmp`</mark> <mark style="color:green;"></mark><mark style="color:green;">= compare (ne modifie pas les registres)</mark>

```nasm
cmp rbx, 10    ; fait rbx - 10 → met les flags
js  loopFib    ; saute si résultat < 0
```

***

#### <mark style="color:green;">📜 Nouveau code avec</mark> <mark style="color:green;"></mark><mark style="color:green;">`cmp`</mark> <mark style="color:green;"></mark><mark style="color:green;">et</mark> <mark style="color:green;"></mark><mark style="color:green;">`js`</mark>

```nasm
global  _start

section .text
_start:
    xor rax, rax    ; initialise rax à 0
    xor rbx, rbx    ; initialise rbx à 0
    inc rbx         ; rbx = 1

loopFib:
    add rax, rbx    ; prochain nombre
    xchg rax, rbx   ; échange
    cmp rbx, 10     ; compare avec 10
    js loopFib      ; saute si rbx < 10
```

🔍 On a supprimé `mov rcx, 10`, car la boucle dépend maintenant de la valeur de `rbx`.

***

#### <mark style="color:green;">🧪 Exécution GDB</mark>

```bash
$ ./assembler.sh fib.s -g
gef➤  b loopFib
gef➤  r
```

```gdb
──────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x1
$eflags: [zero CARRY parity ADJUST SIGN ...]
→   js     0x401009 <loopFib>   TAKEN [Reason: S]
```

➡️ On voit que le **flag S (sign)** est activé → saut pris

***

#### <mark style="color:green;">🧪 Jusqu’à rbx > 10</mark>

On peut utiliser **breakpoint conditionnel** pour arrêter quand `rbx > 10`.

```gdb
gef➤  del 1
gef➤  disas loopFib
→ 0x401012 : js 0x401009

gef➤  b *loopFib+9 if $rbx > 10
gef➤  c
```

```gdb
$rax   : 0x8
$rbx   : 0xd
$eflags: [zero carry PARITY adjust sign ...]
→ js     0x401009   NOT taken [Reason: !(S)]
```

✅ Comme `rbx = 13`, alors `rbx - 10 = 3`, donc le résultat est positif → `SIGN flag` désactivé → saut non pris.

***

### <mark style="color:red;">✅ Résumé – Trois techniques de boucle</mark>

| Méthode     | Code                                      | Conditions                   |
| ----------- | ----------------------------------------- | ---------------------------- |
| `loop rcx`  | `mov rcx, 10` + `loop loopFib`            | boucle 10 fois               |
| `dec + jnz` | `mov rcx, 10` + `dec rcx` + `jnz loopFib` | même effet, plus contrôlable |
| `cmp + js`  | `cmp rbx, 10` + `js loopFib`              | saute tant que `rbx < 10`    |

***

<mark style="color:green;">🧠</mark> <mark style="color:green;"></mark><mark style="color:green;">**Note**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>\
`je` = `jz` (ZF=1)\
`jne` = `jnz` (ZF=0)\
`jge` = `jnl`\
→ Ce sont **des alias**, utilisés selon le style ou la convention du langage.

***
