# ARM

### <mark style="color:blue;">Introduction</mark>

L'architecture ARM (Advanced RISC Machines) est un type de processeur largement répandu dans les composants embarqués tels que les téléphones, tablettes et routeurs.

**Évolution des versions :**

* ARMv3 à ARMv7 : architectures 32 bits
* ARMv8 et plus : architectures 64 bits
* **Focus du cours :** ARMv6 (32 bits) - présente sur le Raspberry Pi

***

### <mark style="color:blue;">1. Les Modes d'Exécution</mark>

Il y a _9 modes_ dans lequel un CPU ARM peut s’exécuter :

* _le mode user_ : un mode non-privilégié dans lequel la plupart des programmes s’exécutent. Il ne sera question que de ce mode dans le reste de l’article ;
* _le mode FIQ_ : un mode privilégié dans lequel le processeur entre lorsqu’il accepte une interruption FIQ (interruption à priorité élevée) ;
* _le mode IRQ_ : un mode privilégié dans lequel le processeur entre lorsqu’il accepte une interruption IRQ (interruption à priorité normale) ;
* _le mode Supervisor_ : un mode protégé pour le système d’exploitation ;
* _le mode Abort_ : un mode privilégié dans lequel le processeur entre lorsqu’une exception arrive ;
* _le mode Undefined_ : un mode privilégié dans lequel le processeur entre lorsqu’une instruction inconnue est exécutée ;
* _le mode System_ : le mode dans lequel est exécuté le système d’exploitation ;
* _le mode Monitor_ : ce mode a été introduit pour supporter l’extension TrustZones ;
* _le mode Hypervisor_ : ce mode est utilisé pour ce qui concerne la virtualisation.

***

### <mark style="color:blue;">2. Les Registres</mark>

L'architecture ARMv6 dispose de **16 registres 32 bits** en mode utilisateur :

#### Registres Généraux

* **r0 à r10** : Registres généraux pour toute opération

#### Registres Spécialisés

* **r11 (fp)** : Frame Pointer - début du contexte de fonction (équivalent d'ebp sur x86)
* **r12 (ip)** : Intraprocedure Register - stockage temporaire entre fonctions
* **r13 (sp)** : Stack Pointer - sommet de la pile (équivalent d'esp sur x86)
* **r14 (lr)** : Link Register - adresse de retour lors d'appels de fonction
* **r15 (pc)** : Program Counter - adresse de la prochaine instruction
* **cpsr** : Current Program Status Register - état du processeur et mode d'exécution

{% hint style="success" %}
Le CPSR est un registre de 32 bits. Il contient plusieurs **zones importantes** :

1. **Flags de condition (bits 31 à 28)**
   * **N (Negative)** : mis à 1 si le résultat de la dernière opération est négatif
   * **Z (Zero)** : mis à 1 si le résultat est 0
   * **C (Carry)** : mis à 1 si la dernière opération a généré un retenue (overflow non signé)
   * **V (Overflow)** : mis à 1 si la dernière opération a généré un dépassement (overflow signé)
2. **Mode du processeur (bits 4 à 0)**
   * Indique si le CPU est en **User mode, FIQ, IRQ, Supervisor, etc.**
   * Exemple : 0b10000 → User mode
3. **Interrupt Disable Bits**
   * Masque des interruptions IRQ ou FIQ
   * Permet de désactiver temporairement certaines interruptions
4. **Autres bits**
   * Divers bits de contrôle et statut du processeur selon la version ARM.
{% endhint %}

{% hint style="info" %}
Il y a _16 registres_ pouvant être utilisés dans le mode utilisateur (le mode dans lequel les programmes sont exécutés).\
Sur ARMv6, tous ces registres sont des registres 32 bits.

* les registres _r0_ à _r10_ sont les registres généraux, pouvant être utilisés pour n’importe quelle opération ;
* le registre _r11_ (fp) est le "frame pointer", il sert à indiquer le début du contexte de la fonction en cours (comme ebp sur x86) ;
* le registre _r12_ (ip) est l’"intraprocedure register", il sert à stocker temporairement des données lorsque l’on passe d’une fonction à une autre ;
* le registre _r13_ (sp) est le "stack pointer", il indique le haut de la pile (comme esp sur x86) ;
* le registre _r14_ (lr) est le "link register", il sert à stocker l’adresse de retour lorsqu’une fonction est appelée avec l’instruction "branch with link" (cf. plus bas) ;
* le registre _r15_ (pc) est le "program counter", il contient l’adresse de la prochaine instruction à exécuter ;
* le registre _cpsr_ pour "current program status register" est un registre spécial mis à jour par le biais de différentes instructions. Il est utilisé, par exemple, par les instructions conditionnelles et stocke le mode d’exécution actuel.
{% endhint %}

***

### <mark style="color:blue;">3. La Pile (Stack)</mark>

L’architecture ARM possède une pile, tout comme l’architecture x86. Celle-ci est par contre beaucoup plus flexible, car le programme peut choisir la façon dont elle fonctionne.

Il existe 4 types de piles :

* _pile ascendante_ : lorsque l’on dépose une valeur sur la pile, celle-ci grandit vers les adresse hautes. Le registre _sp_ pointe sur la dernière valeur de la pile ;
* _pile descendante_ : lorsque l’on dépose une valeur sur la pile, celle-ci grandit vers les adresses basses. Le registre _sp_ pointe sur la dernière valeur de la pile (c’est généralement ce comportement que l’on retrouve dans la plupart des programmes) ;
* _pile ascendante vide_ : tout comme la pile ascendante, la pile grandit vers les adresses hautes. Par contre, le registre _sp_ pointe sur une entrée vide de la pile ;
* _pile descendante vide_ : fonctionne comme la pile descendante, sauf que le registre _sp_ pointe sur une entrée vide de la pile.

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">4. Jeu d'Instructions</mark>

#### <mark style="color:green;">Caractéristiques Générales</mark>  :nerd:

Une instruction ARMv6 est tout le temps codée sur _32 bits_ (ou 16 bits pour le THUMB mode, cf. plus bas).&#x20;

* **Taille d'instruction** : 32 bits (16 bits en mode THUMB)
* **Alignement** : Adresses alignées sur 4 octets (2 octets en THUMB)
* **Format** : `0x18bd8070 -> popne {r4, r5, r6, pc}`

#### <mark style="color:green;">Mnémoniques Conditionnels</mark>&#x20;

Presque chaque instruction ARM peut être exécutée (ou non) suivant une condition. Voici la liste des mnémonique :

* `eq` : égal
* `ne` : pas égal
* `cs/hs` : plus grand ou égal (non-signé)
* `cc/lo` : plus petit (non-signé)
* `hi` : plus grand (non-signé)
* `ls` : plus petit ou égal (non-signé)
* `mi` : négatif
* `pl` : positif ou nul
* `vs` : overflow
* `vc` : pas d'overflow
* `ge` : plus grand ou égal (signé)
* `lt` : plus petit (signé)
* `gt` : plus grand (signé)
* `le` : plus petit ou égal (signé)
* `al` : toujours vrai

#### <mark style="color:green;">Instructions Arithmétiques</mark> :heavy\_plus\_sign:

* Syntaxe : _opconds Rd, Rs, Operand_
* op est un mnémonique parmi : _add, sub, rsb, adc, sbc, rsc_
* cond est un mnémonique conditionnel (optionnel)
* s indique si le registre cpsr est modifié par l’instruction (optionnel)
* Rd est le registre de destination
* Rs est le registre source
* Operand peut être un registre ou une constante.
* Exemples

```arm
addeq r0, r0, #42   ; Ajoute 42 à r0 (si égal)
subs r1, r2, r3     ; r1 = r2 - r3 (cpsr modifié)
```

#### <mark style="color:green;">Instructions Logiques</mark> :handshake:

* Syntaxe : _opconds Rd, Rs, Operand_
* op est un mnémonique parmi : _and, eor, tst, teq, orr, mov, bic, mvn_
* cond est un mnémonique conditionnel. (optionnel)
* s indique si le registre cpsr est modifié par l’instruction. (optionnel)
* Rd est le registre de destination
* Rs est le registre source
* Operand est un registre ou une constante
* Exemples

```arm
andle r5, r2, #13    ; r5 = r2 & 13 (si <=)
```

#### <mark style="color:green;">Instructions de Multiplication</mark> :heavy\_multiplication\_x:

* Syntaxe 1 : _mulconds Rd, Rm, Rs_
* Syntaxe 2 : _mlaconds Rd, Rm, Rs, Rn_
* cond est un mnémonique conditionnel (optionnel)
* s indique si le registre cpsr est modifié par l’instruction (optionnel)
* Rd est le registre de destination
* Rm est le premier opérande
* Rs est le deuxième opérande
* Rn est le troisième opérande pour mla

```arm
mul r5, r0, r1      ; r5 = r0 * r1 ; Stock dans r5 le résultat de (r0 * r1)
mla r2, r5, r6, r3  ; r2 = r5 * r6 + r3 ; Stock dans r2, le résultat de (r5 * r6 + r3)
```

#### <mark style="color:green;">Instructions de Comparaison</mark> :infinity:

* Syntaxe : _opcond Rs, Operand_
* op est un mnémonique parmis : _cmp, cmn_
* cond est un mnémonique conditionnel. (optionnel)
* Rs est un registre pour le premier operand
* Operand est un registre ou une constante
* L’instruction cmp soustrait Operand à Rs, et modifie le registre flag
* L’instruction cmn additionne Operand à Rs et modifie le registre flag

```arm
cmp r0, #5   ; soustrait 5 à r0, et modifie le registre cpsr
cmn r4, r6   ; additionne r4 et r6, et modifie le registre cpsr

```

#### <mark style="color:green;">Instructions d'Accès Mémoire</mark> :pencil:

* Syntaxe 1 : o&#x70;_&#x63;ondbt_ Rd, \[Rs]
* Syntaxe 2 : o&#x70;_&#x63;ondb_ Rd, \[Rs + off] _!_
* Syntaxe 3 : o&#x70;_&#x63;ondbt_ Rd, \[Rs], off
* op est un mnémonique parmi : _ldr, str_
* cond est un mnémonique conditionnel (optionnel)
* b permet de transferer que le byte le moins significatif (optionnel)
* t n’est pas utilisé en user mode.
* Rd est le registre de destination (pour ldr), ou le registre à transférer (pour str)
* Rs contient l’adresse pour charger ou transférer des données
* offset est un offset appliqué à Rs
* &#x20;! indique que l’offset est ajouté à Rs (le registre Rs est alors modifié)
* Exemples

```arm
ldrb r0, [r4]         ; Charge dans r0, le byte de l'adresse r4
str r2, [r1], #42     ; Copie à l'adresse r1, r2, et ajoute 42 à r1
str r1, [r6 + #75]!   ; Copie à l'adresse r6+75 r1, et ajoute 75 à r1
```

<mark style="color:green;">**Accès Multi-registres**</mark>

* Syntaxe : o&#x70;_&#x63;on&#x64;_&#x6D;ode Rs _!_, reglis&#x74;_^_
* op est un mnémonique parmis : _ldm, stm_
* cond est un mnémonique conditionnel (optionnel)
* mode est un mnémonique parmi&#x20;
  * _ia_ incrémentation de l’adresse après chaque transfert&#x20;
  * _ib_ incrémentation de l’adresse avant chaque transfert
  * _da_ décrémentation de l’adresse après chaque transfert
  * _db_ décrémentation de l’adresse avant chaque transfert
  * _fd_ pile descendante
  * _ed_ pile descendante vide
  * _fa_ pile ascendante
  * _ea_ pile ascendante vide
* Rs contient l’adresse où charger/transferer les registres.
* &#x20;! est utilisé pour écrire dans Rs l’adresse finale (optionnel)
* reglist est une liste de registre
* ^ n’est pas utilisé dans le mode user.
* Exemples

```arm
stmfd sp!, {r0}    ; Sauvegarde r0 sur la pile
ldmfd sp!, {fp,pc} ; Restaure fp et pc depuis la pile
push {r0}          ; Alias de stmfd sp!, {r0}
pop {fp,pc}        ; Alias de ldmfd sp!, {fp,pc}
```

#### <mark style="color:green;">Instructions de Branchement</mark>

* Syntaxe 1 : _opcond label_
* Syntaxe 2 : _bxcond Rs_
* op est un mnémonique parmis _b, bl_
* cond est un mnémonique conditionnel (optionnel)
* label est l’adresse où effectuer le branchement
* Rs est le registre contenant l’adresse du saut
* b (branch) effectue un branchement vers le label
* bl (branch with link) copie l’adresse de la prochaine instruction dans le registre lr avant d’effectuer le branchement
* bx effectue un branchement vers l’adresse contenue dans Rs, et passe en mode THUMB si le bit 0 du registre Rs est à 1
* Exemples

```arm
bl label ; lr = instruction suivante, puis saut vers label
b label  ; Saut simple vers label
```

#### <mark style="color:green;">Interruption Logicielle</mark>

* Syntaxe : _swicond expression_
* cond est un mnémonique conditionnel (optionnel)
* expression est une valeur ignorée par le processeur

_swi_ est l’instruction permettant de générer une interruption logicielle. Elle est utilisée par exemple pour les appels systèmes Linux.\
Sur Linux, le numéro de l’appel système est placé dans le registre r7, et les arguments sur la pile.

### <mark style="color:blue;">5. Mode THUMB</mark>

Un petit mot sur le mode THUMB.

Le mode THUMB a été créé afin de diminuer la taille du code. En effet, les instructions ne sont plus codés sur 32 bits comme le mode normal, mais sur 16 bits.

Pour passer du mode normal au mode THUMB, il suffit d’utiliser l’instruction bx (je vous renvoie au paragraphe concernant les instructions de branchement).

Ce mode peut être très utile afin de supprimer les octets nuls d’un shellcode par exemple, et d’en diminuer la taille.

### <mark style="color:blue;">6. Appels de Fonctions</mark>

Dans cette partie, je vais tenter de montrer la forme du code Assembleur généré par [GCC](http://fr.wikipedia.org/wiki/GNU_Compiler_Collection).

Tout d’abord, lorsqu’une fonction est appelée, les arguments sont passés dans les registres _r0_ à _r3_. Si une fonction possède plus de 4 arguments, alors les autres arguments sont placés sur la pile.

La valeur de retour d’une fonction est quant à elle placée dans le registre _r0_.

Une fonction commence généralement par un _prologue_, et se termine par un _épilogue_. Entre les deux, se trouve le corps de la fonction.

_Le prologue_ se charge de sauvegarder le contexte de la fonction appelante, décrit notamment par les registres fp et lr.

_L’épilogue_, lui, s’occupe de recharger le contexte de la fonction appelante, puis retourne vers l’adresse située juste après l’appel.

Analysons un bout de code C, pour voir comment est généré le code assembleur (sans aucune options d’optimisation).

#### Exemple Pratique

**Code C :**

```c
#include <stdio.h>

void foo(const char *s) {
    printf("%s", s);
}

int main(void) {
    foo("Hello World");
    return 0;
}
```

**Code Assembleur généré :**

{% code fullWidth="true" %}
```armasm
	000083cc <foo>:

	83cc:       e92d4800        push    {fp, lr}

	83d0:       e28db004        add     fp, sp, #4

	83d4:       e24dd008        sub     sp, sp, #8

	83d8:       e50b0008        str     r0, [fp, #-8]

	83dc:       e59f3010        ldr     r3, [pc, #16]   ; 83f4 <foo+0x28>

	83e0:       e1a00003        mov     r0, r3

	83e4:       e51b1008        ldr     r1, [fp, #-8]

	83e8:       ebffffc0        bl      82f0 <_init+0x20>

	83ec:       e24bd004        sub     sp, fp, #4

	83f0:       e8bd8800        pop     {fp, pc}

	83f4:       00008488        .word   0x00008488



    000083f8 <main>:
	83f8:       e92d4800        push    {fp, lr}

	83fc:       e28db004        add     fp, sp, #4

	8400:       e59f000c        ldr     r0, [pc, #12]   ; 8414 <main+0x1c>

	8404:       ebfffff0        bl      83cc <foo>

	8408:       e3a03000        mov     r3, #0

	840c:       e1a00003        mov     r0, r3

	8410:       e8bd8800        pop     {fp, pc}

	8414:       0000848c        .word   0x0000848c

	
```
{% endcode %}

#### Analyse du Flot d'Exécution

* En 0x8400, l’adresse de la chaine "Hello World" est placée dans le registre r0
* En 0x8404, on effectue un branchement vers foo, en sauvegardant l’adresse de la prochaine instruction dans lr (link register)
* En 0x83cc et 0x83d0 on a le prologue de la fonction foo. On sauvegarde le registre fp (frame pointer) et le registre lr (link register) sur la pile, puis on place dans fp, l’adresse de sp - 4
* En 0x83d4, on reserve une place sur la pile (8 bytes) pour des variables temporaires.
* En 0x83d8, on sauvegarde le registre r0 dans l’espace mémoire que l’on vient de réserver sur la pile.
* En 0x83dc, on place dans r3, l’adresse de la chaine "%s" (0x8488). Puis en 0x83e0, on place r3 dans r0
* En 0x83e4, on place dans r1 la variable qu’on a sauvegardé sur la pile en 0x83d8.
* En 0x83e8, on appelle la fonction printf. r0 contient l’adresse de la chaine "%s", et r1 contient l’adresse de la chaine "Hello world".
* En 0x83ec et 0x83f0, on a l’épilogue de la fonction foo. On commence par remettre la pile dans le contexte de main, puis on restaure fp, puis pc. En restaurant pc, on revient dans la fonction main (car le registre lr avait été sauvegardé lors du prologue, et contenait l’adresse située après l’appel de foo)

### Conclusion

L'architecture ARM offre un jeu d'instructions riche et flexible, particulièrement adapté aux systèmes embarqués. Sa conception RISC permet une exécution efficace avec des instructions conditionnelles et une gestion flexible de la pile.

**Points clés à retenir :**

* Instructions conditionnelles universelles
* Gestion flexible de la pile
* Convention d'appel claire
* Mode THUMB pour l'optimisation de taille
* Architecture bien adaptée aux contraintes embarquées
