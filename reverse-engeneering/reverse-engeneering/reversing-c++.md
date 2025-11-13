# Reversing C++

## <mark style="color:red;">Manual Approach</mark>

### <mark style="color:blue;">Identifying C++ Binaries and Constructs</mark>

Quand on fait du **reverse engineering** (analyse inverse) sur un programme compilé, il est important de savoir si c’est un programme C++ (et non C, par exemple). Ce texte explique **comment reconnaître un binaire compilé en C++** en observant certains indices dans le code assembleur.

***

#### <mark style="color:green;">1. Utilisation fréquente de</mark> <mark style="color:green;"></mark><mark style="color:green;">`ecx`</mark> <mark style="color:green;"></mark><mark style="color:green;">(pointeur</mark> <mark style="color:green;"></mark><mark style="color:green;">`this`</mark><mark style="color:green;">) :</mark>

En C++, les **fonctions membres des classes** utilisent un pointeur spécial appelé `this` pour accéder aux données de l’objet courant. En assembleur, ce pointeur est souvent stocké dans le registre `ecx`.

<mark style="color:yellow;">**Exemple 1 :**</mark>

```asm
.text:004019E4 mov ecx, esi
.text:004019E6 push 0BBh
.text:004019EB call sub_401120 ; Appel d'une fonction membre
```

Ici, la valeur de `esi` (probablement l’adresse d’un objet) est copiée dans `ecx` avant l’appel d’une fonction&#x20;

→  **signe qu’on appelle une méthode d’objet (fonction membre)**.

#### <mark style="color:orange;">À quoi sert</mark> <mark style="color:orange;"></mark><mark style="color:orange;">`ecx`</mark> <mark style="color:orange;"></mark><mark style="color:orange;">ici ?</mark>

Dans les conventions d’appel du C++ (notamment sous **Windows 32 bits**, avec `__thiscall`), **le pointeur `this` est toujours passé dans le registre `ecx`** quand on appelle une **méthode d'une classe**.

Donc ici :

* **`esi` contient un pointeur vers une instance d’objet** (genre un objet `MyClass`)
* On le copie dans `ecx` pour que la méthode `sub_401120` puisse y accéder
* Ensuite on appelle `sub_401120`, et **à l'intérieur**, ce code peut accéder aux membres de l'objet via `ecx`

Tu verras probablement des instructions comme :

```
mov eax, [ecx+4]  ; lit un champ de l'objet (ex: this->some_field)
```

<mark style="color:yellow;">**Exemple 2 :**</mark>

```asm
.text:004010D0 sub_4010D0 proc near
.text:004010D0 push esi
.text:004010D1 mov esi, ecx
.text:004010DD mov dword ptr [esi], offset off_40C0D0
.text:00401101 mov dword ptr [esi+4], 0BBh
.text:00401108 call sub_401EB0
.text:0040110D add esp, 18h
.text:00401110 pop esi
.text:00401111 retn
.text:00401111 sub_4010D0 endp
```

Dans cette fonction, on utilise `ecx` directement sans l’avoir initialisé dans la fonction → **ça suggère que `ecx` est passé automatiquement par l’appelant, typique d’une fonction membre.**

***

#### <mark style="color:green;">2. Convention d’appel spécifique aux fonctions membres :</mark>

En C++, les fonctions membres sont appelées de manière particulière :

* Les **paramètres** sont poussés sur la pile (`stack`),
* Mais le **pointeur `this` est passé dans `ecx`**.

**Exemple :**

```asm
.text:00401994 push 0Ch
.text:00401996 call ??2@YAPAXI@Z ; operator new(uint)
.text:004019AB mov ecx, eax
.text:004019AD call ClassA_ctor
```

* On alloue de la mémoire avec `operator new` → retourne un pointeur dans `eax`,
* Ce pointeur est ensuite mis dans `ecx`,
* Puis on appelle le **constructeur** de la classe (`ClassA_ctor`).

***

#### <mark style="color:green;">3. Appels à des fonctions virtuelles (virtual calls) :</mark>

En C++, les **fonctions virtuelles** sont appelées de manière indirecte, via une **table virtuelle (vftable)**.

<mark style="color:yellow;">**Exemple :**</mark>

```asm
.text:004019FF mov eax, [esi] ; EAX = vtable
.text:00401A04 mov ecx, esi
.text:00401A0B call dword ptr [eax]
```

* `esi` contient un objet C++,
* On récupère l’adresse de la **vtable** dans `eax`,
* Et on appelle une fonction virtuelle indirectement : `call [eax]`.

Pour comprendre quelle fonction est appelée, il faut retrouver la vtable associée à la classe.

{% hint style="warning" %}
***

En C++, une **fonction virtuelle** est une fonction qui peut être **redéfinie** dans une classe dérivée (héritage).\
Elle permet d’avoir un **comportement différent selon le type réel de l’objet** utilisé, même si on le manipule via un pointeur ou une référence vers la classe de base.

<mark style="color:green;">**📌 Exemple en C++ :**</mark>

```cpp
class Animal {
public:
    virtual void crier() { std::cout << "Animal" << std::endl; }
};

class Chien : public Animal {
public:
    void crier() override { std::cout << "Wouf!" << std::endl; }
};

Animal* a = new Chien();
a->crier(); // Affiche "Wouf!" grâce au mécanisme de fonction virtuelle
```

💡 Ici, même si `a` est un `Animal*`, le C++ appelle `Chien::crier()` → c’est ça une **fonction virtuelle**.

***

Le compilateur (ex : MSVC, GCC) gère les fonctions virtuelles avec une **vtable** (virtual table), une **table d’adresses**.

* Chaque classe avec fonctions virtuelles a une **vtable**.
* Chaque objet contient un **pointeur vers sa vtable** (souvent au tout début de l’objet).
* Quand on appelle une fonction virtuelle, le programme :
  * va chercher **l’adresse de la fonction dans la vtable**,
  * puis il **appelle cette adresse** → d’où l’**appel indirect** (indirect call).

***

```asm
.text:00401996 call ??2@YAPAXI@Z ; operator new(uint)
```

→ Alloue de la mémoire pour un objet C++ (opérateur `new`).

```asm
.text:004019B2 mov esi, eax
```

→ L’adresse de l’objet est maintenant dans `esi`.

```asm
.text:004019AD call ClassA_ctor
```

→ Appelle le **constructeur** de `ClassA` pour initialiser l’objet.

```asm
.text:004019FF mov eax, [esi]
```

→ Charge le **pointeur vers la vtable** de l’objet (souvent stocké en début d’objet).\
Donc maintenant `eax = vtable`.

```asm
.text:00401A0B call dword ptr [eax]
```

→ Appelle **la première fonction** de la vtable → donc une **fonction virtuelle**.

***

{% code fullWidth="true" %}
```
[ objet en mémoire ]
| ptr_vtable | autres données membres |

ptr_vtable -----> [ fctVirt1 | fctVirt2 | fctVirt3 | ... ]
                       |
                       V
                  call fctVirt1
```
{% endcode %}

***
{% endhint %}

***

#### <mark style="color:green;">4. Code utilisant STL et fonctions importées C++ :</mark>

Un autre indice que le binaire est en C++ : **présence de fonctions liées à la STL (Standard Template Library)**. ", which can be determined via Imported functions or library signature identification such as IDA’s FLIRT:"

<mark style="color:yellow;">**Exemple :**</mark>

```asm
.text:00401201 mov ecx, eax
.text:00401203 call ds:?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHD@Z
```

Cela montre un appel à une méthode de la STL (`std::basic_streambuf<char>::sputc(char)`).

Outils comme **IDA Pro (FLIRT signatures)** peuvent aussi détecter les fonctions C++/STL automatiquement.

***

#### <mark style="color:green;">Class Instance Layout</mark>

Avant d’aller plus loin, la personne qui fait du reverse engineering (l’analyste) doit aussi comprendre **comment les classes sont organisées en mémoire**.

Commençons par une classe très simple :

```cpp
class Ex1
{
    int var1;
    int var2;
    char var3;
public:
    int get_var1();
};
```

#### 🧱 Disposition mémoire de la classe `Ex1` :

```
class Ex1 taille(12) :
+---
0  | var1
4  | var2
8  | var3
   | <membre d’alignement> (taille = 3)
+---
```

Un **remplissage (padding)** a été ajouté après le dernier membre (`var3`) parce qu’il faut que l’objet soit aligné sur une **limite de 4 octets**.

> Sous Visual C++, les membres d’une classe sont placés en mémoire **dans le même ordre que celui de leur déclaration** dans le code source.

***

<mark style="color:yellow;">**🧠 Que se passe-t-il si la classe contient des fonctions virtuelles ?**</mark>

Prenons cet exemple :

```cpp
class Ex2
{
    int var1;
public:
    virtual int get_sum(int x, int y);
    virtual void reset_values();
};
```

#### 🧱 Disposition mémoire de la classe `Ex2` :

```
class Ex2 taille(8) :
+---
0 | {vfptr}    // pointeur vers la table virtuelle
4 | var1
+---
```

> Remarque : un **pointeur vers la table des fonctions virtuelles** est ajouté **au début** de la structure mémoire de l’objet.

Cette **table virtuelle (vtable)** contient les **adresses des fonctions virtuelles**, dans l’ordre où elles ont été déclarées.

#### <mark style="color:orange;">📁 Table virtuelle (vtable) de</mark> <mark style="color:orange;"></mark><mark style="color:orange;">`Ex2`</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark>

```
Ex2::$vftable@:
0 | &Ex2::get_sum
4 | &Ex2::reset_values
```

🧬 Que se passe-t-il si une classe hérite d’une autre ? (Héritage simple)

Voici ce qui se passe lorsqu’une classe hérite **d’une seule classe** :

```cpp
class Ex3 : public Ex2
{
    int var1;
public:
    void get_values();
};
```

#### 🧱 Disposition mémoire de `Ex3` :

```
class Ex3 taille(12) :
+---
| +--- (classe de base Ex2)
0 | | {vfptr}
4 | | var1 (hérité de Ex2)
| +---
8 | var1 (propre à Ex3)
+---
```

> Comme on peut le voir, la **disposition mémoire de la classe dérivée** (Ex3) est simplement **ajoutée à la suite** de celle de la classe de base (Ex2).

***

<mark style="color:orange;">**🤹️ Héritage multiple**</mark>

Prenons deux classes, une base et une dérivée :

```cpp
class Ex4
{
    int var1;
    int var2;
public:
    virtual void func1();
    virtual void func2();
};
```

Puis une classe qui hérite de **deux classes** :

```cpp
class Ex5 : public Ex2, Ex4
{
    int var1;
public:
    void func1();       // redéfinition de Ex4::func1
    virtual void v_ex5();
};
```

🧱 Disposition mémoire de `Ex5` :

```
class Ex5 taille(24) :
+---
| +--- (classe de base Ex2)
0  | | {vfptr}
4  | | var1
| +---
| +--- (classe de base Ex4)
8  | | {vfptr}
12 | | var1
16 | | var2
| +---
20 | var1 (propre à Ex5)
+---
```

📁 Tables virtuelles (vtables) de `Ex5` :

**Vtable héritée de Ex2 (et enrichie) :**

```
Ex5::$vftable@Ex2@:
0 | &Ex2::get_sum
1 | &Ex2::reset_values
2 | &Ex5::v_ex5
```

**Vtable héritée (et modifiée) de Ex4 :**

```
Ex5::$vftable@Ex4@:
| -8  // correspond à un ajustement de l’adresse en mémoire
0 | &Ex5::func1        // redéfinit func1
1 | &Ex4::func2
```

***

🔎 Analyse :

* Une **copie des données membres de chaque classe de base** est **intégrée dans l’objet dérivé**.
* Chaque classe de base qui possède **des fonctions virtuelles** obtient sa **propre vtable**.
* **La première classe de base (Ex2 ici)** partage son `vfptr` avec l'objet courant.
* Les fonctions virtuelles **propres à la classe dérivée (Ex5)** sont **ajoutées à la suite** de la vtable de la première classe de base.
* Les classes de base **suivantes** (comme Ex4) reçoivent leur propre `vfptr` et leur propre table virtuelle distincte.

***

### <mark style="color:blue;">**Identification des Classes C++**</mark>

Après avoir identifié que la cible est un binaire C++, avoir abordé certaines structures importantes du langage, et expliqué comment une instance de classe est représentée en mémoire, nous allons maintenant voir **comment identifier les classes C++ utilisées dans le binaire**.

Les méthodes présentées ici cherchent uniquement à **déterminer quelles classes sont présentes** (par exemple : ClassA, ClassB, ClassC, etc.).\
Les prochaines sections expliqueront **comment déduire les relations entre ces classes** ainsi que leurs **membres**.

***

#### <mark style="color:green;">1) Identification des Constructeurs / Destructeurs</mark>

Pour identifier des classes dans un binaire, il faut examiner **comment les objets de ces classes sont créés**.\
La manière dont leur création est implémentée au niveau binaire **donne des indices** pour les repérer dans le désassemblage.

#### <mark style="color:green;">➤ 1. Objet global</mark>

Les **objets globaux**, comme leur nom l’indique, sont des variables **déclarées globalement** (en dehors de toute fonction).\
L’espace mémoire de ces objets est **réservé à la compilation** et stocké dans la **section des données** du binaire.

* Le **constructeur** est appelé **implicitement avant `main()`**, au démarrage du programme C++.
* Le **destructeur** est appelé **à la fin du programme**.

Pour identifier un objet global :

* Cherchez une fonction appelée **avec un pointeur vers une variable globale** comme pointeur `this`.
* Examinez les **références croisées** vers cette variable globale.
* Si un appel de fonction (avec cette variable comme `this`) se trouve **entre le point d'entrée du programme et `main()`**, c'est probablement le **constructeur**.

***

#### <mark style="color:green;">➤ 2. Objet local</mark>

Les **objets locaux** sont des variables **déclarées dans une fonction**. Leur portée va **du point de déclaration jusqu'à la fin du bloc** (fin de fonction ou accolades fermantes).

* Leur mémoire est **allouée sur la pile (stack)**.
* Le **constructeur** est appelé **au moment de la déclaration**.
* Le **destructeur** est appelé **à la fin du bloc**.

Pour identifier :

* Le **constructeur** est une fonction appelée avec un `this` pointant vers **une variable de pile non initialisée**.
* Le **destructeur** est la **dernière fonction appelée avec ce même pointeur** dans le même bloc.

<mark style="color:orange;">**Exemple (Désassemblage) :**</mark>

```asm
Here’s an example:
.text:00401060 sub_401060 proc near
.text:00401060
.text:00401060 var_C = dword ptr -0Ch
.text:00401060 var_8 = dword ptr -8
.text:00401060 var_4 = dword ptr -4
.text:00401060
…(some code)…
.text:004010A4 add esp, 8
.text:004010A7 cmp [ebp+var_4], 5
.text:004010AB jle short loc_4010CE
.text:004010AB
.text:004010AB {  block begin
.text:004010AD lea ecx, [ebp+var_8] ; var_8 is uninitialized
.text:004010B0 call sub_401000 ; constructor
.text:004010B5 mov edx, [ebp+var_8]
.text:004010B8 push edx
.text:004010B9 push offset str->WithinIfX
.text:004010BE call sub_4010E4
.text:004010C3 add esp, 8
.text:004010C6 lea ecx, [ebp+var_8]
.text:004010C9 call sub_401020 ; destructor
.text:004010CE }  block end
.text:004010CE
.text:004010CE loc_4010CE: ; CODE XREF: sub_401060+4Bj
.text:004010CE mov [ebp+var_C], 0
.text:004010D5 lea ecx, [ebp+var_4]
.text:004010D8 call sub_401020
```

***

#### <mark style="color:green;">➤ 3. Objet alloué dynamiquement</mark>

Ces objets sont créés **avec l’opérateur `new`**, donc dynamiquement dans le tas (**heap**).

* `new` → transformé en un appel à la fonction **`operator new()`**, qui :
  * prend en argument la taille de l’objet,
  * alloue la mémoire sur le heap,
  * retourne un pointeur.
* Ensuite, ce pointeur est passé au **constructeur**.
* Pour les libérer, on utilise **`delete`**, qui :
  * appelle le **destructeur**,
  * puis **libère la mémoire** (avec `free`).

**Exemple (Désassemblage) :**

```asm
.text:0040103D _main proc near
.text:0040103D argc = dword ptr 8
.text:0040103D argv = dword ptr 0Ch
.text:0040103D envp = dword ptr 10h
.text:0040103D
.text:0040103D push esi
.text:0040103E push 4 ; size_t
.text:00401040 call ??2@YAPAXI@Z ; operator new(uint)
.text:00401045 test eax, eax ;eax = address of allocated
memory
.text:00401047 pop ecx
.text:00401048 jz short loc_401055
.text:0040104A mov ecx, eax
.text:0040104C call sub_401000 ; call to constructor
.text:00401051 mov esi, eax
.text:00401053 jmp short loc_401057
.text:00401055 loc_401055: ; CODE XREF: _main+Bj
.text:00401055 xor esi, esi
.text:00401057 loc_401057: ; CODE XREF: _main+16j
.text:00401057 push 45h
.text:00401059 mov ecx, esi
.text:0040105B call sub_401027
.text:00401060 test esi, esi
.text:00401062 jz short loc_401072
.text:00401064 mov ecx, esi
.text:00401066 call sub_40101B ; call to destructor
.text:0040106B push esi ; void *
.text:0040106C call j__free ; call to free thunk function
.text:00401071 pop ecx
.text:00401072 loc_401072: ; CODE XREF: _main+25j
.text:00401072 xor eax, eax
.text:00401074 pop esi
.text:00401075 retn
.text:00401075 _main e
```

{% hint style="warning" %}
✅ Pour reconnaître les deux dans un binaire :

* **Pile** : si `lea ecx, [ebp+var_X]` puis `call constructeur` → **local**.
* **Tas** : si `call operator new`, suivi d’un `call constructeur`, puis plus tard `call destructeur` et `free` → **dynamique**.
{% endhint %}

***

#### <mark style="color:green;">2) Identification des Classes Polymorphes via RTTI</mark>

Une autre façon d’identifier des classes (en particulier **les classes polymorphes**, c’est-à-dire avec des **fonctions virtuelles**) est d'utiliser le **RTTI (Run-Time Type Information)**.

Le **RTTI** est un mécanisme qui permet de connaître **le type d’un objet à l'exécution**.

* Utilisé par les opérateurs `typeid` et `dynamic_cast`.
* Ces opérateurs nécessitent que le compilateur **insère dans le binaire des structures** contenant des informations sur les classes :
  * nom de la classe,
  * hiérarchie,
  * disposition mémoire.

⚠️ Sur **MSVC 6.0**, le RTTI est **désactivé par défaut**.\
✔️ Sur **MSVC 2005**, il est **activé par défaut**.

***

#### <mark style="color:green;">🔧 Astuce : Afficher la disposition mémoire des classes</mark>

MSVC a un **switch de compilation** pour afficher la disposition mémoire des classes :

```
-d1reportAllClassLayout
```

Cela génère un fichier `.layout` contenant :

* les **offsets** des classes de base dans les dérivées,
* les vtables (tables de fonctions virtuelles),
* les vb-tables (classes virtuelles de base),
* les membres.

***

#### <mark style="color:green;">Structures utilisées pour le RTTI</mark>

Le compilateur stocke dans le binaire des **structures de métadonnées** pour chaque classe polymorphe.

#### <mark style="color:orange;">➤</mark> <mark style="color:orange;"></mark><mark style="color:orange;">`RTTICompleteObjectLocator`</mark>

C’est une structure qui contient des pointeurs vers deux autres structures :

| Offset | Type | Nom                       | Description                          |
| ------ | ---- | ------------------------- | ------------------------------------ |
| 0x00   | DW   | signature                 | Toujours 0 ?                         |
| 0x04   | DW   | offset                    | Offset de la vftable dans la classe  |
| 0x08   | DW   | cdOffset                  | Inconnu ici                          |
| 0x0C   | DW   | pTypeDescriptor           | Pointeur vers infos de la classe     |
| 0x10   | DW   | pClassHierarchyDescriptor | Infos sur la hiérarchie de la classe |

***

#### <mark style="color:green;">Exemple : disposition en mémoire</mark>

```asm
.rdata:00404128 dd offset ClassA_RTTICompleteObjectLocator
.rdata:0040412C ClassA_vftable dd offset sub_401000 ; fonction virtuelle
.rdata:00404130 dd offset sub_401050
.rdata:00404134 dd offset sub_4010C0
.rdata:00404138 dd offset ClassB_RTTICompleteObjectLocator
.rdata:0040413C ClassB_vftable dd offset sub_4012B0
.rdata:00404140 dd offset sub_401300
.rdata:00404144 dd offset sub_4010C0
```

***

#### <mark style="color:green;">Exemple de</mark> <mark style="color:green;"></mark><mark style="color:green;">`RTTICompleteObjectLocator`</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```asm
.rdata:004045A4 ClassB_RTTICompleteObjectLocator
dd 0                          ; signature
dd 0                          ; offset
dd 0                          ; cdOffset
dd offset ClassB_TypeDescriptor
dd offset ClassB_RTTIClassHierarchyDescriptor
```

***

#### <mark style="color:green;">**🔹 TypeDescriptor (Descripteur de type)**</mark>

➤ C’est quoi ?

Le `TypeDescriptor` est une structure utilisée pour décrire **le type d'une classe**. Elle est pointée par le **4e champ (DWORD)** de la structure `RTTICompleteObjectLocator`.

> Elle contient le **nom de la classe**, ce qui est très utile pour un reverseur, car cela lui donne une idée du rôle de la classe.

📦 Exemple réel :

```asm
.data:0041A098 ClassA_TypeDescriptor
dd offset type_info_vftable     ; pointeur vers la vftable type_info
.data:0041A09C dd 0             ; champ "spare" (réservé)
.data:0041A0A0 db '.?AVClassA@@',0 ; nom de la classe (manglé ici)
```

***

#### <mark style="color:green;">🔹 RTTIClassHierarchyDescriptor</mark>

➤ C’est quoi ?

Cette structure décrit la **hiérarchie d'héritage** d'une classe : combien de classes de base elle a, si l’héritage est multiple, virtuel, etc. Elle contient un **tableau de pointeurs vers des RTTIBaseClassDescriptor** (on y reviendra).

📑 Structure :

| Offset | Type  | Nom             | Description                                                 |
| ------ | ----- | --------------- | ----------------------------------------------------------- |
| 0x00   | DWORD | signature       | Toujours 0 ?                                                |
| 0x04   | DWORD | attributes      | bit 0 = héritage multiple, bit 1 = héritage virtuel         |
| 0x08   | DWORD | numBaseClasses  | Nombre de classes de base (la classe elle-même est incluse) |
| 0x0C   | DWORD | pBaseClassArray | Pointeur vers un tableau de RTTIBaseClassDescriptor         |

***

📦 Exemple :

```cpp
class ClassA { ... };
class ClassE { ... };
class ClassG : public virtual ClassA, public virtual ClassE { ... };
```

```asm
.rdata:004178C8 ClassG_RTTIClassHierarchyDescriptor
dd 0                       ; signature
dd 3                       ; attributs : héritage multiple + virtuel
dd 3                       ; 3 classes de base (ClassG, ClassA, ClassE)
dd offset ClassG_pBaseClassArray ; pointeur vers tableau
```

🔗 Tableau pointé :

```asm
ClassG_pBaseClassArray:
dd offset RTTIBaseClassDescriptor@4178e8 ; ClassG
dd offset RTTIBaseClassDescriptor@417904 ; ClassA
dd offset RTTIBaseClassDescriptor@417920 ; ClassE
```

***

#### <mark style="color:green;">🔹 RTTIBaseClassDescriptor</mark>

➤ C’est quoi ?

C’est une structure contenant des infos sur **une classe de base**. Elle décrit :

* Où se trouve son TypeDescriptor
* Où elle se trouve dans la classe dérivée (offsets)
* Quelle est sa hiérarchie
* Comment accéder à son `vfptr` s’il y en a un

📑 Structure :

| Offset | Type  | Nom               | Description                                           |
| ------ | ----- | ----------------- | ----------------------------------------------------- |
| 0x00   | DWORD | pTypeDescriptor   | TypeDescriptor de cette classe de base                |
| 0x04   | DWORD | numContainedBases | Nombre de bases directes                              |
| 0x08   | DWORD | PMD.mdisp         | Offset vers la vftable de la base                     |
| 0x0C   | DWORD | PMD.pdisp         | Offset vers la vbtable                                |
| 0x10   | DWORD | PMD.vdisp         | Offset dans la vbtable vers le vrai offset de la base |
| 0x14   | DWORD | attributes        | Attributs inconnus (souvent 0 ou 0x50)                |
| 0x18   | DWORD | pClassDescriptor  | RTTIClassHierarchyDescriptor de cette classe de base  |

***

#### <mark style="color:green;">🔹 vbtable : Table d’héritage virtuel</mark>

Quand une classe hérite **virtuellement**, le compilateur crée une **vbtable** (virtual base table), qui contient les offsets nécessaires pour accéder aux classes de base virtuelles.

📘 Pourquoi ?

Parce qu’avec l’héritage virtuel, la position des classes de base dans la mémoire **n’est pas fixe**. Donc le programme a besoin d’un mécanisme pour savoir où elles se trouvent à l’exécution.

***

📦 Exemple de layout mémoire de `ClassG` :

```cpp
class ClassG size(28):
+---
0  | {vfptr}                   ; pointeur vers vtable de ClassG
4  | {vbptr}                   ; pointeur vers vbtable
+--- (base virtuelle ClassA)
8  | {vfptr}                   ; vtable ClassA
12 | class_a_var01
16 | class_a_var02
     <alignement padding>
+--- (base virtuelle ClassE)
20 | {vfptr}                   ; vtable ClassE
24 | class_e_var01
```

***

📦 La vbtable générée pour `ClassG` :

```asm
ClassG::$vbtable@:
0 | -4       ; offset pour "this" ajusté ?
1 | 4        ; offset de ClassA (4 + 0 = 4)
2 | 16       ; offset de ClassE (4 + 16 = 20)
```

Donc :

* vbtable est à l’offset `4` dans la classe
* Le décalage pour atteindre `ClassE` est `vbtable + 8` → donne 16
* Donc `ClassE` commence à l’offset **4 + 16 = 20** dans l’objet

***

🔹 Exemple complet du `RTTIBaseClassDescriptor` pour `ClassE` dans `ClassG` :

```asm
.rdata:00418AFC RTTIBaseClassDescriptor@418afc
dd offset oop_re$ClassE$TypeDescriptor ; pointeur vers nom/type
dd 0     ; pas de bases contenues
dd 0     ; PMD.mdisp
dd 4     ; PMD.pdisp : offset vbtable = 4
dd 8     ; PMD.vdisp : entrée n°2 de la vbtable
dd 50h   ; attributs (inconnu, probablement "est virtuel")
dd offset oop_re$ClassE$RTTIClassHierarchyDescriptor ; lien vers sa hiérarchie
```

Donc pour retrouver `ClassE` :

1. Lire le champ vbptr à l’offset `4`
2. Accéder à l’entrée `[vbptr + 8]` (car `vdisp = 8`)
3. Le contenu est `16` → `ClassE` est à `4 + 16 = offset 2`

Résumé simple

| Structure                      | Sert à quoi ?                                                       |
| ------------------------------ | ------------------------------------------------------------------- |
| `TypeDescriptor`               | Contient le **nom de la classe**                                    |
| `RTTIClassHierarchyDescriptor` | Liste les **classes de base**, indique héritage virtuel/multiple    |
| `RTTIBaseClassDescriptor`      | Donne la **position exacte** d’une classe de base dans la dérivée   |
| `vbtable`                      | Utilisé pour localiser les classes de base virtuelles dynamiquement |

***

### <mark style="color:blue;">Identifier la relation entre classes</mark>

#### <mark style="color:green;">1. Relation de classes via l’analyse des constructeurs</mark>

Les constructeurs contiennent du code qui initialise l’objet, comme par exemple appeler les constructeurs des classes de base et configurer les vftables. Par conséquent, l’analyse des constructeurs peut nous donner une bonne idée de la relation de cette classe avec d’autres classes.

<mark style="color:$success;">**Héritage simple**</mark>

```asm
.text:00401010 sub_401010 proc near
.text:00401010
.text:00401010 var_4 = dword ptr -4
.text:00401010
.text:00401010 push ebp
.text:00401011 mov ebp, esp
.text:00401013 push ecx
.text:00401014 mov [ebp+var_4], ecx ; obtenir le pointeur this de l'objet actuel
.text:00401017 mov ecx, [ebp+var_4]
.text:0040101A call sub_401000 ; appel du constructeur de la classe A
.text:0040101F mov eax, [ebp+var_4]
.text:00401022 mov esp, ebp
.text:00401024 pop ebp
.text:00401025 retn
.text:00401025 sub_401010 endp
```

Supposons que nous ayons déterminé que cette fonction est un constructeur en utilisant les méthodes mentionnées dans la section II-B. À présent, nous voyons qu’une fonction est appelée en utilisant le pointeur this de l’objet courant. Il peut s’agir d’une fonction membre de la classe courante, ou d’un constructeur de la classe de base.

Comment savoir laquelle ? En réalité, il n’existe aucun moyen parfait de distinguer les deux simplement en observant le code généré. Cependant, dans des applications réelles, il est hautement probable que les constructeurs aient déjà été identifiés comme tels avant cette étape (voir section II-B), donc tout ce que nous avons à faire est de corréler cette information afin d’obtenir une identification plus précise. Autrement dit, si une fonction préalablement identifiée comme constructeur est appelée à l’intérieur d’un autre constructeur en utilisant le pointeur this de l’objet courant, il s’agit probablement d’un constructeur de la classe de base.

Identifier cela manuellement impliquerait de vérifier les autres références croisées vers cette fonction et de voir si elle est appelée comme constructeur ailleurs dans le binaire. Nous discuterons des méthodes automatiques d’identification plus loin dans ce document.

***

<mark style="color:$success;">**Héritage multiple**</mark>

```asm
.text:00401020 sub_401020 proc near
.text:00401020
.text:00401020 var_4 = dword ptr -4
.text:00401020
.text:00401020 push ebp
.text:00401021 mov ebp, esp
.text:00401023 push ecx
.text:00401024 mov [ebp+var_4], ecx
.text:00401027 mov ecx, [ebp+var_4] ; pointeur vers la classe de base A
.text:0040102A call sub_401000 ; appel du constructeur de la classe A
.text:0040102A
.text:0040102F mov ecx, [ebp+var_4]
.text:00401032 add ecx, 4 ; pointeur vers la classe de base C
.text:00401035 call sub_401010 ; appel du constructeur de la classe C
.text:00401035
.text:0040103A mov eax, [ebp+var_4]
.text:0040103D mov esp, ebp
.text:0040103F pop ebp
.text:00401040 retn
.text:00401040
.text:00401040 sub_401020 endp
```

L’héritage multiple est en fait plus facile à repérer que l’héritage simple. Comme dans l’exemple d’héritage simple, la première fonction appelée peut être une fonction membre ou un constructeur de classe de base. Remarquez que dans le désassemblage, 4 octets sont ajoutés au pointeur this avant d’appeler la deuxième fonction. Cela indique qu’une autre classe de base est en train d’être initialisée.

Voici la disposition de cette classe pour vous aider à visualiser. Le désassemblage ci-dessus appartient au constructeur de la classe `D`. La classe `D` est dérivée de deux autres classes, `A` et `C` :

```cpp
class A size(4):
+---
0 | a1
+---

class C size(4):
+---
0 | c1
+---

class D size(12):
+---
| +--- (classe de base A)
0 | | a1
| +---
| +--- (classe de base C)
4 | | c1
| +---
8 | d1
+---
```

***

#### <mark style="color:green;">**2. Relation de classes polymorphes via la RTTI**</mark>

Comme nous l’avons évoqué dans la section II-B, les informations de type à l’exécution (RTTI, Run-Time Type Information) peuvent être utilisées pour identifier la relation de classes polymorphes. La structure de données associée à cela est le `RTTIClassHierarchyDescriptor`. Encore une fois, ci-dessous se trouvent les champs de `RTTIClassHierarchyDescriptor` à des fins d’illustration :

<table data-full-width="true"><thead><tr><th>Décalage</th><th>Type</th><th>Nom</th><th>Description</th></tr></thead><tbody><tr><td>0x00</td><td>DW</td><td>signature</td><td>Toujours 0 ?</td></tr><tr><td>0x04</td><td>DW</td><td>attributes</td><td>Bit 0 – héritage multipleBit 1 – héritage virtuel</td></tr><tr><td>0x08</td><td>DW</td><td>numBaseClasses</td><td>Nombre de classes de base (inclut la classe elle-même)</td></tr><tr><td>0x0C</td><td>DW</td><td>pBaseClassArray</td><td>Tableau de <code>RTTIBaseClassDescriptor</code></td></tr></tbody></table>

Le `RTTIClassHierarchyDescriptor` contient un champ nommé `pBaseClassArray`, qui est un tableau de `RTTIBaseClassDescriptor` (BCD). Ces BCD pointeront ensuite vers le `TypeDescriptor` de la classe de base réelle.

***

### <mark style="color:blue;">Identification des membres de classe</mark>

Identifier les membres d’une classe est un processus simple, bien que lent et fastidieux.\
On peut identifier les **variables membres** en observant les accès à des décalages relatifs au pointeur `this` :

```asm
.text:00401003 push ecx
.text:00401004 mov [ebp+var_4], ecx ; ecx = pointeur this
.text:00401007 mov eax, [ebp+var_4]
.text:0040100A mov dword ptr [eax + 8], 12345h ; écriture dans le 3ème
                                               ; membre variable
```

On peut également identifier les **fonctions membres virtuelles** en recherchant les appels indirects à des pointeurs situés à des décalages relatifs à la table virtuelle (vftable) de l’objet :

```asm
.text:00401C21 mov ecx, [ebp+var_1C] ; ecx = pointeur this
.text:00401C24 mov edx, [ecx]        ; edx = pointeur vers la vftable
.text:00401C26 mov ecx, [ebp+var_1C]
.text:00401C29 mov eax, [edx+4]      ; eax = adresse de la 2ème
                                     ; fonction virtuelle dans la vftable
.text:00401C2C call eax              ; appel de la fonction virtuelle
```

Les **fonctions membres non virtuelles** peuvent être identifiées en vérifiant si le pointeur `this` est passé en tant que paramètre caché à l’appel de fonction :

```asm
.text:00401AFC push 0CCh
.text:00401B01 lea ecx, [ebp+var_C] ; ecx = pointeur this
.text:00401B04 call sub_401110
```

Pour s’assurer qu’il s’agit bien d’une **fonction membre**, on peut vérifier si la fonction appelée utilise le registre `ecx` sans l’avoir initialisé auparavant.\
Jetons un œil au code de `sub_401110` :

```asm
.text:00401110 push ebp
.text:00401111 mov ebp, esp
.text:00401113 push ecx
.text:00401114 mov [ebp+var_4], ecx ; ecx est utilisé
```

***
