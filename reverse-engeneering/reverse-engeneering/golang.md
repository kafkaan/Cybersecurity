---
description: https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/
---

# Golang

{% embed url="https://re.kv.io/crackme/15.html" %}

{% embed url="https://github.com/strazzere/golang_loader_assist/blob/master/golang_loader_assist.py#L361" %}

## <mark style="color:red;">📘 Reversing des binaires Go avec IDA Pro</mark>

### <mark style="color:blue;">Chapitre 1 – Introduction</mark>

Le langage **Go (Golang)** est de plus en plus utilisé, notamment pour écrire des programmes système, des outils réseau et même des malwares modernes. Mais analyser un binaire Go compilé est très différent de l’analyse d’un binaire C ou C++ :

* Les binaires Go sont massifs, car ils embarquent tout le runtime Go.
* Même un simple programme `Hello, World!` peut contenir **plus de 1000 fonctions** détectées par IDA Pro.
* Beaucoup de ces fonctions appartiennent au **runtime** et ne sont pas pertinentes pour l’analyste.

👉 Exemple : Un programme Go trivial :

```go
package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}
```

Dans IDA Pro, un tel binaire (non strippé) peut montrer **2058 fonctions**, alors que notre code source n’en définit qu’une seule ! Cela illustre la complexité et le bruit introduit par le runtime Go.

#### Différence entre binaire avec symboles et binaire strip

* **Non strippé** : on retrouve des noms utiles (`main.main`, `fmt.Println`…), IDA détecte beaucoup de fonctions.
* **Strippé** (`go build -ldflags "-s"`) : beaucoup moins de fonctions reconnues (ex. 1329 au lieu de 2058), et les noms disparaissent (`sub_xxxx`).

C’est ici que nos techniques et scripts deviennent indispensables.

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

***

### Chapitre 2 – Structure des binaires Go

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

#### La fonction `main.main`

En Go, la vraie fonction principale s’appelle **`main.main`**. La fonction `main()` que l’on écrit est transformée par le compilateur.

Dans le binaire, `main()` est presque vide : elle appelle en fait `main.main`.

#### Le rôle de `runtime_morestack`

Chaque fonction Go contient en fin de code un bloc pour vérifier la pile :

```asm
call    runtime_morestack_noctxt
jmp     <début_de_la_fonction>
```

👉 Cela permet au runtime de vérifier si la pile est suffisante.

➡ Cet idiome est précieux pour délimiter les fonctions et les reconstruire.

#### La section `.gopclntab`

Go stocke dans son exécutable une table spéciale **`.gopclntab`** :

* Elle contient les adresses de fonctions et leurs noms.
* Même dans un binaire strip, cette section reste présente.
* Exemple : on peut y trouver directement la chaîne `main.main`.

👉 C’est la clé pour **restaurer automatiquement les noms de fonctions**.

#### Les chaînes de caractères Go

* Go stocke toutes ses chaînes dans une table unique.
* Elles ne sont **pas terminées par `\0`** comme en C.
* Chaque chaîne est représentée par une paire `(adresse, longueur)`.
* Les chaînes sont triées par **longueur** puis par **ordre alphabétique**.

Cela explique pourquoi on retrouve souvent un motif de trois instructions `mov` consécutives lors du chargement d’une chaîne :

```asm
mov     ebx, offset aHelloWorld ; adresse de la chaîne
mov     [esp+..], ebx           ; stockage de l’adresse
mov     [esp+..], 0Dh           ; stockage de la longueur (0x0D = 13)
```

***

### <mark style="color:blue;">Chapitre 3 – Analyse pratique avec IDA Pro</mark>

#### Exemple non strippé

* 2058 fonctions reconnues.
* On voit clairement `main.main` et d’autres noms utiles.
* Les chaînes sont présentes dans la section `.rodata`.

#### Exemple strippé

* 1329 fonctions reconnues.
* Tous les noms remplacés par `sub_xxxx`.
* Pourtant, la section `.gopclntab` contient toujours les noms !

👉 Avec les bons scripts, on peut restaurer une grande partie de la lisibilité.

***

### <mark style="color:blue;">Chapitre 4 – Scripts IDA (commentés)</mark>

#### 4.1 Script `renamer.py`

But : Lire la section `.gopclntab` et renommer les fonctions.

Principe :

* Sauter l’en-tête (8 octets).
* Lire la taille de la table.
* Pour chaque entrée : récupérer (adresse fonction, offset nom).
* Lire la chaîne du nom et appliquer `MakeName`.

Extrait commenté :

```python
addr = start_gopclntab + 8          # on saute l'en-tête
size = Dword(addr)                  # nombre d'entrées
addr += 4

while addr < end:
    func_offset = Dword(addr)       # adresse de la fonction
    name_offset = Dword(addr+4)     # offset du nom
    addr += 8

    func_name_addr = start_gopclntab + name_offset + 4
    func_name = GetString(func_name_addr)
    
    MakeStr(func_name_addr, func_name_addr + len(func_name))
    MakeName(func_offset, func_name)
```

👉 Après exécution, `sub_80483F0` redevient `main.main`, etc.

***

#### 4.2 Script `find_runtime_morestack.py`

But : Identifier la fonction spéciale `runtime_morestack`.

Principe :

* Chercher l’instruction unique `mov [ds:0x1003], 0` dans le segment `.text`.
* Remonter pour trouver le début de la fonction.
* Renommer en `runtime_morestack`.

👉 Une fois localisée, on peut explorer ses références croisées pour reconstruire d’autres fonctions.

***

#### 4.3 Script `traverse_functions.py`

But : Définir toutes les fonctions manquantes.

Principe :

* Parcourir toutes les références vers `runtime_morestack`.
* Juste après chaque `call`, on s’attend à un `jmp <début_fonction>`.
* Délimiter la fonction entre `<début_fonction>` et ce `jmp`.
* Créer la fonction avec `MakeFunction`.

👉 Cela complète la couverture des fonctions Go, même celles qu’IDA n’avait pas détectées.

***

#### 4.4 Script `string_hunting.py`

But : Recréer toutes les chaînes Go.

Principe :

* Parcourir les instructions.
* Identifier le motif `mov adresse`, `mov pile`, `mov longueur`.
* Créer la chaîne avec `MakeStr(adresse, adresse+longueur)`.

Exemple :

```asm
mov ebx, offset aHelloWorld
mov [esp+..], ebx
mov [esp+..], 0Dh   ; longueur = 13
```

👉 Produit la chaîne « Hello, World! » dans IDA.

***

### <mark style="color:blue;">Chapitre 5 – Mise en commun :</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`golang_loader_assist.py`</mark>

Tous ces scripts sont intégrés dans un seul outil : **golang\_loader\_assist**.

* `renamer` → noms des fonctions depuis `.gopclntab`.
* `find_runtime_morestack` → localisation du runtime.
* `traverse_functions` → reconstruction des fonctions.
* `string_hunting` → restauration des chaînes.

Résultat dans IDA :

* Les fonctions récupèrent leurs vrais noms.
* Les chaînes apparaissent correctement.
* L’analyse devient lisible et exploitable.

***

### <mark style="color:blue;">Chapitre 6 – Résumé pratique</mark>

Sans outils :

* 1000+ fonctions anonymes (`sub_xxxx`).
* Pas de chaînes visibles.
* Analyse fastidieuse.

Avec scripts :

* Fonctions renommées (`main.main`, `fmt.Println`, etc.).
* Chaînes Go visibles.
* Fonctions manquantes recréées.
* Analyse fluide.

👉 Ces techniques sont **essentielles** pour le reverse engineering de binaires Go, en particulier sous Linux pour analyser des malwares ou des outils suspects écrits en Go.

***

✦ Fin du cours ✦
