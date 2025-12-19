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

#### <mark style="color:green;">Différence entre binaire avec symboles et binaire strip</mark>

* **Non strippé** : on retrouve des noms utiles (`main.main`, `fmt.Println`…), IDA détecte beaucoup de fonctions.
* **Strippé** (`go build -ldflags "-s"`) : beaucoup moins de fonctions reconnues (ex. 1329 au lieu de 2058), et les noms disparaissent (`sub_xxxx`).

C’est ici que nos techniques et scripts deviennent indispensables.

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Chapitre 2 – Structure des binaires Go</mark>

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### <mark style="color:green;">La fonction</mark> <mark style="color:green;"></mark><mark style="color:green;">`main.main`</mark>

En Go, la vraie fonction principale s’appelle **`main.main`**. La fonction `main()` que l’on écrit est transformée par le compilateur.

Dans le binaire, `main()` est presque vide : elle appelle en fait `main.main`.

#### <mark style="color:green;">Le rôle de</mark> <mark style="color:green;"></mark><mark style="color:green;">`runtime_morestack`</mark>

Chaque fonction Go contient en fin de code un bloc pour vérifier la pile :

```asm
call    runtime_morestack_noctxt
jmp     <début_de_la_fonction>
```

👉 Cela permet au runtime de vérifier si la pile est suffisante.

➡ Cet idiome est précieux pour délimiter les fonctions et les reconstruire.

#### <mark style="color:green;">La section</mark> <mark style="color:green;"></mark><mark style="color:green;">`.gopclntab`</mark>

Go stocke dans son exécutable une table spéciale **`.gopclntab`** :

* Elle contient les adresses de fonctions et leurs noms.
* Même dans un binaire strip, cette section reste présente.
* Exemple : on peut y trouver directement la chaîne `main.main`.

👉 C’est la clé pour **restaurer automatiquement les noms de fonctions**.

#### <mark style="color:green;">Les chaînes de caractères Go</mark>

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

#### <mark style="color:green;">4.1 Script</mark> <mark style="color:green;"></mark><mark style="color:green;">`renamer.py`</mark>

But : Lire la section `.gopclntab` et renommer les fonctions.

Principe :

* Sauter l’en-tête (8 octets).
* Lire la taille de la table.
* Pour chaque entrée : récupérer (adresse fonction, offset nom).
* Lire la chaîne du nom et appliquer `MakeName`.

Extrait commenté :

```python
def create_pointer(addr, force_size=None):
    if force_size is not 4 and (idaapi.get_inf_structure().is_64bit() or force_size is 8):
        MakeQword(addr)
	return Qword(addr), 8
    else:
	MakeDword(addr)
	return Dword(addr), 4
STRIP_CHARS = [ '(', ')', '[', ']', '{', '}', ' ', '"' ]
REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/', '\xb7' ]
def clean_function_name(str):
    # Kill generic 'bad' characters
    str = filter(lambda x: x in string.printable, str)
    for c in STRIP_CHARS:
        str = str.replace(c, '')
    for c in REPLACE_CHARS:
        str = str.replace(c, '_')
    return str
def renamer_init():
    renamed = 0
    gopclntab = ida_segment.get_segm_by_name('.gopclntab')
    if gopclntab is not None:
        # Skip unimportant header and goto section size
        addr = gopclntab.startEA + 8
        size, addr_size = create_pointer(addr)
        addr += addr_size
        # Unsure if this end is correct
        early_end = addr + (size * addr_size * 2)
        while addr < early_end:
            func_offset, addr_size = create_pointer(addr)
            name_offset, addr_size = create_pointer(addr + addr_size)
            addr += addr_size * 2
            func_name_addr = Dword(name_offset + gopclntab.startEA + addr_size) + gopclntab.startEA
            func_name = GetString(func_name_addr)
            MakeStr(func_name_addr, func_name_addr + len(func_name))
            appended = clean_func_name = clean_function_name(func_name)
            debug('Going to remap function at 0x%x with %s - cleaned up as %s' % (func_offset, func_name, clean_func_name))
            if ida_funcs.get_func_name(func_offset) is not None:
                if MakeName(func_offset, clean_func_name):
                    renamed += 1
                else:
                    error('clean_func_name error %s' % clean_func_name)
    return renamed
def main():
    renamed = renamer_init()
    info('Found and successfully renamed %d functions!' % renamed
```

👉 Après exécution, `sub_80483F0` redevient `main.main`, etc.

***

#### <mark style="color:green;">4.2 Script</mark> <mark style="color:green;"></mark><mark style="color:green;">`find_runtime_morestack.py`</mark>

Nous connaissons maintenant le **début** des fonctions (grâce au parsing de `.gopclntab`), mais j’ai fini par trouver une méthode encore plus simple pour définir toutes les fonctions dans l’application.

On peut définir toutes les fonctions en utilisant **runtime\_morestack\_noctxt**.\
Comme **chaque fonction** appelle ceci (il existe effectivement un cas particulier, mais presque toutes l’appellent), si on trouve cette fonction et qu’on explore **toutes les références vers elle**, alors on trouvera l’adresse _de chaque fonction_ du binaire.

But : Identifier la fonction spéciale `runtime_morestack`.

Principe :

* Chercher l’instruction unique `mov [ds:0x1003], 0` dans le segment `.text`.
* Remonter pour trouver le début de la fonction.
* Renommer en `runtime_morestack`.

👉 Une fois localisée, on peut explorer ses références croisées pour reconstruire d’autres fonctions

{% code fullWidth="true" %}
```python
def is_simple_wrapper(addr):
    if GetMnem(addr) == 'xor' and GetOpnd(addr, 0) == 'edx' and  GetOpnd(addr, 1) == 'edx':
        addr = FindCode(addr, SEARCH_DOWN)
        if GetMnem(addr) == 'jmp' and GetOpnd(addr, 0) == 'runtime_morestack':
            return True
    return False
def create_runtime_ms():
    debug('Attempting to find runtime_morestack function for hooking on...')
    text_seg = ida_segment.get_segm_by_name('.text')
    # This code string appears to work for ELF32 and ELF64 AFAIK
    runtime_ms_end = ida_search.find_text(text_seg.startEA, 0, 0, "word ptr ds:1003h, 0", SEARCH_DOWN)
    runtime_ms = ida_funcs.get_func(runtime_ms_end)
    if idc.MakeNameEx(runtime_ms.startEA, "runtime_morestack", SN_PUBLIC):
        debug('Successfully found runtime_morestack')
    else:
        debug('Failed to rename function @ 0x%x to runtime_morestack' % runtime_ms.startEA)
    return runtime_ms
def traverse_xrefs(func):
    func_created = 0
    if func is None:
        return func_created
    # First
    func_xref = ida_xref.get_first_cref_to(func.startEA)
    # Attempt to go through crefs
    while func_xref != 0xffffffffffffffff:
        # See if there is a function already here
        if ida_funcs.get_func(func_xref) is None:
            # Ensure instruction bit looks like a jump
            func_end = FindCode(func_xref, SEARCH_DOWN)
            if GetMnem(func_end) == "jmp":
                # Ensure we're jumping back "up"
                func_start = GetOperandValue(func_end, 0)
                if func_start < func_xref:
                    if idc.MakeFunction(func_start, func_end):
                        func_created += 1
                    else:
                        # If this fails, we should add it to a list of failed functions
                        # Then create small "wrapper" functions and backtrack through the xrefs of this
                        error('Error trying to create a function @ 0x%x - 0x%x' %(func_start, func_end))
        else:
            xref_func = ida_funcs.get_func(func_xref)
            # Simple wrapper is often runtime_morestack_noctxt, sometimes it isn't though...
            if is_simple_wrapper(xref_func.startEA):
                debug('Stepping into a simple wrapper')
                func_created += traverse_xrefs(xref_func)
            if ida_funcs.get_func_name(xref_func.startEA) is not None and 'sub_' not in ida_funcs.get_func_name(xref_func.startEA):
                debug('Function @0x%x already has a name of %s; skipping...' % (func_xref, ida_funcs.get_func_name(xref_func.startEA)))
            else:
                debug('Function @ 0x%x already has a name %s' % (xref_func.startEA, ida_funcs.get_func_name(xref_func.startEA)))
        func_xref = ida_xref.get_next_cref_to(func.startEA, func_xref)
    return func_created
def find_func_by_name(name):
    text_seg = ida_segment.get_segm_by_name('.text')
    for addr in Functions(text_seg.startEA, text_seg.endEA):
        if name == ida_funcs.get_func_name(addr):
            return ida_funcs.get_func(addr)
    return None
def runtime_init():
    func_created = 0
    if find_func_by_name('runtime_morestack') is not None:
        func_created += traverse_xrefs(find_func_by_name('runtime_morestack'))
        func_created += traverse_xrefs(find_func_by_name('runtime_morestack_noctxt'))
    else:
        runtime_ms = create_runtime_ms()
        func_created = traverse_xrefs(runtime_ms)
    return func_created
```
{% endcode %}

***

#### <mark style="color:green;">4.3 Script</mark> <mark style="color:green;"></mark><mark style="color:green;">`traverse_functions.py`</mark>

But : Définir toutes les fonctions manquantes.

Principe :

* Parcourir toutes les références vers `runtime_morestack`.
* Juste après chaque `call`, on s’attend à un `jmp <début_fonction>`.
* Délimiter la fonction entre `<début_fonction>` et ce `jmp`.
* Créer la fonction avec `MakeFunction`.

👉 Cela complète la couverture des fonctions Go, même celles qu’IDA n’avait pas détectées.

***

#### <mark style="color:green;">4.4 Script</mark> <mark style="color:green;"></mark><mark style="color:green;">`string_hunting.py`</mark>

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

{% code fullWidth="true" %}
```python
# Currently it's normally ebx, but could in theory be anything - seen ebp
VALID_REGS = ['ebx', 'ebp']
# Currently it's normally esp, but could in theory be anything - seen eax
VALID_DEST = ['esp', 'eax', 'ecx', 'edx']
def is_string_load(addr):
    patterns = []
    # Check for first part
    if GetMnem(addr) == 'mov':
        # Could be unk_ or asc_, ignored ones could be loc_ or inside []
        if GetOpnd(addr, 0) in VALID_REGS and not ('[' in GetOpnd(addr, 1) or 'loc_' in GetOpnd(addr, 1)) and('offset ' in GetOpnd(addr, 1) or 'h' in GetOpnd(addr, 1)):
            from_reg = GetOpnd(addr, 0)
            # Check for second part
            addr_2 = FindCode(addr, SEARCH_DOWN)
            try:
                dest_reg = GetOpnd(addr_2, 0)[GetOpnd(addr_2, 0).index('[') + 1:GetOpnd(addr_2, 0).index('[') + 4]
            except ValueError:
                return False
            if GetMnem(addr_2) == 'mov' and dest_reg in VALID_DEST and ('[%s' % dest_reg) in GetOpnd(addr_2, 0) and GetOpnd(addr_2, 1) == from_reg:
                # Check for last part, could be improved
                addr_3 = FindCode(addr_2, SEARCH_DOWN)
                if GetMnem(addr_3) == 'mov' and (('[%s+' % dest_reg) in GetOpnd(addr_3, 0) or GetOpnd(addr_3, 0) in VALID_DEST) and 'offset ' not in GetOpnd(addr_3, 1) and 'dword ptr ds' not in GetOpnd(addr_3, 1):
                    try:
                        dumb_int_test = GetOperandValue(addr_3, 1)
                        if dumb_int_test > 0 and dumb_int_test < sys.maxsize:
                            return True
                    except ValueError:
                        return False
def create_string(addr, string_len):
    debug('Found string load @ 0x%x with length of %d' % (addr, string_len))
    # This may be overly aggressive if we found the wrong area...
    if GetStringType(addr) is not None and GetString(addr) is not None and len(GetString(addr)) != string_len:
        debug('It appears that there is already a string present @ 0x%x' % addr)
        MakeUnknown(addr, string_len, DOUNK_SIMPLE)
    if GetString(addr) is None and MakeStr(addr, addr + string_len):
        return True
    else:
        # If something is already partially analyzed (incorrectly) we need to MakeUnknown it
        MakeUnknown(addr, string_len, DOUNK_SIMPLE)
        if MakeStr(addr, addr + string_len):
            return True
        debug('Unable to make a string @ 0x%x with length of %d' % (addr, string_len))
    return False
```
{% endcode %}

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
