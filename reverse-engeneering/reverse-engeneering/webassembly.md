# WebAssembly

## WebAssembly et Reverse Engineering

### Table des Matières

1. Introduction à WebAssembly
2. Architecture et Concepts Fondamentaux
3. Format Binaire et Structure
4. Instructions WebAssembly
5. Outils de Reverse Engineering WASM
6. Techniques de Debugging
7. Analyse Statique vs Dynamique
8. Cas Pratique Détaillé
9. Techniques Avancées
10. Exercices et Challenges

***

### 1. Introduction à WebAssembly

#### Qu'est-ce que WebAssembly ?

WebAssembly (WASM) est un format d'instruction binaire pour une machine virtuelle basée sur une pile (stack-based virtual machine). Il a été conçu comme une cible de compilation portable pour les langages de haut niveau, permettant le déploiement d'applications client et serveur sur le web.

#### Caractéristiques Principales

* **Portabilité** : Fonctionne sur toutes les plateformes modernes
* **Performance** : Proche des performances natives
* **Sécurité** : Sandbox intégré
* **Compacité** : Format binaire optimisé
* **Interopérabilité** : Peut interagir avec JavaScript

#### Langages Sources Supportés

* C/C++
* Rust
* Go
* C#
* Python (via Pyodide)
* AssemblyScript (TypeScript-like)

***

### 2. Architecture et Concepts Fondamentaux

#### Machine Virtuelle Stack-Based

WebAssembly utilise une architecture basée sur une pile, contrairement aux processeurs traditionnels qui utilisent des registres.

**Pile d'Opérandes**

```wasm
;; Exemple : addition de deux nombres
i32.const 10    ;; Empile 10
i32.const 20    ;; Empile 20
i32.add         ;; Dépile 20 et 10, empile 30
```

#### Modèle Mémoire

* **Mémoire linéaire** : Un seul espace d'adressage continu
* **Pages de 64KB** : La mémoire est organisée en pages
* **Croissance contrôlée** : La mémoire peut grandir mais pas se réduire

#### Types de Données

* `i32` : Entier 32 bits
* `i64` : Entier 64 bits
* `f32` : Flottant 32 bits (IEEE 754)
* `f64` : Flottant 64 bits (IEEE 754)

***

### 3. Format Binaire et Structure

#### Structure d'un Module WASM

Un module WebAssembly contient plusieurs sections :

**Sections Principales**

1. **Type Section** : Signatures des fonctions
2. **Import Section** : Fonctions importées
3. **Function Section** : Déclaration des fonctions
4. **Table Section** : Tables de références
5. **Memory Section** : Déclaration de la mémoire
6. **Global Section** : Variables globales
7. **Export Section** : Exports du module
8. **Code Section** : Corps des fonctions

**Format Binaire**

```
Magic Number: 0x00 0x61 0x73 0x6D (\0asm)
Version:      0x01 0x00 0x00 0x00
```

***

### 4. Instructions WebAssembly

#### Categories d'Instructions

**Instructions de Contrôle**

* `unreachable` : Trap inconditionnel
* `nop` : Pas d'opération
* `block` : Bloc structuré
* `loop` : Boucle structurée
* `if` : Condition
* `br` : Branchement
* `br_if` : Branchement conditionnel
* `call` : Appel de fonction
* `return` : Retour de fonction

**Instructions Paramétriques**

* `drop` : Supprime la valeur du sommet
* `select` : Sélection conditionnelle

**Instructions de Variables**

* `local.get` : Lire une variable locale
* `local.set` : Écrire une variable locale
* `local.tee` : Écrire et laisser sur la pile
* `global.get` : Lire une variable globale
* `global.set` : Écrire une variable globale

**Instructions Mémoire**

* `i32.load` : Charger 32 bits depuis la mémoire
* `i32.store` : Stocker 32 bits en mémoire
* `memory.size` : Taille de la mémoire
* `memory.grow` : Augmenter la mémoire

**Instructions Numériques**

```wasm
;; Arithmétique entière
i32.add, i32.sub, i32.mul
i32.div_s, i32.div_u  ;; Division signée/non-signée
i32.rem_s, i32.rem_u  ;; Reste signé/non-signé

;; Opérations bit à bit
i32.and, i32.or, i32.xor
i32.shl, i32.shr_s, i32.shr_u

;; Comparaisons
i32.eq, i32.ne
i32.lt_s, i32.lt_u, i32.gt_s, i32.gt_u
i32.le_s, i32.le_u, i32.ge_s, i32.ge_u

;; Conversions
i32.wrap_i64
i64.extend_i32_s, i64.extend_i32_u
```

***

### 5. Outils de Reverse Engineering WASM

#### 5.1 WABT (WebAssembly Binary Toolkit)

**Installation :**

```bash
git clone --recursive https://github.com/WebAssembly/wabt
cd wabt
make
```

**Outils Principaux :**

**wasm2wat**

Convertit un binaire WASM en format texte :

```bash
wasm2wat module.wasm -o module.wat
```

**wat2wasm**

Convertit le format texte en binaire :

```bash
wat2wasm module.wat -o module.wasm
```

**wasm-objdump**

Examine le contenu d'un module :

```bash
wasm-objdump -x module.wasm  # Headers
wasm-objdump -s module.wasm  # Toutes les sections
wasm-objdump -d module.wasm  # Désassemblage
```

**wasm-decompile**

Décompile en pseudo-C :

```bash
wasm-decompile module.wasm -o output.c
```

#### 5.2 Ghidra + Plugin WASM

**Installation du Plugin :**

1. Télécharger Ghidra
2. Télécharger le plugin : https://github.com/nneonneo/ghidra-wasm-plugin
3. Installer via Extensions → Install Extension

**Utilisation :**

* Ouvrir le fichier .wasm dans Ghidra
* Analyser automatiquement
* Explorer les fonctions dans le Symbol Tree

#### 5.3 Cetus

Outil similaire à Cheat Engine pour WASM :

```bash
git clone https://github.com/Qwokka/Cetus
```

#### 5.4 Chrome DevTools

**Activation du support WASM :**

1. Ouvrir DevTools (F12)
2. Settings → Experiments → "WebAssembly Debugging"
3. Redémarrer DevTools

***

### 6. Techniques de Debugging

#### 6.1 Debugging Dynamique avec Chrome

**Configuration de l'Environnement**

```html
<!DOCTYPE html>
<html>
<head>
    <script type="module">
        import init, { exported_function } from './pkg/module.js';
        
        async function run() {
            await init();
            // Votre code ici
        }
        run();
    </script>
</head>
</html>
```

**Points de Rupture (Breakpoints)**

1. Ouvrir DevTools → Sources
2. Naviguer vers le fichier .wasm
3. Cliquer sur l'adresse pour placer un breakpoint
4. Utiliser Ctrl+G pour aller à une adresse spécifique

**Inspection des Données**

**Stack Inspection :**

* Voir les valeurs sur la pile d'opérandes
* Observer les paramètres des instructions

**Memory Inspection :**

1. Aller dans Sources → Module → Memory
2. Cliquer sur l'icône RAM
3. Entrer l'adresse mémoire à inspecter

**Local Variables :**

* Voir les variables locales de la fonction
* Observer les pointeurs et valeurs

#### 6.2 Techniques de Debugging Avancées

**Modification du Code à la Volée**

```javascript
// Patcher une fonction WASM depuis JavaScript
const originalFunction = wasm.exported_function;
wasm.exported_function = function(...args) {
    console.log('Called with:', args);
    const result = originalFunction.apply(this, args);
    console.log('Result:', result);
    return result;
};
```

**Logging Personnalisé**

```javascript
// Injecter du logging dans le code WASM
const memory = new Uint8Array(wasm.memory.buffer);

function logMemory(address, length) {
    const data = memory.slice(address, address + length);
    console.log('Memory at', address.toString(16), ':', 
                Array.from(data).map(x => x.toString(16).padStart(2, '0')).join(' '));
}
```

***

### 7. Analyse Statique vs Dynamique

#### 7.1 Analyse Statique

**Avantages**

* Vue d'ensemble complète du programme
* Pas besoin d'exécution
* Peut révéler des chemins d'exécution cachés

**Techniques**

```bash
# Extraction des strings
strings module.wasm

# Analyse des sections
wasm-objdump -s module.wasm

# Décompilation
wasm-decompile module.wasm
```

**Exemple d'Analyse avec Ghidra**

```c
// Code décompilé typique
undefined4 check_password(int param_1) {
    int local_c = 0;
    while (local_c < 8) {
        if ((char)param_1[local_c] != "password"[local_c]) {
            return 0;
        }
        local_c = local_c + 1;
    }
    return 1;
}
```

#### 7.2 Analyse Dynamique

**Avantages**

* Voir l'exécution réelle
* Observer les données en temps réel
* Comprendre les algorithmes complexes

**Techniques**

* Breakpoints conditionnels
* Tracing d'exécution
* Modification de mémoire

***

### 8. Cas Pratique Détaillé

#### 8.1 Challenge WASM-Safe (Basé sur votre document)

**Analyse Initiale**

```javascript
// Structure du challenge
const checkFunction = () => {
    const part1 = document.getElementById('part-1').value;
    const part2 = document.getElementById('part-2').value;
    const part3 = parseInt(document.getElementById('part-3').value);
    
    const result = wasm.verify_flag(part2);
    // Analyse des résultats...
};
```

**Reverse Engineering - Partie 1**

**Objectif :** Trouver la valeur correcte pour le premier select

**Méthode :**

1. Localiser la fonction de vérification dans Ghidra
2. Identifier la comparaison de chaînes
3. Extraire la chaîne de référence

**Code WASM (format texte) :**

```wasm
(func $verify_part_one
  (local $0 i32)
  (local $1 i32)
  
  ;; Charger l'adresse de la chaîne de référence
  i32.const 1024
  local.set $1
  
  ;; Boucle de comparaison
  (loop $label$1
    local.get $0
    local.get $1
    i32.load8_u
    i32.const 87  ;; 'W'
    i32.eq
    br_if $label$2
    ;; ... suite de la logique
  )
)
```

**Solution :** "W4sm"

**Reverse Engineering - Partie 2**

**Objectif :** Trouver une chaîne de 18 caractères

**Analyse du Pattern :**

```wasm
;; Vérification de longueur
local.get $input_length
i32.const 18  ;; 0x12 en hexadécimal
i32.ne
br_if $error

;; Logique XOR et comparaison
local.get $index
i32.const 1
i32.and  ;; Test pair/impair
i32.eqz
if $even
  ;; Traitement pour index pair
else
  ;; Traitement pour index impair
end
```

**Méthode de Résolution :**

1. Placer des breakpoints aux comparaisons
2. Itérer caractère par caractère
3. Observer les valeurs comparées sur la pile

**Solution :** "isamagicalb0xth4ts"

**Reverse Engineering - Partie 3**

**Objectif :** Trouver la valeur numérique correcte

**Analyse Mathématique :**

```wasm
;; Transformation de l'input
local.get $input
i32.const 3
i32.mul
i32.const 93
i32.add
local.set $transformed

;; Comparaison finale
local.get $transformed
i32.const 4107  ;; 0x100b
i32.eq
```

**Calcul :**

```
transformed = input * 3 + 93
4107 = input * 3 + 93
input = (4107 - 93) / 3 = 1338
```

**Solution :** 1338

#### 8.2 Techniques d'Optimisation du Reverse

**Script d'Automatisation**

```python
# Script pour automatiser l'extraction de chaînes
import struct

def extract_strings(wasm_file, min_length=4):
    with open(wasm_file, 'rb') as f:
        data = f.read()
    
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # Caractères imprimables
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    return strings
```

**Patcher WASM**

```python
# Modification du binaire WASM
def patch_wasm(file_path, offset, new_bytes):
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())
    
    data[offset:offset+len(new_bytes)] = new_bytes
    
    with open(file_path + '_patched', 'wb') as f:
        f.write(data)
```

***

### 9. Techniques Avancées

#### 9.1 Anti-Debug et Contournement

**Détection de Debugging**

```wasm
;; Technique de timing pour détecter le debugging
(func $anti_debug
  (local $start i64)
  (local $end i64)
  
  call $get_time
  local.set $start
  
  ;; Code sensible
  nop
  nop
  nop
  
  call $get_time
  local.set $end
  
  local.get $end
  local.get $start
  i64.sub
  i64.const 1000  ;; Seuil de temps
  i64.gt_u
  if
    ;; Debugging détecté
    call $exit
  end
)
```

**Contournement**

* Patcher les vérifications de timing
* Utiliser des breakpoints conditionnels
* Modifier la mémoire en temps réel

#### 9.2 Obfuscation et Déobfuscation

**Techniques d'Obfuscation Courantes**

* **Control Flow Flattening** : Transformation du flux de contrôle
* **String Encryption** : Chiffrement des chaînes
* **Dead Code Insertion** : Ajout de code inutile
* **Instruction Substitution** : Remplacement d'instructions simples par des complexes

**Exemple de Déobfuscation**

```python
# Déchiffrement XOR simple
def decrypt_xor_string(encrypted_data, key):
    decrypted = []
    for i, byte in enumerate(encrypted_data):
        decrypted.append(byte ^ key[i % len(key)])
    return bytes(decrypted)
```

#### 9.3 Analyse de Malwares WASM

**Vecteurs d'Attaque**

* **Cryptomining** caché dans les pages web
* **Data Exfiltration** via WebAssembly
* **Browser Exploitation** utilisant les vulnérabilités WASM

**Techniques de Détection**

```javascript
// Monitoring des appels de fonctions sensibles
const originalFetch = window.fetch;
window.fetch = function(...args) {
    console.log('Fetch called with:', args);
    return originalFetch.apply(this, args);
};

// Monitoring de l'utilisation CPU
let cpuUsage = 0;
setInterval(() => {
    const start = performance.now();
    // Tâche de référence
    const end = performance.now();
    cpuUsage = end - start;
    if (cpuUsage > threshold) {
        console.warn('High CPU usage detected');
    }
}, 1000);
```

***
