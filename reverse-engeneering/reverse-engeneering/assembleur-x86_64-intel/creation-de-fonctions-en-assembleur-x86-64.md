# Création de Fonctions en Assembleur x86-64

***

### <mark style="color:blue;">🔍 Anatomie d'une fonction {#anatomie}</mark>

Une fonction en assembleur x86-64 suit cette structure :

```asm
nom_fonction:
    ; === PROLOGUE ===
    push rbp          ; Sauvegarder l'ancien frame pointer
    mov rbp, rsp      ; Nouveau frame pointer
    sub rsp, N        ; Allouer de l'espace pour variables locales
    
    ; Sauvegarder les registres callee-saved si nécessaire
    push rbx
    push r12
    ; ... autres registres
    
    ; === CORPS DE LA FONCTION ===
    ; Votre code ici
    
    ; === ÉPILOGUE ===
    ; Restaurer les registres callee-saved
    pop r12
    pop rbx
    ; ... autres registres
    
    mov rsp, rbp      ; Restaurer le stack pointer
    pop rbp           ; Restaurer l'ancien frame pointer
    ret               ; Retour à l'appelant
```

***

### <mark style="color:blue;">📜 Convention d'appel System V AMD64 {#convention}</mark>

#### <mark style="color:green;">🎯 Ordre des paramètres (premiers 6 entiers/pointeurs)</mark>

1. **RDI** - 1er paramètre
2. **RSI** - 2e paramètre
3. **RDX** - 3e paramètre
4. **RCX** - 4e paramètre
5. **R8** - 5e paramètre
6. **R9** - 6e paramètre
7. **Stack** - paramètres suivants (de droite à gauche)

#### <mark style="color:green;">🔢 Paramètres flottants (premiers 8)</mark>

* **XMM0-XMM7** pour les nombres flottants

#### <mark style="color:green;">💾 Classification des registres</mark>

**Caller-saved** (l'appelant doit sauvegarder) :

* RAX, RCX, RDX, RSI, RDI, R8-R11
* XMM0-XMM15

<mark style="color:green;">**Callee-saved**</mark> <mark style="color:green;"></mark><mark style="color:green;">(la fonction doit sauvegarder) :</mark>

* RBX, RBP, R12-R15
* Stack pointer (RSP)

#### <mark style="color:green;">📤 Valeur de retour</mark>

* **RAX** - entiers/pointeurs (64 bits max)
* **RDX:RAX** - entiers 128 bits
* **XMM0** - nombres flottants

***

### <mark style="color:blue;">🚪 Prologue et Épilogue {#prologue-epilogue}</mark>

#### <mark style="color:green;">🎬 Prologue Standard</mark>

```asm
ma_fonction:
    push rbp        ; Sauvegarder l'ancien frame pointer
    mov rbp, rsp    ; Établir le nouveau frame pointer
    sub rsp, 32     ; Allouer 32 octets pour variables locales
                    ; (toujours multiple de 16 pour alignement)
```

#### <mark style="color:green;">🎭 Épilogue Standard</mark>

```asm
    mov rsp, rbp    ; Libérer les variables locales
    pop rbp         ; Restaurer l'ancien frame pointer
    ret             ; Retourner à l'appelant
```

#### <mark style="color:green;">🎯 Prologue/Épilogue Simplifié (si pas de variables locales)</mark>

```asm
ma_fonction:
    push rbp
    mov rbp, rsp
    
    ; corps de la fonction
    
    pop rbp
    ret
```

***

### <mark style="color:blue;">📥 Gestion des paramètres {#parametres}</mark>

#### <mark style="color:green;">Exemple : fonction avec 3 paramètres</mark>

```asm
; int additionner(int a, int b, int c)
additionner:
    push rbp
    mov rbp, rsp
    
    ; a est dans RDI
    ; b est dans RSI  
    ; c est dans RDX
    
    add rdi, rsi    ; a + b
    add rdi, rdx    ; (a + b) + c
    mov rax, rdi    ; mettre le résultat dans RAX
    
    pop rbp
    ret
```

#### <mark style="color:green;">Exemple : plus de 6 paramètres</mark>

```asm
; int somme7(int a, int b, int c, int d, int e, int f, int g)
somme7:
    push rbp
    mov rbp, rsp
    
    ; a=RDI, b=RSI, c=RDX, d=RCX, e=R8, f=R9
    ; g est sur le stack à [rbp+16]
    
    add rdi, rsi
    add rdi, rdx
    add rdi, rcx
    add rdi, r8
    add rdi, r9
    add rdi, [rbp+16]   ; ajouter le 7e paramètre depuis le stack
    
    mov rax, rdi        ; résultat
    
    pop rbp
    ret
```

***

### <mark style="color:blue;">📤 Valeurs de retour {#retour}</mark>

#### <mark style="color:green;">Retour d'entier simple</mark>

```asm
get_answer:
    push rbp
    mov rbp, rsp
    
    mov rax, 42     ; retourner 42
    
    pop rbp
    ret
```

#### <mark style="color:green;">Retour de pointeur</mark>

```nasm
get_string:
    push rbp
    mov rbp, rsp
    
    mov rax, message    ; retourner l'adresse de 'message'
    
    pop rbp
    ret

section .data
    message db "Hello World", 0
```

#### <mark style="color:green;">Retour de structure (> 64 bits)</mark>

```nasm
; Pour structures > 64 bits, l'appelant passe un pointeur vers
; la zone où écrire le résultat (paramètre "caché" dans RDI)
get_large_struct:
    push rbp
    mov rbp, rsp
    
    ; RDI contient l'adresse où écrire le résultat
    ; RSI devient le 1er paramètre visible
    
    ; Écrire les données dans [RDI]
    mov qword [rdi], 123
    mov qword [rdi+8], 456
    
    mov rax, rdi    ; retourner l'adresse de la structure
    
    pop rbp
    ret
```

***

### <mark style="color:blue;">💾 Sauvegarde des registres {#sauvegarde}</mark>

#### <mark style="color:green;">Exemple complet avec sauvegarde</mark>

```asm
ma_fonction:
    push rbp
    mov rbp, rsp
    
    ; Sauvegarder les registres callee-saved qu'on va utiliser
    push rbx
    push r12
    push r13
    
    ; Corps de la fonction utilisant rbx, r12, r13
    mov rbx, rdi    ; utiliser rbx
    mov r12, rsi    ; utiliser r12
    ; ... calculs ...
    
    ; Restaurer dans l'ordre inverse
    pop r13
    pop r12
    pop rbx
    
    pop rbp
    ret
```

#### <mark style="color:green;">Optimisation : ne sauvegarder que ce qu'on utilise</mark>

```asm
fonction_simple:
    push rbp
    mov rbp, rsp
    
    ; On utilise que les registres caller-saved (RAX, RDI, RSI)
    ; Pas besoin de les sauvegarder
    
    mov rax, rdi
    add rax, rsi
    
    pop rbp
    ret
```

***

### <mark style="color:blue;">🏠 Variables locales {#variables-locales}</mark>

#### <mark style="color:green;">Allocation sur le stack</mark>

```nasm
fonction_avec_variables:
    push rbp
    mov rbp, rsp
    sub rsp, 32         ; Allouer 32 octets (4 variables de 8 octets)
    
    ; Accès aux variables locales :
    ; [rbp-8]  = 1ère variable locale
    ; [rbp-16] = 2e variable locale  
    ; [rbp-24] = 3e variable locale
    ; [rbp-32] = 4e variable locale
    
    mov qword [rbp-8], 100      ; var1 = 100
    mov qword [rbp-16], 200     ; var2 = 200
    
    mov rax, [rbp-8]            ; charger var1
    add rax, [rbp-16]           ; var1 + var2
    
    mov rsp, rbp        ; Libérer les variables locales
    pop rbp
    ret
```

#### <mark style="color:green;">Stack Frame complet</mark>

```nasm
Adresse     Contenu
---------   --------
[rbp+16]    Paramètre 7 (si existe)
[rbp+8]     Adresse de retour (placée par CALL)
[rbp]       Ancien RBP (placé par prologue)
[rbp-8]     1ère variable locale
[rbp-16]    2e variable locale
[rbp-24]    3e variable locale
[rbp-32]    4e variable locale
[rsp]       Sommet actuel du stack
```

***

### <mark style="color:blue;">🛠️ Exemples pratiques {#exemples}</mark>

#### <mark style="color:green;">1. Factorielle récursive</mark>

```nasm
; int factorial(int n)
factorial:
    push rbp
    mov rbp, rsp
    
    ; Cas de base : si n <= 1, retourner 1
    cmp rdi, 1
    jle base_case
    
    ; Cas récursif : n * factorial(n-1)
    push rdi            ; sauvegarder n
    dec rdi             ; n-1
    call factorial      ; factorial(n-1)
    pop rdi             ; restaurer n
    mul rdi             ; n * factorial(n-1)
    jmp end
    
base_case:
    mov rax, 1
    
end:
    pop rbp
    ret
```

#### <mark style="color:green;">2. Fonction avec tableau</mark>

```nasm
; int somme_tableau(int* tableau, int taille)
somme_tableau:
    push rbp
    mov rbp, rsp
    
    xor rax, rax        ; somme = 0
    xor rcx, rcx        ; i = 0
    
boucle:
    cmp rcx, rsi        ; comparer i avec taille
    jge fin             ; si i >= taille, sortir
    
    add eax, [rdi + rcx*4]  ; somme += tableau[i] (int = 4 octets)
    inc rcx             ; i++
    jmp boucle
    
fin:
    pop rbp
    ret
```

#### <mark style="color:green;">3. Fonction avec chaîne de caractères</mark>

```nasm
; int strlen_custom(char* str)
strlen_custom:
    push rbp
    mov rbp, rsp
    
    xor rax, rax        ; longueur = 0
    
boucle_strlen:
    cmp byte [rdi + rax], 0    ; comparer avec '\0'
    je fin_strlen              ; si c'est 0, terminer
    inc rax                    ; longueur++
    jmp boucle_strlen
    
fin_strlen:
    pop rbp
    ret
```

***

### <mark style="color:blue;">🚀 Fonctions avancées {#avancees}</mark>

#### <mark style="color:green;">1. Fonction avec nombre variable d'arguments</mark>

```asm
; int somme_variable(int count, ...)
somme_variable:
    push rbp
    mov rbp, rsp
    
    ; count est dans RDI
    ; Les arguments suivants sont dans RSI, RDX, RCX, R8, R9, puis stack
    
    xor rax, rax        ; somme = 0
    dec rdi             ; count-- (on a déjà traité le premier)
    
    cmp rdi, 0
    jle fin
    add rax, rsi        ; ajouter 2e arg
    
    dec rdi
    cmp rdi, 0
    jle fin
    add rax, rdx        ; ajouter 3e arg
    
    ; ... continuer pour RCX, R8, R9, puis parcourir le stack
    
fin:
    pop rbp
    ret
```

#### <mark style="color:green;">2. Fonction avec gestion d'erreurs</mark>

```asm
; int diviser_securise(int dividende, int diviseur, int* resultat)
; Retourne 0 si succès, -1 si erreur
diviser_securise:
    push rbp
    mov rbp, rsp
    
    ; Vérifier si diviseur == 0
    cmp rsi, 0
    je erreur_division
    
    ; Effectuer la division
    mov rax, rdi        ; dividende dans RAX
    cqo                 ; étendre le signe pour la division
    idiv rsi            ; diviser par RSI
    
    ; Stocker le résultat
    mov [rdx], rax      ; *resultat = quotient
    
    mov rax, 0          ; retourner 0 (succès)
    jmp fin_division
    
erreur_division:
    mov rax, -1         ; retourner -1 (erreur)
    
fin_division:
    pop rbp
    ret
```

#### <mark style="color:green;">3. Fonction optimisée (sans frame pointer)</mark>

```asm
; Version optimisée sans RBP pour de meilleures performances
addition_rapide:
    ; Pas de prologue/épilogue si pas nécessaire
    mov rax, rdi
    add rax, rsi
    ret                 ; Retour direct
```

***

### <mark style="color:blue;">✅ Checklist pour créer une fonction</mark>

1. **Nom et visibilité**
   * \[ ] Définir le nom de la fonction
   * \[ ] Ajouter `global nom_fonction` si exportée
2. **Prologue**
   * \[ ] `push rbp` et `mov rbp, rsp`
   * \[ ] `sub rsp, N` si variables locales nécessaires
   * \[ ] Sauvegarder les registres callee-saved utilisés
3. **Corps de la fonction**
   * \[ ] Lire les paramètres dans les bons registres
   * \[ ] Implémenter la logique
   * \[ ] Mettre le résultat dans RAX
4. **Épilogue**
   * \[ ] Restaurer les registres sauvegardés
   * \[ ] `mov rsp, rbp` et `pop rbp`
   * \[ ] `ret`
5. **Test et débogage**
   * \[ ] Vérifier l'alignement du stack
   * \[ ] Tester avec différents paramètres
   * \[ ] Vérifier les cas limites

***
