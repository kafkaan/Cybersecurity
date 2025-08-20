# FICHE REGISTRES

***

## <mark style="color:red;">🧠 Fiche des Registres x86\_64 & Flags</mark>

***

### <mark style="color:blue;">📦 Registres Généraux (GPR – General Purpose Registers)</mark>

<table data-full-width="true"><thead><tr><th>Registre</th><th>Description</th><th>Exemple d’usage</th></tr></thead><tbody><tr><td><code>rax</code></td><td>Accumulateur principal</td><td>Résultat d’une addition/multiplication</td></tr><tr><td><code>rbx</code></td><td>Base register (stockage temporaire)</td><td>Stocke une valeur pour traitement</td></tr><tr><td><code>rcx</code></td><td>Compteur (loop, shift, rep)</td><td><code>mov rcx, 10</code> pour boucle</td></tr><tr><td><code>rdx</code></td><td>Données/Division/IO</td><td>Reste après division, argument syscall</td></tr><tr><td><code>rsi</code></td><td>Source index</td><td>Source d’un <code>movs</code>, 2ᵉ argument syscall</td></tr><tr><td><code>rdi</code></td><td>Destination index</td><td>Destination d’un <code>movs</code>, 1ᵉʳ argument syscall</td></tr><tr><td><code>rsp</code></td><td>Stack Pointer</td><td>Pointeur de pile (stack)</td></tr><tr><td><code>rbp</code></td><td>Base Pointer</td><td>Base de la pile (pour frame stack)</td></tr><tr><td><code>r8</code> à <code>r15</code></td><td>Registres supplémentaires</td><td>Utilisation libre ou pour arguments syscalls (Linux)</td></tr></tbody></table>

🧠 Chaque registre 64 bits (`rax`) a ses versions :

* 32 bits → `eax`
* 16 bits → `ax`
* 8 bits → `al` (low) / `ah` (high)

***

### <mark style="color:blue;">🧪 Exemple simple d’usage</mark>

```nasm
mov rax, 5       ; rax = 5
mov rbx, 2       ; rbx = 2
add rax, rbx     ; rax = rax + rbx => 7
```

***

### <mark style="color:blue;">🔁 Registres spéciaux de boucle</mark>

| Registre | Utilisation                                    |
| -------- | ---------------------------------------------- |
| `rcx`    | Utilisé par `loop`, `rep`, `repe`, `repne`     |
| `rsi`    | Pointeur source pour opérations de chaîne      |
| `rdi`    | Pointeur destination pour opérations de chaîne |

***

### <mark style="color:blue;">📡 Registres système / conventions appel (Linux x86\_64)</mark>

| Ordre | Registre       | Description              |
| ----- | -------------- | ------------------------ |
| 1ᵉʳ   | `rdi`          | 1ᵉʳ argument             |
| 2ᵉ    | `rsi`          | 2ᵉ argument              |
| 3ᵉ    | `rdx`          | 3ᵉ argument              |
| 4ᵉ    | `rcx` ou `r10` | 4ᵉ argument              |
| 5ᵉ    | `r8`           | 5ᵉ argument              |
| 6ᵉ    | `r9`           | 6ᵉ argument              |
| ↩     | `rax`          | Code de retour / syscall |

***

#### 📞 Exemple appel système : write(1, msg, 13)

```nasm
mov rax, 1        ; syscall write
mov rdi, 1        ; STDOUT
mov rsi, msg      ; Adresse du buffer
mov rdx, 13       ; Taille
syscall
```

***

### 🧯 Registres de pile (`rsp`, `rbp`)

| Registre | Rôle                                  |
| -------- | ------------------------------------- |
| `rsp`    | Pointeur vers le sommet de la pile    |
| `rbp`    | Base du cadre d’appel (`stack frame`) |

```nasm
push rax    ; décrémente rsp de 8 et stocke rax
pop rbx     ; récupère ce qui est au sommet de la pile dans rbx
```

🧠 Utilisé en debug pour `backtrace`, appels imbriqués, etc.

***

### <mark style="color:blue;">🧨 FLAGS (EFLAGS / RFLAGS)</mark>

| Flag | Nom           | Rôle                                | Déclenché par        |
| ---- | ------------- | ----------------------------------- | -------------------- |
| `ZF` | Zero Flag     | Résultat = 0                        | `cmp`, `sub`, `test` |
| `SF` | Sign Flag     | Résultat négatif                    | Bit de signe = 1     |
| `CF` | Carry Flag    | Retenue binaire (overflow unsigned) | `add`, `sub`         |
| `OF` | Overflow Flag | Overflow arithmétique (signed)      | `add`, `sub`, `imul` |
| `PF` | Parity Flag   | Nombre pair de bits = 1             | Très peu utilisé     |
| `AF` | Adjust Flag   | Pour BCD (rare)                     | Binaire vers décimal |

***

#### 🧪 Exemples avec flags

**`cmp` : compare deux valeurs sans modifier les registres**

```nasm
cmp rax, rbx    ; rax - rbx, affecte les flags
je equal        ; saute si ZF = 1 (equal)
jg greater      ; saute si rax > rbx (ZF=0 && SF=OF)
jl lower        ; saute si rax < rbx (SF != OF)
```

***

### <mark style="color:blue;">🔁 Résumé instructions de saut conditionnel</mark>

| Instruction   | Condition (signée)        | Test          |
| ------------- | ------------------------- | ------------- |
| `je` / `jz`   | égal à                    | ZF = 1        |
| `jne` / `jnz` | pas égal                  | ZF = 0        |
| `jg` / `jnle` | supérieur                 | ZF=0 et SF=OF |
| `jge` / `jnl` | supérieur ou égal         | SF=OF         |
| `jl` / `jnge` | inférieur                 | SF≠OF         |
| `jle` / `jng` | inférieur ou égal         | ZF=1 ou SF≠OF |
| `jc`          | carry (overflow unsigned) | CF=1          |
| `jnc`         | no carry                  | CF=0          |

***

#### 🧪 Exemple complet : test conditionnel

```nasm
mov rax, 5
mov rbx, 3
cmp rax, rbx    ; met ZF=0, SF=0, OF=0
jg  is_greater  ; ZF=0 && SF=OF → OK
```

***

### <mark style="color:blue;">🧠 Notes utiles</mark>

* `xor reg, reg` → met le registre à 0 rapidement
* `xchg reg1, reg2` → échange deux registres sans registre temporaire
* `loop label` → décrémente `rcx`, saute si `rcx != 0`

***

### <mark style="color:blue;">📍 Exemple résumé : Boucle avec condition</mark>

```nasm
mov rcx, 5
start:
    ; instructions
    loop start      ; rcx -= 1 → saute si rcx ≠ 0
```

***

### <mark style="color:blue;">🧮 Mémo tailles registres</mark>

| Registre 64 bits | 32 bits | 16 bits | 8 bits     |
| ---------------- | ------- | ------- | ---------- |
| `rax`            | `eax`   | `ax`    | `al`, `ah` |
| `rbx`            | `ebx`   | `bx`    | `bl`, `bh` |
| `rcx`            | `ecx`   | `cx`    | `cl`, `ch` |
| `rdx`            | `edx`   | `dx`    | `dl`, `dh` |

***
