# Assembleur x86\_64 (Intel)

***

## <mark style="color:red;">🧾 Fiche de Révision – Assembleur x86\_64 (Intel)</mark>

***

### <mark style="color:blue;">📌</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Structure d’un fichier ASM (.nasm)**</mark>

{% code fullWidth="true" %}
```asm
global _start          ; Point d’entrée
;-------------------------------------------------
section .data          ; Déclaration des variables globaux
message: db "Hello",0xA

;-------------------------------------------------
section .text          ; Instructions du programme
_start:
    mov rax, 1         ; syscall write
    mov rdi, 1         ; stdout
    mov rsi, message   ; adresse de message
    mov rdx, 6         ; longueur du message
    syscall

    mov rax, 60        ; syscall exit
    xor rdi, rdi       ; code de retour 0
    syscall
```
{% endcode %}

***

### <mark style="color:blue;">🧠</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Registres principaux**</mark>

<table data-full-width="true"><thead><tr><th>Rôle</th><th>Registre(s)</th><th>Taille</th></tr></thead><tbody><tr><td>Valeur de retour</td><td><code>rax</code></td><td>64-bit</td></tr><tr><td>Arguments syscall/fonction</td><td><code>rdi</code>, <code>rsi</code>, <code>rdx</code>, <code>rcx</code>, <code>r8</code>, <code>r9</code></td><td>64-bit</td></tr><tr><td>Pointeur de pile (base)</td><td><code>rbp</code></td><td></td></tr><tr><td>Pointeur de pile (sommet)</td><td><code>rsp</code></td><td></td></tr><tr><td>Pointeur instruction</td><td><code>rip</code></td><td></td></tr></tbody></table>

***

### <mark style="color:blue;">🔍</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Sous-registres (selon taille)**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td>Taille</td><td>Exemple <code>rax</code></td><td>Exemple <code>rbx</code></td></tr><tr><td>64-bit</td><td><code>rax</code></td><td><code>rbx</code></td></tr><tr><td>32-bit</td><td><code>eax</code></td><td><code>ebx</code></td></tr><tr><td>16-bit</td><td><code>ax</code></td><td><code>bx</code></td></tr><tr><td>8-bit</td><td><code>al</code></td><td><code>bl</code></td></tr></tbody></table>

***

### <mark style="color:blue;">💬</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Instructions courantes**</mark>

<table data-full-width="true"><thead><tr><th>Instruction</th><th>Description</th></tr></thead><tbody><tr><td><code>mov dst, src</code></td><td>Copie une valeur</td></tr><tr><td><code>add rax, 1</code></td><td>Additionne</td></tr><tr><td><code>sub rax, 1</code></td><td>Soustrait</td></tr><tr><td><code>inc rax</code></td><td>Incrémente</td></tr><tr><td><code>dec rax</code></td><td>Décrémente</td></tr><tr><td><code>xor rax, rax</code></td><td>Met <code>rax</code> à 0</td></tr><tr><td><code>cmp rax, rbx</code></td><td>Compare</td></tr><tr><td><code>jmp label</code></td><td>Saut inconditionnel</td></tr><tr><td><code>je</code>, <code>jne</code>, <code>jg</code>, <code>jl</code></td><td>Sauts conditionnels</td></tr><tr><td><code>call label</code></td><td>Appel de fonction</td></tr><tr><td><code>ret</code></td><td>Retour de fonction</td></tr><tr><td><code>syscall</code></td><td>Appel système (Linux)</td></tr></tbody></table>

***

### <mark style="color:blue;">📥</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Déclaration de données**</mark>

<table data-full-width="true"><thead><tr><th>Mot-clé</th><th>Taille</th><th>Exemple</th></tr></thead><tbody><tr><td><code>db</code></td><td>1 octet</td><td><code>db "H"</code></td></tr><tr><td><code>dw</code></td><td>2 octets</td><td><code>dw 0x4142</code></td></tr><tr><td><code>dd</code></td><td>4 octets</td><td><code>dd 0x12345678</code></td></tr><tr><td><code>dq</code></td><td>8 octets</td><td><code>dq 0x1122334455667788</code></td></tr></tbody></table>

***

### <mark style="color:blue;">🔁</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Cycle d’instruction CPU**</mark>

```
Fetch  → Decode  → Execute  → Store
```

***

### <mark style="color:blue;">🏁</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Convention d’appel Linux x86\_64 (syscall)**</mark>

<table data-full-width="true"><thead><tr><th>Argument</th><th>Registre</th></tr></thead><tbody><tr><td>Numéro appel</td><td><code>rax</code></td></tr><tr><td>1er arg</td><td><code>rdi</code></td></tr><tr><td>2e arg</td><td><code>rsi</code></td></tr><tr><td>3e arg</td><td><code>rdx</code></td></tr><tr><td>4e arg</td><td><code>r10</code></td></tr><tr><td>5e arg</td><td><code>r8</code></td></tr><tr><td>6e arg</td><td><code>r9</code></td></tr></tbody></table>

**Exemple :**

```nasm
mov rax, 60     ; syscall: exit
xor rdi, rdi    ; status = 0
syscall
```

***

### <mark style="color:blue;">🔄</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Endianness (ordre des octets)**</mark>

* x86\_64 = **Little Endian**
* Stocke les octets **de droite à gauche**

Exemple :

```
push 0x68732f2f ; "//sh"
push 0x6e69622f ; "/bin"
```

***

### <mark style="color:blue;">⚙️</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Assembler & Exécuter**</mark>

<pre class="language-bash" data-full-width="true"><code class="lang-bash">nasm -f elf64 hello.asm -o hello.o
<strong>----------------------------------
</strong><strong>ld hello.o -o hello
</strong><strong>----------------------------------
</strong>./hello
</code></pre>

***

### <mark style="color:blue;">✏️</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Commentaires**</mark>

* Les commentaires se font avec `;`

```nasm
mov rax, 1     ; appel write
```

***

### <mark style="color:blue;">🔐</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Conseils Pentest / Exploit**</mark>

* Stack = `rsp`, `rbp`
* Shellcode = doit être **exécuté depuis `.text`**
* Éviter d’écrire dans `.text` ; `.data` ≠ exécutable
* Utiliser `xor reg, reg` pour nettoyer rapidement

***
