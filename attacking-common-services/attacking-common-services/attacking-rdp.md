# Attacking RDP

***

[**Remote Desktop Protocol (RDP)**](https://en.wikipedia.org/wiki/Remote_Desktop_Protocol) is a proprietary protocol developed by Microsoft which provides a user with a graphical interface to connect to another computer over a network connection. It is also one of the most popular administration tools,

By default, RDP uses **port `TCP/3389`**. Using `Nmap`, we can identify the available RDP service on the target host:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# nmap -Pn -p3389 192.168.2.143 

```
{% endcode %}

***

### <mark style="color:blue;">Misconfigurations</mark>

Since RDP takes user credentials for authentication, one common attack vector against the RDP protocol is password guessing. Although it is not common, we could find an RDP service without a password if there is a misconfiguration.

`Password Spraying`. This technique works by attempting a single password for many usernames before trying another password, being careful to avoid account lockout.

Using the [Crowbar](https://github.com/galkan/crowbar) tool, we can perform a password spraying attack against the RDP service.&#x20;

```shell-session
mrroboteLiot@htb[/htb]# cat usernames.txt 

```

#### <mark style="color:green;">**Crowbar - RDP Password Spraying**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
```
{% endcode %}

We can also use `Hydra` to perform an RDP password spray attack.

#### <mark style="color:green;">**Hydra - RDP Password Spraying**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```
{% endcode %}

We can RDP into the target system using the `rdesktop` client or `xfreerdp` client with valid credentials.

#### <mark style="color:green;">**RDP Login**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# rdesktop -u admin -p password123 192.168.2.143

```
{% endcode %}

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-7-2.png)

***

### <mark style="color:blue;">Protocol Specific Attacks</mark>

Let's imagine we successfully gain access to a machine and have an account with local administrator privileges. If a user is connected via RDP to our compromised machine, we can hijack the user's remote desktop session to escalate our privileges and impersonate the account. In an Active Directory environment, this could result in us taking over a Domain Admin account or furthering our access within the domain.

<mark style="color:green;">**RDP Session Hijacking**</mark>

As shown in the example below, we are logged in as the user `juurena` (UserID = 2) who has `Administrator` privileges. Our goal is to hijack the user `lewen` (User ID = 4), who is also logged in via RDP.

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-1-2.png)

To successfully impersonate a user without their password, we need to have `SYSTEM` privileges and use the Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) binary that enables users to connect to another desktop session. It works by specifying which `SESSION ID` (`4` for the `lewen` session in our example) we would like to connect to which session name (`rdp-tcp#13`, which is our current session). So, for example, the following command will open a new console as the specified `SESSION_ID` within our current RDP session:

```cmd-session
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

If we have local administrator privileges, we can use several methods to obtain `SYSTEM` privileges, such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or [Mimikatz](https://github.com/gentilkiwi/mimikatz).&#x20;

A simple trick is to create a Windows service that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges. We will use [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) binary. First, we specify the service name (`sessionhijack`) and the `binpath`, which is the command we want to execute. Once we run the following command, a service named `sessionhijack` will be created.

{% code fullWidth="true" %}
```cmd-session
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```
{% endcode %}

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-2-2.png)

To run the command, we can start the `sessionhijack` service :

```cmd-session
C:\htb> net start sessionhijack
```

Once the service is started, a new terminal with the `lewen` user session will appear. With this new account, we can attempt to discover what kind of privileges it has on the network, and maybe we'll get lucky, and the user is a member of the Help Desk group with admin rights to many hosts or even a Domain Admin.

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-3-2.png)

_Note: This method no longer works on Server 2019._

{% hint style="info" %}
L'attaque décrite ici utilise la commande `tscon.exe` pour s'approprier une session utilisateur active via une élévation de privilèges. L'idée est de s'imprégner du **contexte d'un autre utilisateur**, en accédant à leur session sans avoir besoin de connaître leur mot de passe, mais pour cela, il faut des **privilèges SYSTÈME**.

Voyons les concepts clés :

1\. **Privilèges Système (SYSTEM Privileges)**

* **Privilèges Système** sont les privilèges les plus élevés sur un système Windows. Ils permettent d'exécuter des commandes avec des droits d'administrateur système (LocalSystem). Les utilisateurs ayant des privilèges système peuvent effectuer presque toutes les actions sur un ordinateur, y compris l'accès à des informations sensibles et la gestion des sessions d'autres utilisateurs.
* En d'autres termes, **avoir des privilèges SYSTEM** signifie que vous êtes pratiquement tout-puissant sur l'ordinateur, capable de faire des actions même au-dessus de l'administrateur local.

2\. **Comment S'imprégner d'une Session avec `tscon.exe`**

* `tscon.exe` est une commande permettant de se connecter à une autre session d'un utilisateur sur un poste distant ou local, généralement dans un environnement Terminal Server ou RDP (Remote Desktop Protocol).
* Avec **les privilèges SYSTEM**, vous pouvez utiliser cette commande pour vous connecter à une session RDP d'un autre utilisateur **sans avoir leur mot de passe**. Vous pouvez ensuite exécuter des actions dans cette session comme si vous étiez cet utilisateur.
*   **Exemple de commande :**

    ```bash
    tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
    ```

    * `TARGET_SESSION_ID` : ID de la session que vous souhaitez prendre (par exemple, `2` dans cet exemple).
    * `OUR_SESSION_NAME` : Le nom de la session actuelle à partir de laquelle vous vous connectez (par exemple, `rdp-tcp#13`).

3\. **Élévation de Privilèges pour Atteindre SYSTEM**

* Pour **s'imprégner d'une session**, il est nécessaire de disposer de **privilèges SYSTEM**. Si vous avez **des privilèges d'administrateur local**, il existe des moyens d'augmenter vos privilèges jusqu'au niveau SYSTEM.
  * **Utilisation de PsExec ou Mimikatz** : Ce sont des outils puissants qui permettent d'exécuter des commandes avec des privilèges SYSTEM sur un poste local.
  * **Méthode simple : Créer un service Windows** qui s'exécute sous **LocalSystem** et utilise un **binaire avec privilèges SYSTEM** pour exécuter une commande (comme `cmd.exe`).

#### 4. **Créer un Service Windows pour Utiliser `tscon.exe`**

* L'attaque consiste à **créer un service** qui va s'exécuter en tant que **LocalSystem**, et qui utilisera la commande `tscon.exe` pour se connecter à une session RDP d'un autre utilisateur.
*   Exemple de commande pour créer un service Windows :

    {% code overflow="wrap" %}
    ```bash
    sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
    ```
    {% endcode %}

    * Cette commande crée un service nommé `sessionhijack` qui, une fois démarré, exécutera `tscon` pour se connecter à la session de l'utilisateur avec l'ID 2 (`rdp-tcp#14`), et rediriger cette session vers la session `rdp-tcp#13`.

5\. **Démarrer le Service et Accéder à la Session**

*   Une fois que le service est créé, il faut **démarrer le service** pour qu'il exécute la commande :

    ```bash
    net start sessionhijack
    ```
* Cela ouvrira un **nouveau terminal** avec la session de l'utilisateur ciblé (dans cet exemple, l'utilisateur `lewen` dans la session `rdp-tcp#14`).
{% endhint %}

***

### <mark style="color:blue;">RDP Pass-the-Hash (PtH)</mark>

There are a few caveats to this attack:

* `Restricted Admin Mode`, which is disabled by default, should be enabled on the target host; otherwise, we will be prompted with the following error:

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-4.png)

This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG\_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`. It can be done using the following command:

<mark style="color:green;">**Adding the DisableRestrictedAdmin Registry Key**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
{% endcode %}

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-5.png)

Once the registry key is added, we can use `xfreerdp` with the option `/pth` to gain RDP access:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB

```
{% endcode %}

If it works, we'll now be logged in via RDP as the target user without knowing their cleartext password.

![](https://academy.hackthebox.com/storage/modules/116/rdp_session-6-2.png)

***

{% hint style="info" %}
<mark style="color:orange;">**Vulnérabilités RDP (BlueKeep - CVE-2019-0708)**</mark>

***

**1. Présentation de la Vulnérabilité**

* **Nom de la Vulnérabilité :** BlueKeep
* **Identifiant CVE :** CVE-2019-0708
* **Type :** Exécution de code à distance (RCE)
* **Service Affecté :** Remote Desktop Protocol (RDP - TCP/3389)
* **Date de Publication :** 2019
* **Gravité :** Critique
* **Méthode d’exploitation :** Ne nécessite aucune authentification préalable
* **Technique Utilisée :** Use-After-Free (UAF)

***

**2. Concept de l’Attaque**

* **Principe :** Manipulation de requêtes envoyées au service RDP pour exploiter une faille dans la gestion de la mémoire.
* **Dangerosité :** Aucun besoin d'authentification. L'attaque se produit lors de l'initialisation de la connexion entre le client et le serveur.
* **Conséquence :** Exécution de code arbitraire avec des privilèges SYSTEM, pouvant mener à l’installation de malwares ou ransomwares.

**Cibles principales :**

* **Organisations sensibles** (hôpitaux, infrastructures critiques) avec des logiciels dépendants de versions obsolètes de Windows.

***

**3. Déroulement de l’Attaque (BlueKeep Exploit)**

**Phase 1 : Initialisation et Exploitation**

1. **Source :** L'attaquant envoie une requête modifiée lors de l'échange initial des paramètres entre le client et le serveur.
2. **Processus :** Cette requête exploite une fonction vulnérable lors de la création d'un canal virtuel.
3. **Privilèges :** Le service RDP tourne avec les privilèges SYSTEM.
4. **Destination :** La fonction manipulée réoriente vers un processus en mode noyau (kernel), déclenchant la vulnérabilité.

***

**Phase 2 : Exécution de Code à Distance (RCE)**

5. **Source :** L'attaquant injecte une charge utile (payload) pour libérer la mémoire du noyau.
6. **Processus :** Le noyau exécute la charge utile à la place du code initial.
7. **Privilèges :** Les instructions injectées s'exécutent avec des privilèges SYSTEM.
8. **Destination :** Un shell inverse (reverse shell) est envoyé à la machine de l'attaquant, permettant un accès complet.

***

**4. Conséquences de l'Attaque**

* **Infiltration de malwares/ransomwares**
* **Contrôle total du système**
* **Mouvement latéral** (attaques sur d'autres machines du réseau)
* **Vol de données sensibles**

***

**5. Protection et Mitigation**

* **Correctifs Disponibles :** Microsoft a publié des patchs pour les versions supportées et non supportées de Windows.
* **Mises à jour critiques :** Installer les correctifs de sécurité pour CVE-2019-0708 sans délai.
* **Désactiver RDP :** Si non nécessaire, désactiver le service RDP.
* **Limiter les connexions RDP :** Restreindre l'accès à RDP via VPN ou IPs de confiance.
* **Segmentation du Réseau :** Séparer les machines critiques et limiter leur exposition.

***

**6. Statistiques et Impact**

* **Nombre de Systèmes Vulnérables en Mai 2019 :** 950,000
* **Systèmes Encore Vulnérables en 2024 :** Environ 25% (près de 237,500)

***

**7. Références Utiles**

* **Site Microsoft Security :** https://portal.msrc.microsoft.com
* **Patch de Sécurité :** KB4499175 (Windows 7), KB4499180 (Windows Server 2008 R2)
* **Exploitation Technique :** Recherche BlueKeep Exploit sur GitHub et d'autres plateformes de cybersécurité.
{% endhint %}
