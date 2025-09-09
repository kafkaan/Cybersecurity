# Enumerating DNS Records

### <mark style="color:blue;">Enumerating DNS Records</mark>

* **But de l’outil** :\
  `adidnsdump` permet d’énumérer tous les enregistrements DNS d’un domaine Active Directory en utilisant un compte utilisateur valide du domaine.
* **Pourquoi c’est utile** :
  * Dans certains environnements, les noms de machines sont peu parlants (exemple : `SRV01934.INLANEFREIGHT.LOCAL`).
  * Avec les enregistrements DNS, on peut découvrir des noms plus descriptifs (ex : `JENKINS.INLANEFREIGHT.LOCAL`), ce qui aide à cibler des serveurs intéressants (Jenkins, Exchange, SQL, etc.).
* **Pourquoi ça marche** :
  * Par défaut, **tous les utilisateurs du domaine** ont le droit de lister les objets enfants d’une zone DNS dans Active Directory.
  * En interrogeant via LDAP standard, on n’obtient pas toujours tous les enregistrements.
* **Avantage d’adidnsdump** :\
  L’outil interroge la zone DNS de l’AD et retourne **l’ensemble des enregistrements DNS** disponibles, révélant potentiellement des cibles utiles pour l’attaque.

{% hint style="warning" %}
The background and more in-depth explanation of this tool and technique can be found in this [post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).
{% endhint %}

On the first run of the tool, we can see that some records are blank, namely `?,LOGISTICS,?`.

<mark style="color:green;">**Using adidnsdump**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records
```

<mark style="color:green;">**Viewing the Contents of the records.csv File**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ head records.csv 

type,name,value
?,LOGISTICS,?
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29
```

If we run again with the `-r` flag the tool will attempt to resolve unknown records by performing an `A` query. Now we can see that an IP address of `172.16.5.240` showed up for LOGISTICS. While this is a small example, it is worth running this tool in larger environments. We may uncover "hidden" records that can lead to discovering interesting hosts.

<mark style="color:green;">**Using the -r Option to Resolve Unknown Records**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
```

<mark style="color:green;">**Finding Hidden Records in the records.csv File**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ head records.csv 

type,name,value
A,LOGISTICS,172.16.5.240
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29
```
