---
description: >-
  https://medium.com/@mrbnf/password-attacks-credential-hunting-in-windows-5b899c3e58b1
---

# Credential Hunting in Windows

### <mark style="color:red;">Search Centric</mark>

Many of the tools available to us in Windows have search functionality. In this day and age, there are search-centric features built into most applications and operating systems, so we can use this to our advantage on an engagement. A user may have documented their passwords somewhere on the system. There may even be default credentials that could be found in various files. It would be wise to base our search for credentials on what we know about how the target system is being used. In this case, we know we have access to an IT admin's workstation.

`What might an IT admin be doing on a day-to-day basis & which of those tasks may require credentials?`

We can use this question & consideration to refine our search to reduce the need for random guessing as much as possible.

**Key Terms to Search**

Whether we end up with access to the GUI or CLI, we know we will have some tools to use for searching but of equal importance is what exactly we are searching for. Here are some helpful key terms we can use that can help us discover some credentials:

|               |              |             |
| ------------- | ------------ | ----------- |
| Passwords     | Passphrases  | Keys        |
| Username      | User account | Creds       |
| Users         | Passkeys     | Passphrases |
| configuration | dbcredential | dbpassword  |
| pwd           | Login        | Credentials |

Let's use some of these key terms to search on the IT admin's workstation.

***

### <mark style="color:red;">Search Tools</mark>

With access to the GUI, it is worth attempting to use `Windows Search` to find files on the target using some of the keywords mentioned above.

![Windows Search](https://academy.hackthebox.com/storage/modules/147/WindowsSearch.png)

By default, it will search various OS settings and the file system for files & applications containing the key term entered in the search bar.

We can also take advantage of third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store. It would be beneficial to keep a [standalone copy](https://github.com/AlessandroZ/LaZagne/releases/) of Lazagne on our attack host so we can quickly transfer it over to the target. `Lazagne.exe` will do just fine for us in this scenario. We can use our RDP client to copy the file over to the target from our attack host. If we are using `xfreerdp` all we must do is copy and paste into the RDP session we have established.

Once Lazagne.exe is on the target, we can open command prompt or PowerShell, navigate to the directory the file was uploaded to, and execute the following command:

<mark style="color:orange;">**Running Lazagne All**</mark>

```cmd-session
C:\Users\bob\Desktop> start lazagne.exe all
```

This will execute Lazagne and run `all` included modules. We can include the option `-vv` to study what it is doing in the background. Once we hit enter, it will open another prompt and display the results.

<mark style="color:orange;">**Lazagne Output**</mark>

```cmd-session
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```

If we used the `-vv` option, we would see attempts to gather passwords from all Lazagne's supported software. We can also look on the GitHub page under the supported software section to see all the software Lazagne will try to gather credentials from. It may be a bit shocking to see how easy it can be to obtain credentials in clear text. Much of this can be attributed to the insecure way many applications store credentials.

<mark style="color:orange;">**Using findstr**</mark>

We can also use [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr) to search from patterns across many types of files. Keeping in mind common key terms, we can use variations of this command to discover credentials on a Windows target:

```cmd-session
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

***

### <mark style="color:red;">Additional Considerations</mark>

Il existe des milliers d'outils et de termes clés que nous pouvons utiliser pour rechercher des identifiants sur les systèmes d'exploitation Windows. Sachez que le choix des outils dépendra principalement de la fonction de l'ordinateur. Si nous tombons sur un serveur Windows, nous pourrions utiliser une approche différente de celle que nous adopterions sur un poste de travail Windows. Il est important de toujours garder à l'esprit l'utilisation du système, car cela nous aidera à savoir où chercher. Parfois, nous pourrions même être capables de trouver des identifiants en naviguant et en listant les répertoires sur le système de fichiers pendant que nos outils fonctionnent.

Voici d'autres endroits où nous devrions être vigilants lors de la recherche de mots de passe :

* Mots de passe dans la stratégie de groupe dans le partage SYSVOL
* Mots de passe dans les scripts dans le partage SYSVOL
* Mots de passe dans les scripts sur les partages informatiques (IT)
* Mots de passe dans les fichiers web.config sur les machines de développement et les partages IT
* Fichier unattend.xml
* Mots de passe dans les champs de description des utilisateurs ou ordinateurs dans Active Directory
* Bases de données KeePass → extraire le hachage, cracker et obtenir un accès étendu
* Trouvés sur les systèmes et partages utilisateurs
* Fichiers tels que pass.txt, passwords.docx, passwords.xlsx trouvés sur les systèmes utilisateurs, partages, SharePoint

***
