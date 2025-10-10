---
cover: ../../../../.gitbook/assets/images.png
coverY: 0
layout:
  width: default
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# Microsoft SQL Server (MSSQL)

## <mark style="color:red;">**1. Introduction à MSSQL**</mark>

* <mark style="color:orange;">**MSSQL**</mark> (Microsoft SQL Server) est un <mark style="color:orange;">**système de gestion de bases de données relationnelles**</mark> (SGBDR) développé par Microsoft.
* Contrairement à MySQL, MSSQL est **propriétaire** et principalement conçu pour fonctionner sur les systèmes d'<mark style="color:orange;">**exploitation Windows**</mark>.
* Il est populaire parmi les administrateurs de bases de données et les développeurs travaillant sur le cadre .NET de Microsoft.
* Bien que des versions pour Linux et macOS existent, MSSQL est généralement rencontré sur des serveurs Windows.

***

### <mark style="color:red;">**2. Clients MSSQL**</mark>

* <mark style="color:orange;">**SQL Server Management Studio (SSMS)**</mark> : Outil graphique pour la gestion de bases de données. Il peut être installé séparément ou avec le package d'installation de MSSQL.
  * Utilisé pour la configuration initiale et la gestion à long terme des bases de données.
  * Peut être installé sur n'importe quelle machine, pas seulement sur le serveur hébergeant la base de données.
* **Autres clients MSSQL** :
  * <mark style="color:orange;">**mssql-cli**</mark> : Client interactif en ligne de commande.
  * <mark style="color:orange;">**SQL Server PowerShell**</mark> : Interface de script pour l'automatisation des tâches.
  * <mark style="color:orange;">**HeidiSQL**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">et</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**SQLPro**</mark> : Clients tiers pour gérer les bases de données.
  * <mark style="color:orange;">**mssqlclient.py**</mark> (Impacket) : Outil utilisé par les pentesters pour se connecter à MSSQL, souvent présent sur les distributions de tests d'intrusion.

***

## <mark style="color:red;">**3. Bases de données par défaut dans MSSQL**</mark>

MSSQL possède des bases de données système par défaut essentielles pour le fonctionnement du serveur SQL :

* <mark style="color:orange;">**master**</mark> : Gère toutes les informations système d'une instance SQL Server.
* <mark style="color:orange;">**model**</mark> : Base de modèle utilisée comme structure pour chaque nouvelle base de données créée.
* <mark style="color:orange;">**msdb**</mark> : Utilisée par SQL Server Agent pour la planification des tâches et des alertes.
* <mark style="color:orange;">**tempdb**</mark> : Stocke des objets temporaires.
* <mark style="color:orange;">**resource**</mark> : Base de données en lecture seule contenant des objets système inclus avec SQL Server.

***

## <mark style="color:red;">**4. Configuration par défaut**</mark>

* **Service MSSQL** : Fonctionne généralement sous le compte `NT SERVICE\MSSQLSERVER`.
* **Authentification** : Par défaut, l'authentification Windows est utilisée, ce qui permet au système d'exploitation Windows de gérer les demandes de connexion.
  * L'authentification peut utiliser soit la base SAM locale, soit le contrôleur de domaine (Active Directory).

{% hint style="warning" %}
Le système d'exploitation Windows traitera la demande de connexion et utilisera soit la base de données SAM locale, soit le contrôleur de domaine (hébergeant Active Directory) avant d'autoriser la connectivité au système de gestion de base de données. Utiliser Active Directory peut être idéal pour l'audit des activités et le contrôle d'accès dans un environnement Windows, mais si un compte est compromis, cela pourrait entraîner une élévation de privilèges et un déplacement latéral à travers un environnement de domaine Windows. Comme avec tout système d'exploitation, service, rôle de serveur ou application, il peut être bénéfique de l'installer dans une machine virtuelle, depuis l'installation jusqu'à la configuration, afin de comprendre toutes les configurations par défaut et les erreurs potentielles que l'administrateur pourrait commettre.
{% endhint %}

* **Chiffrement** : Non activé par défaut lors de la connexion au serveur SQL.

***

## <mark style="color:red;">**5. Paramètres dangereux et erreurs courantes**</mark>

* **Absence de chiffrement** : Les clients MSSQL peuvent se connecter sans chiffrement, exposant les données.
* **Certificats auto-signés** : Susceptibles d'être falsifiés, ce qui compromet la sécurité.
* Utilisation des **Named Pipes** : Peut exposer les données si mal configuré.
* **Crédentials faibles ou par défaut** : Comme `sa`, l'admin peut oublier de désactiver ou de sécuriser ce compte.

***

## <mark style="color:red;">**6. Footprinting et Scanning du Service MSSQL**</mark>

* <mark style="color:green;">**NMAP : Outils de scan pour collecter des informations sur MSSQL :**</mark>
  * Scripts utiles : `ms-sql-info`, `ms-sql-empty-password`, `ms-sql-xp-cmdshell`, etc.
  *   Exemple de commande NMAP pour MSSQL :

      {% code title="Nmap mmsql" overflow="wrap" %}
      ```bash
      sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 [target_ip]
      ```
      {% endcode %}
* **Metasploit** : Scanner auxiliaire `mssql_ping` pour footprinting MSSQL.

***

## <mark style="color:red;">**7. Connexion avec mssqlclient.py (Impacket)**</mark>

* **Connexion** : Permet de se connecter à distance à un serveur MSSQL avec les credentials appropriés.
*   **Exemple de commande** :

    ```bash
    python3 mssqlclient.py Administrator@[target_ip] -windows-auth
    ```
* **Actions possibles** : Une fois connecté, il est possible d'interagir avec les bases de données via T-SQL, lister les bases présentes, etc.

***
