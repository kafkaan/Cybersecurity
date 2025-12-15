# Internal Password Spraying - from Windows

***

## <mark style="color:red;">**Qu'est-ce que le Password Spraying ?**</mark>

Le _password spraying_ est une méthode d'attaque où un attaquant tente d'utiliser un même mot de passe sur plusieurs comptes d’utilisateurs. Contrairement à l'attaque par _brute-force_, où tous les mots de passe sont testés pour un compte, le password spraying consiste à tester un mot de passe commun sur de nombreux comptes afin de ne pas déclencher des verrous de compte en raison de tentatives échouées multiples.

There are several options available to us with the tool. Since the host is domain-joined, we will skip the `-UserList` flag and let the tool generate a list for us. We'll supply the `Password` flag and one single password and then use the `-OutFile` flag to write our output to a file for later use.

<mark style="color:green;">**Outil : DomainPasswordSpray**</mark>

* **Utilisation** : Cet outil permet de réaliser une attaque de _password spraying_ sur un réseau où un attaquant a déjà un accès initial (souvent sur une machine jointe au domaine).
*   **Commande Exemple** :

    <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Import-Module .\DomainPasswordSpray.ps1
    Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
    </code></pre>
* **Fonctionnement** : L’outil crée une liste d’utilisateurs à partir de l’Active Directory, exclut les utilisateurs sur le point d’être verrouillés et tente de se connecter en utilisant un mot de passe commun.

<mark style="color:green;">**Mitigation des attaques de Password Spraying**</mark>

1. **Authentification multi-facteurs** : Cela empêche l'attaquant d’accéder aux comptes même si le mot de passe est valide.
2. **Restriction d'accès** : Limiter l'accès aux ressources en appliquant le principe du moindre privilège.
3. **Réduire l'impact** : Utiliser des comptes séparés pour les activités administratives et appliquer des niveaux de permission spécifiques.
4. **Bonne gestion des mots de passe** : Utiliser des mots de passe complexes et uniques, ainsi qu'un filtre de mots de passe pour empêcher l'utilisation de mots simples.
5. **Politique de verrouillage des comptes** : Assurer que la politique de verrouillage des comptes ne soit pas trop restrictive, pour éviter les attaques par déni de service.

<mark style="color:green;">**Détection des attaques**</mark>

* **Indicateurs dans les journaux** :
  * Nombre élevé de verrous de comptes en peu de temps.
  * Échecs de connexion multiples (ID d'événement 4625).
  * Tentatives d'authentification échouées sur plusieurs serveurs ou applications.
* **Utilisation de l'ID 4771** : Cela indique un échec d'authentification Kerberos et peut indiquer une tentative de _password spraying_ via LDAP.
