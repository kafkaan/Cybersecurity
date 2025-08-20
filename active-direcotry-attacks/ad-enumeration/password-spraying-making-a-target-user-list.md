# Password Spraying - Making a Target User List

***

### <mark style="color:red;">Detailed User Enumeration</mark>

* By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
* Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
* Using a tool such as `Kerbrute` to validate users utilizing a word list from a source such as the [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo, or gathered by using a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to create a list of potentially valid users
* Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using `Responder` or even a successful password spray using a smaller wordlist

***

### <mark style="color:red;">SMB NULL Session to Pull User List</mark>

<mark style="color:green;">**Using enum4linux**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```
{% endcode %}

We can use the `enumdomusers` command after connecting anonymously using `rpcclient`.

<mark style="color:green;">**Using rpcclient**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ rpcclient -U "" -N 172.16.5.5

rpcclient $> enumdomusers 
```

{% hint style="warning" %}
Finally, we can use `CrackMapExec` with the `--users` flag. This is a useful tool that will also show the `badpwdcount` (invalid login attempts), so we can remove any accounts from our list that are close to the lockout threshold. It also shows the `baddpwdtime`, which is the date and time of the last bad password attempt, so we can see how close an account is to having its `badpwdcount` reset. In an environment with multiple Domain Controllers, this value is maintained separately on each one. To get an accurate total of the account's bad password attempts, we would have to either query each Domain Controller and use the sum of the values or query the Domain Controller with the PDC Emulator FSMO role.
{% endhint %}

<mark style="color:green;">**Using CrackMapExec --users Flag**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 172.16.5.5 --users
```
{% endcode %}

***

### <mark style="color:red;">Gathering Users with LDAP Anonymous</mark>

We can use various tools to gather users when we find an LDAP anonymous bind. Some examples include [windapsearch](https://github.com/ropnop/windapsearch) and [ldapsearch](https://linux.die.net/man/1/ldapsearch).

<mark style="color:green;">**Using ldapsearch**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```
{% endcode %}

Tools such as `windapsearch` make this easier (though we should still understand how to create our own LDAP search filters). Here we can specify anonymous access by providing a blank username with the `-u` flag and the `-U` flag to tell the tool to retrieve just users.

Voici une fiche complète sur les **filtres LDAP** pour t’aider à mieux comprendre leur fonctionnement, leurs syntaxes, et leurs cas d’utilisation.

***

### <mark style="color:blue;">**FILTRES LDAP - GUIDE COMPLET**</mark>

#### <mark style="color:green;">**Structure générale d'un filtre LDAP**</mark>

Un filtre LDAP est écrit entre parenthèses `()` et suit cette structure :

```
(opérateur(champ=comparaison))
```

* **`opérateur`** : Définit la logique du filtre (AND, OR, NOT, etc.).
* **`champ`** : Le champ/attribut dans l'annuaire (comme `objectclass`, `sAMAccountName`).
* **`comparaison`** : La valeur recherchée dans le champ.

***

<mark style="color:green;">**Opérateurs LDAP**</mark>

Voici les principaux opérateurs :

<table data-full-width="true"><thead><tr><th>Opérateur</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td><code>&#x26;</code></td><td>AND : Toutes les conditions doivent être vraies</td><td><code>(&#x26;(objectclass=user)(cn=John Doe))</code></td></tr><tr><td>`</td><td>`</td><td>OR : Au moins une condition doit être vraie</td></tr><tr><td><code>!</code></td><td>NOT : Négation d’une condition</td><td><code>(!(objectclass=computer))</code></td></tr></tbody></table>

<mark style="color:green;">**Attributs courants dans LDAP**</mark>

Voici les champs les plus souvent utilisés dans les filtres :

<table data-full-width="true"><thead><tr><th>Champ</th><th>Description</th></tr></thead><tbody><tr><td><code>objectclass</code></td><td>Type d’objet (utilisateur, groupe, ordinateur, etc.)</td></tr><tr><td><code>sAMAccountName</code></td><td>Nom d'utilisateur ou identifiant unique</td></tr><tr><td><code>cn</code></td><td>Nom commun</td></tr><tr><td><code>distinguishedName</code></td><td>Chemin complet de l’objet dans l’annuaire</td></tr><tr><td><code>memberOf</code></td><td>Groupe auquel appartient l’utilisateur</td></tr><tr><td><code>userAccountControl</code></td><td>Statut du compte (actif, désactivé, etc.)</td></tr></tbody></table>

***

<mark style="color:green;">**Syntaxes des filtres LDAP**</mark>

**a) Recherche de tous les utilisateurs**

```ldap
(&(objectclass=user))
```

* **Explication** : Recherche tous les objets de type utilisateur.

**b) Recherche des utilisateurs actifs uniquement**

```ldap
(&(objectclass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

* **Explication** : Exclut les comptes désactivés.
  * **`userAccountControl:...:=2`** : Correspond à un flag indiquant que le compte est désactivé.
  * **`!`** : Négation (NOT).

**c) Recherche d’un utilisateur précis par son nom**

```ldap
(&(objectclass=user)(sAMAccountName=jdoe))
```

* **Explication** : Recherche un utilisateur dont le nom est `jdoe`.

**d) Recherche des comptes d’ordinateurs**

```ldap
(&(objectclass=computer))
```

* **Explication** : Recherche tous les objets de type ordinateur.

**e) Recherche des utilisateurs membres d’un groupe**

```ldap
(&(objectclass=user)(memberOf=CN=Admins,CN=Users,DC=example,DC=com))
```

* **Explication** : Recherche les utilisateurs appartenant au groupe `Admins`.

**f) Recherche avec plusieurs conditions (AND et OR combinés)**

```ldap
(&(|(objectclass=user)(objectclass=group))(cn=Admin*))
```

* **Explication** :
  * **`|`** : Accepte les objets de type utilisateur ou groupe.
  * **`&`** : Condition supplémentaire sur `cn` (nom commun) commençant par `Admin`.

***

#### <mark style="color:green;">**Opérateurs de comparaison LDAP**</mark>

Les filtres permettent aussi de rechercher des valeurs avec différents types de comparaison.

<table data-full-width="true"><thead><tr><th>Comparaison</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td><code>=</code></td><td>Égalité</td><td><code>(sAMAccountName=jdoe)</code></td></tr><tr><td><code>>=</code></td><td>Supérieur ou égal</td><td><code>(loginAttempts>=5)</code></td></tr><tr><td><code>&#x3C;=</code></td><td>Inférieur ou égal</td><td><code>(loginAttempts&#x3C;=10)</code></td></tr><tr><td><code>*</code></td><td>Joker (wildcard) pour une recherche partielle</td><td><code>(cn=Admin*)</code></td></tr><tr><td><code>!=</code> (avec <code>!</code>)</td><td>Différent</td><td><code>(!(objectclass=group))</code></td></tr></tbody></table>

***

#### <mark style="color:green;">**Cas pratiques**</mark>

Voici quelques cas courants pour des recherches LDAP utiles en contexte réel.

**a) Liste des noms d’utilisateur**

{% code fullWidth="true" %}
```bash
ldapsearch -x -h <server_ip> -b "DC=example,DC=com" -s sub "(&(objectclass=user))" | grep sAMAccountName:
```
{% endcode %}

* **But** : Retourner tous les noms d'utilisateur.

**b) Liste des groupes dans un domaine**

```bash
ldapsearch -x -h <server_ip> -b "DC=example,DC=com" -s sub "(&(objectclass=group))"
```

* **But** : Retourner tous les groupes disponibles.

**c) Comptes créés récemment**

```ldap
(&(objectclass=user)(whenCreated>=20240101000000.0Z))
```

* **Explication** : Recherche les utilisateurs créés après le 1er janvier 2024.

**d) Comptes avec des mots de passe expirés**

```ldap
(&(objectclass=user)(pwdLastSet<=20230101000000.0Z))
```

* **Explication** : Recherche les utilisateurs dont le mot de passe a été changé avant le 1er janvier 2023.

***

### <mark style="color:red;">**Using windapsearch**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

***

### <mark style="color:red;">Enumerating Users with Kerbrute</mark>

{% hint style="warning" %}
Cet outil utilise l'authentification préalable Kerberos (**Kerberos Pre-Authentication**) pour effectuer du **password spraying** (attaque visant à tester un petit nombre de mots de passe sur une liste d’utilisateurs). Cette méthode est à la fois **plus rapide** et potentiellement **plus discrète**, car elle ne génère pas l’événement Windows **ID 4625 : Échec de connexion d’un compte** ou tout autre échec de connexion qui est souvent surveillé dans les journaux d’événements.

***

**Fonctionnement de l'outil :**

1.  **Énumération des utilisateurs :**

    * L’outil envoie des requêtes TGT (**Ticket-Granting Ticket**) au contrôleur de domaine (Domain Controller) sans utiliser l’authentification préalable Kerberos.
    * Si le KDC (**Key Distribution Center**) renvoie l’erreur **PRINCIPAL UNKNOWN** (principal inconnu), cela signifie que le nom d’utilisateur est **invalide**.
    * En revanche, si le KDC demande une authentification préalable Kerberos, cela indique que le nom d’utilisateur **existe**. L’outil marquera alors cet utilisateur comme **valide**.

    **Avantage :** Cette méthode permet d'énumérer les utilisateurs sans générer d’échecs de connexion, ce qui signifie qu’elle **ne verrouille pas les comptes**.
2. **Password spraying :**
   * Une fois la liste des utilisateurs valides obtenue, l’outil peut être utilisé pour tester un mot de passe sur ces utilisateurs (password spraying).
   * Toutefois, chaque échec d’authentification préalable Kerberos est comptabilisé comme une tentative de connexion échouée. Si trop d’échecs sont enregistrés, cela peut entraîner le verrouillage du compte (selon les politiques définies dans Active Directory).

***

**Points importants à retenir :**

* **Discrétion :** L’énumération des utilisateurs via l’absence d’authentification préalable Kerberos ne génère pas d’événements de connexion échouée dans les journaux, ce qui rend la méthode difficile à détecter.
* **Précaution :** Lorsque vous passez à l’étape de **password spraying**, il faut être prudent, car les tentatives échouées compteront comme des échecs de connexion et risquent de verrouiller les comptes si vous dépassez le seuil autorisé.
{% endhint %}

<mark style="color:green;">**Kerbrute User Enumeration**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt     
```
{% endcode %}

{% hint style="danger" %}
Using Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack. If we are successful with this method during a penetration test, this can be an excellent recommendation to add to our report.
{% endhint %}

***

### <mark style="color:red;">Credentialed Enumeration to Build our User List</mark>

<mark style="color:green;">**Using CrackMapExec with Valid Credentials**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```
{% endcode %}
