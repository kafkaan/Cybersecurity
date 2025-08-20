# Enable Disabled User

{% code overflow="wrap" fullWidth="true" %}
```
ldapmodify -x -H ldap://10.10.11.70 -D 'ant.edwards@puppy.htb' -w 'Antman2025!' <<EOF
dn: CN=Adam D. Silver,CN=Users,DC=puppy,DC=htb
changetype: modify
replace: userAccountControl
userAccountControl: 512
EOF
modifying entry "CN=Adam D. Silver,CN=Users,DC=puppy,DC=htb"
```
{% endcode %}

#### 🔹 `ldapmodify`

C’est un outil en ligne de commande qui permet de **modifier des entrées LDAP** (comme un utilisateur) dans un annuaire (ex: Active Directory).

#### 🔹 `-x`

Utilise une **authentification simple** (non SASL).

#### 🔹 `-H ldap://10.10.11.70`

Indique l’**hôte LDAP**, ici `10.10.11.70`. C’est l’adresse IP du **contrôleur de domaine** ou du serveur LDAP.

#### 🔹 `-D 'ant.edwards@puppy.htb'`

C’est l’**identifiant LDAP complet** (DN) de l’utilisateur qui se connecte pour faire la modification. Ici, l’utilisateur **Ant Edwards**.

#### 🔹 `-w 'Antman2025!'`

Mot de passe du compte `ant.edwards@puppy.htb`.

#### 🔸 `changetype: modify`

Indique qu’on souhaite **modifier** l’objet (pas créer ou supprimer).

#### 🔸 `replace: userAccountControl`

On remplace complètement la valeur de l’attribut **`userAccountControl`**.

#### 🔸 `userAccountControl: 512`

On définit la valeur **512**, qui correspond à :

🟢 **NORMAL\_ACCOUNT**\
➡️ Un compte utilisateur standard (activé, sans restriction spéciale).

***

### 📘 userAccountControl : signification des valeurs

`userAccountControl` est un attribut AD contenant des **drapeaux de contrôle** codés en binaire.

Quelques valeurs courantes :

| Valeur  | Signification                                 |
| ------- | --------------------------------------------- |
| 512     | Compte utilisateur actif standard             |
| 514     | Compte **désactivé**                          |
| 544     | Compte + mot de passe non requis              |
| 66048   | Compte + mot de passe ne peut pas être changé |
| 2097152 | Compte **Smartcard required**                 |

{% code fullWidth="true" %}
```
bloodyAD --host 10.10.11.70 -d PUPPY.HTB -u ant.edwards -p Antman2025! remove uac adam.silver -f ACCOUNTDISABLE
```
{% endcode %}
