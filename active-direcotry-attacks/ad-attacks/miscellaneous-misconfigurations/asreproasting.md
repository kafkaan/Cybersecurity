# ASREPRoasting

### <mark style="color:blue;">ASREPRoasting</mark>

{% hint style="warning" %}
Il est possible d’obtenir le **Ticket Granting Ticket (TGT)** pour n’importe quel compte ayant l’option **"Ne pas exiger l’authentification préalable Kerberos"** activée.

De nombreux guides d’installation de fournisseurs recommandent de configurer ainsi leurs **comptes de service**.

La réponse du **service d’authentification (AS\_REP)** est chiffrée avec le **mot de passe du compte**, et **tout utilisateur du domaine** peut en faire la demande.

**Fonctionnement de l’authentification Kerberos avec la pré-authentification activée**

1. **L’utilisateur saisit son mot de passe**
2. **Un horodatage (timestamp) est chiffré** avec ce mot de passe
3. **Le contrôleur de domaine** (DC) **déchiffre cet horodatage** pour vérifier que l’utilisateur a utilisé le bon mot de passe
4. **Si la validation est réussie**, un **TGT** est délivré à l’utilisateur pour lui permettre d’effectuer d’autres requêtes d’authentification sur le domaine

**Vulnérabilité lorsque la pré-authentification est désactivée**

Si un compte a la **pré-authentification Kerberos désactivée**, alors **un attaquant peut demander les données d’authentification de ce compte** et récupérer un **TGT chiffré** auprès du **contrôleur de domaine**.

Ce **TGT chiffré** peut ensuite être soumis à une **attaque hors ligne sur le mot de passe** en utilisant des outils comme **Hashcat** ou **John the Ripper**.

***

🔹 **Ticket Granting Ticket (TGT)**\
👉 C’est un ticket délivré par le contrôleur de domaine lorsqu’un utilisateur s’authentifie avec Kerberos. Il permet à l’utilisateur de demander d’autres tickets d’accès aux services du domaine sans avoir à entrer à nouveau son mot de passe.

🔹 **Do not require Kerberos pre-authentication (Ne pas exiger l’authentification préalable Kerberos)**\
👉 C’est une option qui, si activée sur un compte, **désactive une protection** contre les attaques sur Kerberos. Cela signifie qu’un attaquant peut demander des données d’authentification sans avoir à fournir un mot de passe valide au préalable.

🔹 **AS\_REP (Authentication Service Reply)**\
👉 C’est la réponse envoyée par le contrôleur de domaine lorsqu’un utilisateur fait une demande d’authentification Kerberos. Si la pré-authentification est désactivée, cette réponse est chiffrée avec le mot de passe du compte et peut être exploitée par un attaquant.

***

📌 **Si la pré-authentification Kerberos est désactivée pour un compte :**\
✅ **Tout utilisateur du domaine** peut demander une réponse d’authentification chiffrée (AS\_REP).\
✅ Cette réponse est chiffrée avec le **mot de passe du compte ciblé**.\
✅ **Un attaquant peut récupérer cette réponse** et essayer de casser le chiffrement **hors ligne** en testant des mots de passe.\
✅ S’il réussit, il récupère **le mot de passe du compte ciblé**, ce qui peut lui permettre **d’escalader ses privilèges** dans Active Directory.

🔴 **C’est une vulnérabilité sérieuse car elle permet de récupérer des identifiants sans générer beaucoup d’alertes sur le réseau !**

💡 **Solution : Vérifier et s’assurer que la pré-authentification Kerberos est activée sur tous les comptes, en particulier les comptes de service.**
{% endhint %}

**Viewing an Account with the Do not Require Kerberos Preauthentication Option**

<figure><img src="../../../.gitbook/assets/preauth_not_reqd_mmorgan.webp" alt=""><figcaption></figcaption></figure>

**ASREPRoasting** est similaire à **Kerberoasting**, mais cela implique d'attaquer le **AS-REP** au lieu du **TGS-REP**.

Un **SPN (Service Principal Name)** n'est pas requis.

{% hint style="warning" %}
Si un attaquant a les permissions **GenericWrite** ou **GenericAll** sur un compte, il peut **activer cet attribut** et obtenir le **ticket AS-REP** pour **le casser hors ligne** afin de récupérer le **mot de passe du compte**, puis **désactiver l’attribut** à nouveau.
{% endhint %}

Comme pour **Kerberoasting**, le succès de cette attaque dépend du fait que le compte ait un **mot de passe relativement faible**.

Ci-dessous se trouve un exemple de l'attaque. **PowerView** peut être utilisé pour **énumérer les utilisateurs** ayant leur valeur **UAC** définie sur **DONT\_REQ\_PREAUTH**..

<mark style="color:green;">**Enumerating for DONT\_REQ\_PREAUTH Value using Get-DomainUser**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```
{% endcode %}

<mark style="color:green;">**Retrieving AS-REP in Proper Format using Rubeus**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```
{% endcode %}

We can then crack the hash offline using Hashcat with mode `18200`.

<mark style="color:green;">**Cracking the Hash Offline with Hashcat**</mark>

<pre class="language-shell-session" data-overflow="wrap" data-full-width="true"><code class="lang-shell-session"><strong>hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 
</strong></code></pre>

When performing user enumeration with `Kerbrute`, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.

<mark style="color:green;">**Retrieving the AS-REP Using Kerbrute**</mark>

{% code fullWidth="true" %}
```shell-session
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```
{% endcode %}

<mark style="color:green;">**Hunting for Users with Kerberoast Pre-auth Not Required**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 
```
{% endcode %}
