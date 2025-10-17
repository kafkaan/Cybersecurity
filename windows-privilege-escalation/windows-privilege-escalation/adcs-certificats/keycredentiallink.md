# KeyCredentialLink

#### <mark style="color:green;">🧠 Définition :</mark>

Le champ **KeyCredentialLink** (ou `msDS-KeyCredentialLink`) est un attribut LDAP introduit par Microsoft pour **stock­er des certificats d’authentification Kerberos** (PKINIT).

Il contient :

* des certificats,
* des clés publiques associées,
* et des métadonnées pour l’authentification par certificat (smartcard login, etc.).

***

#### <mark style="color:green;">⚙️ Utilisation légitime :</mark>

Quand un utilisateur s’authentifie avec une **carte à puce** (ou un certificat),\
son certificat est stocké dans l’attribut `msDS-KeyCredentialLink`.

Le contrôleur de domaine (KDC) l’utilise ensuite pour valider la signature et délivrer un **TGT Kerberos**.

***

#### <mark style="color:green;">💣 Abus offensif :</mark>

Si un attaquant peut **écrire dans cet attribut** pour un autre utilisateur (ex : administrateur),\
il peut y **ajouter un certificat contrôlé par lui-même**.

Ainsi, il peut :

* générer une paire de clés publique/privée,
* injecter la clé publique dans `KeyCredentialLink` de la cible,
* puis **s’authentifier au nom de cette cible** via PKINIT (Kerberos par certificat).

Outils :\
🧰 `pywhisker`, `certipy`, `whisker.py`

{% code fullWidth="true" %}
```sh
python3 pywhisker.py -d haze.htb -u "Backup$" -H "<NTLMhash>" --target "edward.martin" --action "add"

```
{% endcode %}

{% code fullWidth="true" %}
```
python3 gettgtpkinit.py -cert-pfx test.pfx -pfx-pass password haze.htb/edward.martin edward.ccache
```
{% endcode %}
