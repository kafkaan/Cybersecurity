# Machine Key dans ASP.NET

***

### <mark style="color:red;">🧠 Partie 1 — Qu’est-ce qu’une Machine Key dans ASP.NET / IIS ?</mark>

#### <mark style="color:green;">Définition</mark>

Une **Machine Key** est une paire de clés cryptographiques utilisée par ASP.NET pour :

* **Signer** (intégrité) des données comme le `ViewState`, les cookies d’authentification, etc.
* **Chiffrer** (confidentialité) certaines données côté serveur.

Elle garantit que :

* Les données échangées entre client et serveur **n’ont pas été modifiées**.
* Un serveur d’un cluster peut **lire les cookies générés par un autre** (dans un web farm).

***

### <mark style="color:red;">⚙️ Partie 2 — Structure de la machineKey</mark>

Définie dans le `web.config` :

```xml
<machineKey
  validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80"
  decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"
  validation="HMACSHA256"
  decryption="AES"
/>
```

* `validationKey` → sert à **signer** (MAC ou HMAC)
* `decryptionKey` → sert à **chiffrer/déchiffrer**
* `validation` → algorithme de signature (`SHA1`, `HMACSHA256`, `HMACSHA512`…)
* `decryption` → algorithme de chiffrement (`AES`, `3DES`, etc.)

***

### <mark style="color:red;">📂 Partie 3 — Où sont stockées les Machine Keys ?</mark>

#### <mark style="color:green;">1️⃣ Dans un site web spécifique</mark>

* `C:\inetpub\wwwroot\app\web.config`**3️⃣ Dans la base de registre si `AutoGenerate` est activé :**

#### <mark style="color:green;">2️⃣ Dans les fichiers systèmes ASP.NET</mark>

* `C:\Windows\Microsoft.NET\Framework\v4.0.30319\config\machine.config`
* `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config`

#### <mark style="color:green;">3️⃣ Dans la base de registre si</mark> <mark style="color:green;"></mark><mark style="color:green;">`AutoGenerate`</mark> <mark style="color:green;"></mark><mark style="color:green;">est activé :</mark>

```
HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeyV4
```

***

### <mark style="color:red;">🔐 Partie 4 — À quoi servent-elles concrètement ?</mark>

#### <mark style="color:green;">1️⃣</mark> <mark style="color:green;"></mark><mark style="color:green;">**ViewState**</mark>

* Le `__VIEWSTATE` contient des données de l’état de la page.
* Il est signé avec la **validationKey**.
* S’il est chiffré, la **decryptionKey** est utilisée.
* Un pentester qui récupère cette clé peut :
  * Vérifier/éditer le ViewState.
  * Générer un nouveau ViewState valide (ex: exploitation de désérialisation).

#### <mark style="color:green;">2️⃣</mark> <mark style="color:green;"></mark><mark style="color:green;">**Forms Authentication**</mark>

* Les cookies `.ASPXAUTH` sont chiffrés/signés avec la machineKey.
* Cela permet au serveur de vérifier leur authenticité.
* Si un attaquant connaît la clé → il peut forger un cookie admin (dans un lab).

#### <mark style="color:green;">3️⃣</mark> <mark style="color:green;"></mark><mark style="color:green;">**Session State**</mark>

* Les identifiants de session stockés dans un cache externe (ex: SQL, Redis) sont également protégés.

***

### <mark style="color:red;">💻 Partie 5 — Exemple pratique (local et légal)</mark>

#### <mark style="color:green;">Exemple 1 — Créer un cookie d’authentification en C#</mark>

```csharp
using System;
using System.Web.Security;

class Program {
    static void Main() {
        var ticket = new FormsAuthenticationTicket(
            1, "admin", DateTime.Now, DateTime.Now.AddHours(1), false, "Role=Admin"
        );
        string encrypted = FormsAuthentication.Encrypt(ticket);
        Console.WriteLine(encrypted);
    }
}
```

➡️ Le cookie généré sera signé/chiffré avec la `machineKey` du `web.config`.

***

### <mark style="color:red;">🧩 Partie 6 — Utilisation en Pentesting / Audit</mark>

#### 🕵️ Objectif du pentester

* **Identifier** la machineKey (via `web.config`, `machine.config`, ou LFI).
* **Déterminer** comment elle est utilisée :
  * `ViewState`
  * `.ASPXAUTH`
  * `__RequestVerificationToken`
* **Tester** la présence de protections (`EnableViewStateMac`, `ViewStateEncryptionMode`).
* **Créer un environnement local** avec la même machineKey pour reproduire le comportement.

***

### <mark style="color:red;">⚔️ Partie 7 — Outils utilisés en audit</mark>

| Outil                           | Usage                                    |
| ------------------------------- | ---------------------------------------- |
| **ysoserial.net**               | Générer un payload ViewState valide      |
| **Blacklist3r**                 | Identifier une machineKey valide         |
| **viewstalker**                 | Décoder ViewState                        |
| **AspDotNetWrapper.exe**        | Chiffrer/Déchiffrer cookies ou ViewState |
| **badsecrets**                  | Recherche de clés connues / faibles      |
| **ViewStateEditor** (Burp BApp) | Décoder et modifier \_\_VIEWSTATE        |

***

### <mark style="color:red;">🧠 Partie 8 — Pentest Workflow typique (ex: CTF, lab)</mark>

1. **LFI ou téléchargement** → récupération de `web.config`
2.  **Extraction** de :

    ```xml
    <machineKey validationKey="..." decryptionKey="..." validation="HMACSHA256" decryption="AES" />
    ```
3. **Analyse** des paramètres de la cible :
   * Requêtes contenant `__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`
4. **Test** de signature avec `Blacklist3r` ou `AspDotNetWrapper`
5. **Génération** d’un ViewState custom via `ysoserial.net` si vulnérable

***

### <mark style="color:red;">🧩 Partie 9 — Sécurisation côté développeur</mark>

* Utiliser des clés fortes et aléatoires.
* Ne **jamais** publier `web.config`.
* Activer :
  * `EnableViewStateMac="true"`
  * `ViewStateEncryptionMode="Always"`
* Configurer le mode `compatibilityMode="Framework45"`
*   Forcer HTTPS pour les cookies :

    ```xml
    <forms requireSSL="true" />
    ```

***

### <mark style="color:red;">🧠 Partie 10 — À retenir</mark>

| Élément            | Clé utilisée                  | Rôle                      |
| ------------------ | ----------------------------- | ------------------------- |
| `__VIEWSTATE`      | validationKey / decryptionKey | stocke état de page       |
| `.ASPXAUTH` cookie | validationKey / decryptionKey | cookie d’authentification |
| `Session ID`       | validationKey                 | signature de session      |
| `AntiForgeryToken` | validationKey                 | protection CSRF           |

***
