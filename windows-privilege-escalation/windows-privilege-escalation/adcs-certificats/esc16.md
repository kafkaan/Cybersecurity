# ESC16

***

## &#x20;<mark style="color:red;">ESC16 — Misconfiguration et Exploitation AD CS</mark>

***

#### <mark style="color:green;">Qu’est-ce que ESC16 ?</mark>

* **ESC16** est une vulnérabilité liée à une mauvaise configuration dans **Active Directory Certificate Services (AD CS)**.
* Cette faille affaiblit la **liaison forte entre certificats et comptes AD**, permettant à un utilisateur avec peu de privilèges d’usurper une identité privilégiée.

***

#### <mark style="color:green;">Cause principale</mark>

* La **désactivation globale de l’extension de sécurité szOID\_NTDS\_CA\_SECURITY\_EXT** (OID: `1.3.6.1.4.1.311.25.2`) sur la CA.
* Cette extension inclut le **SID (Security Identifier)** du compte AD dans le certificat, assurant un lien fort et sécurisé.
* Quand cette extension est désactivée (dans la clé registre `DisableExtensionList`), les certificats sont émis **sans SID**, affaiblissant la validation.

***

#### <mark style="color:green;">Conséquences</mark>

* Le CA émet des certificats qui ne contiennent pas cette liaison SID sécurisée.
* Si les contrôleurs de domaine n’exigent pas une **validation stricte** (paramètre `StrongCertificateBindingEnforcement` ≠ 2), ils acceptent des certificats basés sur des méthodes moins sécurisées comme le **User Principal Name (UPN)** ou le **DNS name**.
* Un attaquant peut alors :
  * Modifier son propre **userPrincipalName** (s’il a la permission `Write` sur son attribut).
  * Demander un certificat avec ce nouveau UPN usurpé.
  * S’authentifier avec ce certificat et obtenir des privilèges plus élevés.

***

#### <mark style="color:green;">Paramètre clé : StrongCertificateBindingEnforcement</mark>

* Gère la rigueur de la validation entre certificat et compte AD.
* Valeurs possibles (dans `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\Parameters`) :

| Valeur | Mode                                              | Description                                                                 |
| ------ | ------------------------------------------------- | --------------------------------------------------------------------------- |
| 0      | Disabled                                          | Validation faible, confiance aux mappings legacy (UPN, SAN).                |
| 1      | Compatibility Mode (défaut jusqu’en février 2025) | Validation préférentielle forte, mais fallback possible vers legacy.        |
| 2      | Full Enforcement (à partir de février 2025)       | Validation stricte : seuls les certificats avec mapping fort sont acceptés. |

***

#### <mark style="color:green;">Exploitation simplifiée d’ESC16</mark>

1. **Le CA désactive l’extension szOID\_NTDS\_CA\_SECURITY\_EXT.**
2. **Le DC n’applique pas l’enforcement fort (mode 0 ou 1).**
3. Un utilisateur ayant le droit de modifier son `userPrincipalName` change cette valeur pour usurper un compte privilégié.
4. Il demande un certificat avec ce UPN modifié.
5. Il s’authentifie avec ce certificat et obtient un accès privilégié.

***

#### <mark style="color:green;">Prévention</mark>

* Ne jamais désactiver l’extension `szOID_NTDS_CA_SECURITY_EXT` dans la configuration de la CA.
* Configurer `StrongCertificateBindingEnforcement` à 2 (Full Enforcement) sur les DC.
* Restreindre les permissions d’écriture sur les attributs sensibles comme `userPrincipalName`.
* Auditer régulièrement les templates et permissions AD CS.

***

#### <mark style="color:green;">Commandes utiles (exemples)</mark>

* Pour vérifier les extensions désactivées sur la CA :

```powershell
certutil -getreg policy\DisableExtensionList
```

* Pour désactiver l’extension (mise en place de ESC16) :

```powershell
certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.25.2
net stop certsvc
net start certsvc
```

* Pour configurer la validation forte sur DC :

```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Kdc\Parameters" -Name "StrongCertificateBindingEnforcement" -Value 2
Restart-Service kdc
```

***

#### Outils d’exploitation et détection

* **Certipy** peut détecter la vulnérabilité ESC16 et aider à l’exploitation.
* Exemple de commande pour vérifier vulnérabilité :

```bash
certipy find -u 'user' -p 'password' -dc-ip <IP-DC> -stdout -vulnerable
```

***

{% hint style="warning" %}
Pour **finaliser une exploitation ESC16** via un template de certificat dans AD CS, il faut que certains **flags/attributs** du template soient configurés de façon spécifique. Voici les points clés :

***

#### 1. **Flag CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT**

* **Doit être activé** dans le template.
* Permet à l’utilisateur qui fait la demande (l’enrollee) de **fournir les informations du sujet (Subject)** dans la requête de certificat.
* Sans ce flag, le CA construit le sujet à partir des données AD du demandeur, rendant l’attaque ESC16 difficile/impossible.

***

#### 2. **Attribut `userPrincipalName` modifiable par l’utilisateur**

* Pour pouvoir **usurper un autre compte**, l’utilisateur doit avoir **le droit d’écrire sur son propre `userPrincipalName`**.
* Cette permission est souvent désactivée par défaut.
* Pour exploiter ESC16, il faut que l’utilisateur ait au moins un **droit `Write` ou `Write userPrincipalName`** sur son objet AD.

***

#### 3. **Template compatible avec l’extension szOID\_NTDS\_CA\_SECURITY\_EXT**

* Normalement, cette extension est prise en compte **uniquement si le flag CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT est activé**.
* **Si la CA a désactivé cette extension (ESC16 activé),** alors la liaison forte est désactivée, permettant la validation faible.

***

#### 4. **Pas de restrictions fortes sur le SAN**

* Si la template ou la CA impose des restrictions strictes sur le **Subject Alternative Name (SAN)**, cela pourrait empêcher une usurpation via ESC16.
* Il faut souvent que le SAN puisse être contrôlé par le demandeur (par exemple, via le flag CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT).

***
{% endhint %}
