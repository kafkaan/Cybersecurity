# Subdomain FUZZING

### <mark style="color:red;">Qu'est-ce qu'un sous-domaine ?</mark>

Un sous-domaine est un domaine qui dépend d'un autre domaine principal. Par exemple, l'URL [**https://photos.google.com**](https://photos.google.com/) correspond au sous-domaine **photos** du domaine principal **google.com**.

Le fuzzing de sous-domaines consiste à tester différents noms de sous-domaines pour vérifier leur existence en utilisant des enregistrements DNS publics. Cela permet d'identifier des services ou des applications cachés qui peuvent offrir des points d'entrée potentiels pour des tests de sécurité.

***

### <mark style="color:red;">Prérequis pour le Fuzzing</mark>

Avant de commencer un scan de sous-domaines, vous aurez besoin de :

* **Une wordlist (liste de mots)** : Contient des noms de sous-domaines courants.
* **Une cible** : Le domaine principal à tester.

**Où trouver une wordlist ?** Dans le dépôt SecLists, vous trouverez des wordlists pour le fuzzing de sous-domaines :

```
/opt/useful/seclists/Discovery/DNS/
```

Dans cet exemple, nous utiliserons la liste **subdomains-top1million-5000.txt**.

***

### <mark style="color:red;">Lancer un Scan avec ffuf</mark>

Nous allons effectuer un scan sur le domaine **inlanefreight.com** pour identifier les sous-domaines publics.

#### <mark style="color:green;">Commande ffuf pour le fuzzing de sous-domaines :</mark>

{% code fullWidth="true" %}
```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```
{% endcode %}

**Explication des options :**

* **-w** : Spécifie la wordlist à utiliser.
* **FUZZ** : Placeholder remplaçable par chaque mot de la wordlist.
* **-u** : Définit l'URL cible avec le placeholder FUZZ.
* **Matcher** : Recherche des réponses avec les codes de statut 200, 301, 403, etc.
* **Threads** : Définit le nombre de requêtes parallèles (ici 40).

#### Exemple de résultats :

```bash
[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 381ms]
    * FUZZ: support
[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 385ms]
    * FUZZ: ns3
[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 402ms]
    * FUZZ: blog
[Status: 200, Size: 22266, Words: 2903, Lines: 316, Duration: 589ms]
    * FUZZ: www
```

Ces résultats indiquent que les sous-domaines **support**, **ns3**, **blog**, et **www** existent pour le domaine **inlanefreight.com**.

***

### <mark style="color:red;">Scan d'un Autre Domaine : academy.htb</mark>

{% code fullWidth="true" %}
```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/
```
{% endcode %}

#### Résultats :

{% code overflow="wrap" fullWidth="true" %}
```bash
:: Progress: [4997/4997] :: Job [1/1] :: 131 req/sec :: Duration: [0:00:38] :: Errors: 4997 ::
```
{% endcode %}

**Interprétation :** Aucune correspondance n'a été trouvée pour **academy.htb**. Cela signifie que ce domaine n'a pas de sous-domaines publics enregistrés dans le DNS.

**Remarque :**

* Si vous avez ajouté le domaine à **/etc/hosts**, ffuf ne trouvera que le domaine principal, car il interroge le DNS public pour les sous-domaines.

***

### <mark style="color:red;">Fuzzing des VHosts (Virtual Hosts)</mark>

Lorsque des sous-domaines ne sont pas publics, il est possible de les identifier par fuzzing des VHosts. Un VHost est un site hébergé sur le même serveur IP que le domaine principal.

#### <mark style="color:green;">Différence entre VHosts et Sous-Domaines</mark>

* **Sous-domaine** : Peut avoir un enregistrement DNS public.
* **VHost** : Peut ne pas avoir d'enregistrement DNS public mais est accessible via le même IP.

#### <mark style="color:green;">Pourquoi Fuzzer les VHosts ?</mark>

Le fuzzing des VHosts permet de découvrir des sites cachés sans enregistrement DNS public.

#### <mark style="color:green;">Commande de fuzzing des VHosts avec ffuf</mark>

{% code overflow="wrap" fullWidth="true" %}
```
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```
{% endcode %}

#### <mark style="color:green;">Interprétation des résultats</mark>

* Si tous les mots de la wordlist retournent un code 200, cela signifie probablement que le serveur répond par défaut.
* Un changement de taille de réponse peut indiquer l'existence d'un VHost.

#### Exemples de VHosts trouvés

* `mail2`
* `dns2`
* `webmail`

***

### <mark style="color:red;">Problème de Réponses en Doublon (Code 200)</mark>

Lorsqu'on teste des VHosts, il est courant que les VHosts inexistants retournent une réponse HTTP 200 avec une page par défaut. Cela peut entraîner de nombreux faux positifs.

Exemple :

```
ffuf -w subdomains.txt -u http://academy.htb/ -H "Host: FUZZ.academy.htb"
```

Résultat :

```
mail2   [Status: 200, Size: 900]
dns2    [Status: 200, Size: 900]
admin   [Status: 200, Size: 0]
```

Dans ce cas, `mail2` et `dns2` retournent une taille de 900 octets, ce qui indique une réponse générique.

#### <mark style="color:green;">Filtrage des Résultats avec ffuf</mark>

Pour éviter ces faux positifs, on utilise des options de filtrage basées sur la taille de réponse.

**Options de filtrage disponibles :**

* **-fc** : Filtrer par code HTTP (ex : `-fc 404` pour ignorer les 404).
* **-fs** : Filtrer par taille de réponse (ex : `-fs 900` pour filtrer les réponses de 900 octets).
* **-fw** : Filtrer par nombre de mots dans la réponse.
* **-fl** : Filtrer par nombre de lignes.

#### Exécution avec Filtrage de Taille

{% code overflow="wrap" fullWidth="true" %}
```
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb/ -H 'Host: FUZZ.academy.htb' -fs 900
```
{% endcode %}

Résultat filtré :

```
admin   [Status: 200, Size: 0, Words: 1, Lines: 1]
```

En utilisant `-fs 900`, on élimine toutes les réponses génériques de 900 octets, révélant uniquement les VHosts uniques.
