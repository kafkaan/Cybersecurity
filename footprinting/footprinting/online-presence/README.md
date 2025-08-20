---
cover: ../../../.gitbook/assets/int.jpg
coverY: 0
---

# Online Presence

## <mark style="color:red;">Domain Information</mark>

> Les informations sur un domaine sont un élément essentiel de tout test d'intrusion. Il ne s'agit pas seulement des sous-domaines, mais de l'ensemble de la présence sur Internet. Ainsi, nous recueillons des informations et essayons de comprendre le fonctionnement de l'entreprise, ainsi que les technologies et structures nécessaires pour que les services soient proposés de manière efficace et réussie

The first thing we should do is scrutinize the company's `main website`. Then, we should read through the texts, keeping in mind what technologies and structures are needed for these services.

***

## <mark style="color:red;">Infrastructure Based Enumeration</mark>

***

### <mark style="color:blue;">Examen des Certificats SSL</mark>

<figure><img src="../../../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

* **Objectif**: <mark style="color:orange;">**Identifier les domaines et sous-domaines associés au certificat SSL**</mark> de l'entreprise.
* **Méthode**:
  * Examiner le certificat SSL du site principal.
  * Utiliser <mark style="color:red;">**`crt.sh`**</mark> pour rechercher les journaux de transparence des certificats.
  *   Exemples de commandes:

      {% code title="crt.sh" overflow="wrap" %}
      ```bash
      curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
      curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | sort -u
      ```
      {% endcode %}

{% hint style="info" %}
1. <mark style="color:green;">**`curl`**</mark>
   * **Description**: Utilisé pour transférer des données depuis ou vers un serveur.
   * **Options Clés**:
     * **-s**: Mode silencieux.
2. <mark style="color:green;">**`jq`**</mark>
   * **Description**: Outil de traitement et manipulation de JSON.
   * **Options Clés**:
     * **.**: Filtre qui affiche le JSON tel quel.
3. <mark style="color:green;">**`grep`**</mark>
   * **Description**: Utilisé pour rechercher des motifs dans les fichiers ou les flux de texte.
   * **Options Clés**:
     * **-v**: Inverse la correspondance (exclut les lignes correspondantes).
4. <mark style="color:green;">**`cut`**</mark>
   * **Description**: Utilisé pour découper des sections de chaque ligne d'un fichier ou d'un flux de texte.
   * **Options Clés**:
     * **-d**: Définit le délimiteur.
     * **-f**: Sélectionne le champ à afficher.
5. <mark style="color:green;">**`awk`**</mark>
   * **Description**: Langage de programmation pour le traitement des fichiers texte et des flux de texte.
   * **Options Clés**:
     * **gsub(pattern, replacement)**: Fonction qui remplace toutes les occurrences du motif par la chaîne de remplacement.
6. <mark style="color:green;">**`sort`**</mark>
   * **Description**: Trie les lignes de texte.
   * **Options Clés**:
     * **-u**: Trie et supprime les doublons.


{% endhint %}

***

### <mark style="color:blue;">Identification des Hôtes</mark>

* **Objectif**: <mark style="color:orange;">**Trouver les serveurs directement accessibles**</mark> et hébergés par l'entreprise.
* **Méthode**:
  * Utiliser les commandes `host` et `grep` pour identifier les adresses IP.
  *   Exemple de commande:

      {% code title="Identification" overflow="wrap" %}
      ```bash
      for i in $(cat subdomainlist); do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4; done
      ```
      {% endcode %}

***

### <mark style="color:blue;">Host Based Enumeration</mark>

#### <mark style="color:orange;">Utilisation de Shodan</mark>

* **Objectif**: Rechercher les <mark style="color:orange;">**dispositifs et systèmes connectés en permanence à Internet**</mark>.
* **Méthode**:
  * Utiliser Shodan pour rechercher des ports TCP/IP ouverts.
  *   Exemple de commande:

      ```bash
      for i in $(cat ip-addresses.txt); do shodan host $i; done
      ```

#### <mark style="color:orange;">Analyse des Enregistrements DNS</mark>

* **Objectif**: Identifier les enregistrements DNS pour découvrir plus de hôtes et services.
* **Méthode**:
  * Utiliser la commande <mark style="color:red;">**`dig`**</mark> pour obtenir tous les enregistrements DNS.
  *   Exemple de commande:

      ```bash
      dig any inlanefreight.com
      ```

{% hint style="info" %}
<mark style="color:orange;">**We see an IP record, some mail servers, some DNS servers, TXT records, and an SOA record**</mark><mark style="color:orange;">.</mark>

* `A` records: We recognize the IP addresses that point to a specific (sub)domain through the A record. Here we only see one that we already know.
* `MX` records: The mail server records show us which mail server is responsible for managing the emails for the company. Since this is handled by google in our case, we should note this and skip it for now.
* `NS` records: These kinds of records show which name servers are used to resolve the FQDN to IP addresses. Most hosting providers use their own name servers, making it easier to identify the hosting provider.
* `TXT` records: this type of record often contains verification keys for different third-party providers and other security aspects of DNS, such as [SPF](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC](https://datatracker.ietf.org/doc/html/rfc7489), and [DKIM](https://datatracker.ietf.org/doc/html/rfc6376), which are responsible for verifying and confirming the origin of the emails sent. Here we can already see some valuable information if we look closer at the results.
{% endhint %}

***
