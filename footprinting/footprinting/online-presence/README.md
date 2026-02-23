---
cover: ../../../.gitbook/assets/int.jpg
coverY: 0
---

# Online Presence

## <mark style="color:red;">Domain Information</mark>

> Les informations sur un domaine sont un élément essentiel de tout test d'intrusion. Il ne s'agit pas seulement des sous-domaines, mais de l'ensemble de la présence sur Internet. Ainsi, nous recueillons des informations et essayons de comprendre le fonctionnement de l'entreprise, ainsi que les technologies et structures nécessaires pour que les services soient proposés de manière efficace et réussie

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

      <pre class="language-bash" data-title="crt.sh" data-overflow="wrap"><code class="lang-bash">curl -s https://crt.sh/\?q\=inlanefreight.com\&#x26;output\=json | jq .
      curl -s https://crt.sh/\?q\=inlanefreight.com\&#x26;output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | sort -u
      </code></pre>

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

      <pre class="language-bash" data-title="Identification" data-overflow="wrap"><code class="lang-bash">for i in $(cat subdomainlist); do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4; done
      </code></pre>

***

### <mark style="color:blue;">Host Based Enumeration</mark>

#### <mark style="color:green;">Utilisation de Shodan</mark>

* **Objectif**: Rechercher les <mark style="color:orange;">**dispositifs et systèmes connectés en permanence à Internet**</mark>.
* **Méthode**:
  * Utiliser Shodan pour rechercher des ports TCP/IP ouverts.
  *   Exemple de commande:

      ```bash
      for i in $(cat ip-addresses.txt); do shodan host $i; done
      ```

#### <mark style="color:green;">Analyse des Enregistrements DNS</mark>

* **Objectif**: Identifier les enregistrements DNS pour découvrir plus de hôtes et services.
* **Méthode**:
  * Utiliser la commande <mark style="color:red;">**`dig`**</mark> pour obtenir tous les enregistrements DNS.
  *   Exemple de commande:

      ```bash
      dig any inlanefreight.com
      ```

{% hint style="info" %}
<mark style="color:green;">**We see an IP record, some mail servers, some DNS servers, TXT records, and an SOA record**</mark><mark style="color:green;">.</mark>

🔹 **Enregistrements A (A records)**

Les enregistrements **A** permettent d’associer une adresse IP à un nom de domaine (ou sous-domaine).\
Ici, on ne voit qu’une seule adresse IP, que nous connaissions déjà.

***

🔹 **Enregistrements MX (MX records)**

Les enregistrements **MX** indiquent quels serveurs de messagerie sont responsables de la gestion des e-mails du domaine.\
Dans notre cas, ce service est assuré par **Google**, donc nous pouvons simplement le noter et passer à la suite.

***

🔹 **Enregistrements NS (NS records)**

Les enregistrements **NS** spécifient quels **serveurs de noms** (name servers) sont utilisés pour résoudre les noms de domaine complets (FQDN) en adresses IP.\
La plupart des hébergeurs utilisent leurs **propres serveurs de noms**, ce qui peut aider à **identifier le fournisseur d’hébergement**.

***

🔹 **Enregistrements TXT (TXT records)**

Les enregistrements **TXT** contiennent souvent des **clés de vérification** utilisées par des services tiers, ainsi que des **informations de sécurité DNS** comme :

* **SPF** (Sender Policy Framework)
* **DKIM** (DomainKeys Identified Mail)
* **DMARC** (Domain-based Message Authentication, Reporting & Conformance)

Ces mécanismes servent à **authentifier et vérifier l’origine des e-mails** envoyés depuis le domaine.\
En examinant de près les résultats, on peut déjà y trouver **des informations intéressantes et utiles**.

***
{% endhint %}

***
