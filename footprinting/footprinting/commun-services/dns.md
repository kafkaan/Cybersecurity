---
description: Domain Name System (DNS) is an integral part of the Internet.
cover: >-
  https://images.unsplash.com/photo-1531956656798-56686eeef3d4?crop=entropy&cs=srgb&fm=jpg&ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHw2fHxkbnN8ZW58MHx8fHwxNzQwNDgwMjM2fDA&ixlib=rb-4.0.3&q=85
coverY: 0
---

# DNS

## <mark style="color:red;">Étape par Étape : Résolution DNS pour "google.com"</mark>

<mark style="color:orange;">**1. Vérification du cache local**</mark>

* **Votre ordinateur** : Lorsque vous tapez "google.com", votre ordinateur vérifie d'abord son propre cache DNS pour voir s'il connaît déjà l'adresse IP correspondante.
* **Fichier Hosts** : Si l'adresse IP est trouvée dans le fichier hosts (par exemple, **`/etc/hosts`** sur Linux/MacOS ou **`C:\Windows\System32\drivers\etc\hosts`** sur Windows), la résolution s'arrête ici et l'adresse IP est utilisée.

<mark style="color:orange;">**2. Consultation du résolveur DNS local**</mark>

* **Résolveur DNS** : Si l'adresse IP n'est pas trouvée localement, votre ordinateur envoie une requête au résolveur DNS configuré, souvent celui de votre fournisseur d'accès internet (ISP).

<mark style="color:orange;">**3. Interrogation des serveurs racine**</mark>

* **Serveur Racine** : Le résolveur DNS vérifie ensuite s'il a la réponse en cache. Si ce n'est pas le cas, il envoie une requête à l'un des serveurs racine DNS (par exemple, `a.root-servers.net`).

<mark style="color:orange;">**4. Redirection vers les serveurs TLD**</mark>

* **Serveur TLD** : Le serveur racine renvoie l'adresse IP du serveur TLD responsable du domaine de premier niveau `.com` (par exemple, `a.gtld-servers.net`).

<mark style="color:orange;">**5. Redirection vers les serveurs faisant autorité**</mark>

* **Serveur TLD** : Le résolveur DNS envoie une requête au serveur TLD pour `.com`, qui renvoie l'adresse IP du serveur DNS faisant autorité pour le domaine `google.com` (par exemple, `ns1.google.com`).

<mark style="color:orange;">**6. Réponse du serveur faisant autorité**</mark>

* **Serveur faisant autorité** : Le résolveur DNS interroge le serveur faisant autorité pour `google.com`. Ce serveur renvoie l'adresse IP associée à `google.com` (par exemple, `172.217.164.110`).

<mark style="color:orange;">**7. Transmission de la réponse au client**</mark>

* **Résolveur DNS** : Le résolveur DNS renvoie l'adresse IP trouvée à votre ordinateur.
* **Cache** : Votre ordinateur peut mettre en cache cette réponse pour une utilisation future.

***

## <mark style="color:red;">**1. Introduction au DNS**</mark>

* **DNS (Domain Name System)** : <mark style="color:orange;">**Système permettant de résoudre les noms de domaine en adresses IP.**</mark>
* **Exemple** : academy.hackthebox.com traduit en une adresse IP spécifique.
* **Fonctionnement** : Imaginez-le comme une bibliothèque avec de nombreux annuaires téléphoniques.

***

## <mark style="color:red;">**2. Types de Serveurs DNS**</mark>

1. <mark style="color:green;">**DNS Root Server**</mark>
   * **Rôle** : Responsable des domaines de premier niveau (TLD).
   * **Coordination** : ICANN (Internet Corporation for Assigned Names and Numbers).
   * **Nombre** : 13 serveurs racine dans le monde.
2. <mark style="color:green;">**Authoritative Nameserver**</mark>
   * **Rôle** : Autorité pour une zone DNS particulière, réponse faisant autorité.
   * **Usage** : Si incapable de répondre, redirige vers le serveur racine.
3. <mark style="color:green;">**Non-authoritative Nameserver**</mark>
   * **Rôle** : Ne fait pas autorité pour une zone DNS, collecte des informations via des requêtes récursives ou itératives.
4. <mark style="color:green;">**Caching DNS Server**</mark>
   * **Rôle** : Cache les informations pour une période déterminée définie par le serveur faisant autorité.
5. <mark style="color:green;">**Forwarding Server**</mark>
   * **Rôle** : Transmet les requêtes DNS à un autre serveur DNS.
6. <mark style="color:green;">**Resolver**</mark>
   * **Rôle** : Effectue la résolution des noms localement sur l'ordinateur ou le routeur.

***

## <mark style="color:red;">**3. Enregistrement DNS (DNS Records)**</mark>

1. <mark style="color:green;">**A**</mark>
   * **Rôle** : Retourne une adresse IPv4 pour le domaine demandé.
2. <mark style="color:green;">**AAAA**</mark>
   * **Rôle** : Retourne une adresse IPv6 pour le domaine demandé.
3. <mark style="color:green;">**MX**</mark>
   * **Rôle** : Retourne les serveurs de messagerie responsables.
4. <mark style="color:green;">**NS**</mark>
   * **Rôle** : Retourne les serveurs DNS (nameservers) du domaine.
5. <mark style="color:green;">**TXT**</mark>
   * **Rôle** : Contient diverses informations, par exemple, validation de la Google Search Console ou des certificats SSL.
6. <mark style="color:green;">**CNAME**</mark>
   * **Rôle** : Alias pour un autre nom de domaine.
7. <mark style="color:green;">**PTR**</mark>
   * **Rôle** : Résolution inverse, convertit les adresses IP en noms de domaine.
8. <mark style="color:green;">**SOA**</mark>
   * **Rôle** : Informations sur la zone DNS et l'adresse e-mail de contact administratif.

***

## <mark style="color:red;">**4. Configuration DNS**</mark>

* <mark style="color:green;">**Fichiers de configuration DNS locaux**</mark>
  *   **named.conf.local** : Définir les différentes zones.

      ```dns-zone-file
      //
      // Do any local configuration here
      //

      // Consider adding the 1918 zones here, if they are not used in your
      // organization
      //include "/etc/bind/zones.rfc1918";
      zone "domain.com" {
          type master;
          file "/etc/bind/db.domain.com";
          allow-update { key rndc-key; };
      };
      ```
  * **named.conf.options** : Options générales.
  * **named.conf.log** : Logs du serveur DNS.
*   <mark style="color:green;">**Zone Files**</mark>

    * **Format** : Texte décrivant une zone DNS avec le format de fichier BIND.
    * **Exigence** : Doit contenir un enregistrement SOA et au moins un enregistrement NS.

    ```dns-zone-file
    $ORIGIN domain.com
    $TTL 86400
    @     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                        2001062501 ; serial
                        21600      ; refresh
                        3600       ; retry
                        604800     ; expire
                        86400 )    ; minimum TTL

          IN     NS     ns1.domain.com.
          IN     MX     10     mx.domain.com.
          IN     A      10.129.14.5

    server1  IN  A      10.129.14.5
    www      IN  CNAME  server2
    ```
*   <mark style="color:green;">**Fichiers de résolution inverse**</mark>

    * **Rôle** : Résolution des adresses IP en noms de domaine.

    ```dns-zone-file
    $ORIGIN 14.129.10.in-addr.arpa
    $TTL 86400
    @     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                        2001062501 ; serial
                        21600      ; refresh
                        3600       ; retry
                        604800     ; expire
                        86400 )    ; minimum TTL

          IN     NS     ns1.domain.com.

    5    IN     PTR    server1.domain.com.
    ```

{% hint style="info" %}
<mark style="color:green;">**Traduction Inverse (Reverse Lookup) dans DNS**</mark>

**1. Introduction**

* **DNS Direct Lookup** : Habituellement, quand on parle de DNS, on parle de la résolution de noms de domaine (par exemple, `www.example.com`) en adresses IP (par exemple, `192.0.2.1`).
* **DNS Reverse Lookup** : C'est l'inverse : trouver le nom de domaine (FQDN - Fully Qualified Domain Name) associé à une adresse IP.

**2. Fichier de Traduction Inverse (Reverse Lookup File)**

Pour que la traduction inverse soit possible, le serveur DNS doit avoir un fichier spécifique, appelé fichier de recherche inverse (reverse lookup file), qui contient des enregistrements PTR (Pointer).

**3. Enregistrement PTR**

* **PTR Record** : C'est un type d'enregistrement DNS utilisé pour la traduction inverse. Il associe une adresse IP à un nom de domaine complet (FQDN).

**4. Comment ça Fonctionne**

1. **Format de l'adresse IP pour la recherche inverse** :
   * Pour effectuer une recherche inverse, l'adresse IP doit être convertie en un format spécial appelé "in-addr.arpa".
   * Exemple : Pour l'adresse IP `192.0.2.1`, le format sera `1.2.0.192.in-addr.arpa`.
2. **Enregistrement dans le Fichier de Recherche Inverse** :
   * Le serveur DNS contient un fichier de recherche inverse où chaque adresse IP (dans le format "in-addr.arpa") est associée à un FQDN via un enregistrement PTR.
   *   Exemple d'un enregistrement PTR :

       <pre class="language-bash" data-title="" data-overflow="wrap"><code class="lang-bash">1.2.0.192.in-addr.arpa. IN PTR www.example.com.
       </code></pre>
3. **Processus de Recherche Inverse** :
   * Lorsqu'un client ou un serveur veut connaître le nom de domaine associé à une adresse IP, il interroge le serveur DNS avec l'adresse IP convertie.
   * Le serveur DNS cherche dans son fichier de recherche inverse et renvoie le nom de domaine correspondant.

**5. Exemple Pratique**

Imaginons que nous avons une adresse IP `192.0.2.1` et nous voulons connaître le nom de domaine associé.

1. **Adresse IP Convertie** : On convertit `192.0.2.1` en `1.2.0.192.in-addr.arpa`.
2. **Interrogation DNS** : On interroge le serveur DNS avec `1.2.0.192.in-addr.arpa`.
3.  **Réponse du Serveur DNS** : Le serveur DNS cherche un enregistrement PTR correspondant dans son fichier de recherche inverse et renvoie le FQDN :

    ```plaintext
    1.2.0.192.in-addr.arpa. IN PTR www.example.com.
    ```

    Cela signifie que l'adresse IP `192.0.2.1` est associée au nom de domaine `www.example.com`.
{% endhint %}

***

## <mark style="color:red;">**5. Sécurité DNS**</mark>

* **Risques** : DNS est principalement non chiffré, ce qui permet à des attaquants d'intercepter et de surveiller les requêtes DNS.
* <mark style="color:green;">**Solutions de chiffrement**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * **DNS over TLS (DoT)**
  * **DNS over HTTPS (DoH)**
  * **DNSCrypt** : Chiffre le trafic entre l'ordinateur et le serveur de noms.

***

## <mark style="color:red;">**6. Attaques et Vulnérabilités**</mark>

* <mark style="color:green;">**Paramètres dangereux**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * **allow-query** : Qui peut envoyer des requêtes.
  * **allow-recursion** : Qui peut envoyer des requêtes récursives.
  * **allow-transfer** : Qui peut recevoir des transferts de zone.
*   <mark style="color:green;">**Footprinting**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

    * **Requête NS** : Identifier les serveurs DNS connus.
    * **Requête ANY** : Voir tous les enregistrements disponibles.
    * **Requête de version** : Identifier la version du serveur DNS.

    ```plaintext
    dig ns domain.com @dns-server
    dig any domain.com @dns-server
    dig CH TXT version.bind @dns-server
    ```

#### <mark style="color:green;">**Transfert de zone**</mark>&#x20;

{% hint style="warning" %}
**Le transfert de zone** fait référence au **transfert de zones vers un autre serveur dans DNS**, ce qui se produit généralement via le **port TCP 53**.\
Cette procédure est abrégée en **Asynchronous Full Transfer Zone (AXFR)** (Transfert Asynchrone Complet de Zone).

Puisqu'une **défaillance DNS** a généralement de **graves conséquences** pour une entreprise, le **fichier de zone** est presque toujours **conservé à l'identique** sur plusieurs **serveurs de noms**.

Lorsque des modifications sont apportées, il faut s'assurer que **tous les serveurs** possèdent les **mêmes données**.\
La **synchronisation** entre les serveurs impliqués est réalisée grâce au **transfert de zone**.

En utilisant une **clé secrète `rndc-key`**, que nous avons vue **initialement dans la configuration par défaut**, les serveurs s'assurent qu'ils **communiquent uniquement avec leur propre maître ou esclave**.

Le **transfert de zone** implique simplement :

* **Le transfert des fichiers ou enregistrements**
* **La détection des différences** dans les ensembles de données des serveurs impliqués.

***

Les **données originales** d'une zone sont situées sur un **serveur DNS**, appelé **serveur de noms primaire** pour cette zone.

Cependant, pour :\
✅ **Améliorer la fiabilité**\
✅ **Équilibrer la charge**\
✅ **Protéger le serveur primaire des attaques**

👉 On installe généralement **un ou plusieurs serveurs supplémentaires**, appelés **serveurs de noms secondaires** pour cette zone.

📌 Pour certains **domaines de premier niveau (TLDs)**, il est **obligatoire** de rendre les fichiers de zone des **domaines de second niveau** accessibles sur au moins **deux serveurs**.

***

Les **entrées DNS** sont **créées, modifiées ou supprimées** uniquement sur le **serveur primaire**.

Cela peut être fait :

* **Manuellement** en éditant le **fichier de zone**
* **Automatiquement** par une **mise à jour dynamique depuis une base de données**

Un **serveur DNS** qui sert de **source directe** pour **synchroniser un fichier de zone** est appelé un **maître** (**master**).

Un **serveur DNS** qui **obtient les données de zone d'un maître** est appelé un **esclave** (**slave**).

👉 **Un primaire est toujours un maître**, tandis qu'un **secondaire peut être à la fois un esclave et un maître**.

***

📌 **Comment fonctionne la mise à jour ?**

📍 L'**esclave** récupère **l’enregistrement SOA** (Start of Authority) de la zone concernée **depuis le maître**, à intervalles réguliers (**refresh time**), en général **toutes les heures**.

📍 Il **compare les numéros de série** du **SOA record**.

📍 **Si le numéro de série du SOA du maître est supérieur à celui de l'esclave**, alors **les ensembles de données ne correspondent plus** et un **transfert de zone est déclenché**.
{% endhint %}

* **AXFR** : Transfert complet de la zone, souvent vulnérable si mal configuré.

```sh
dig axfr domain.com @dns-server
```

*   **Subdomain Brute Forcing**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt); do
        dig $sub.inlanefreight.htb @10.129.14.128 |
        grep -v ';\|SOA' |
        sed -r '/^\s*$/d' |
        grep $sub |
        tee -a subdomains.txt
    done
    </code></pre>

{% hint style="warning" %}
**1. `for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt); do`**

* **`for sub in $(...)`** : Cette partie de la commande est une boucle `for` qui itère sur chaque sous-domaine trouvé dans le fichier de liste.
* **`cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt`** : La commande `cat` lit le contenu du fichier spécifié, qui contient une liste de sous-domaines.
* **`$(...)`** : L'expression entre parenthèses est exécutée et son résultat est utilisé comme entrée pour la boucle `for`.

**Ce que cela fait :** Cela initialise une boucle qui parcourt chaque sous-domaine listé dans le fichier.

**2. `dig $sub.inlanefreight.htb @10.129.14.128`**

* **`dig $sub.inlanefreight.htb`** : La commande `dig` est utilisée pour interroger le DNS. Ici, elle interroge le sous-domaine spécifié (avec la variable `$sub`) pour le domaine `inlanefreight.htb`.
* **`@10.129.14.128`** : Indique le serveur DNS (avec l'adresse IP 10.129.14.128) à utiliser pour effectuer la requête.

**Ce que cela fait :** Cela interroge le serveur DNS pour obtenir des informations sur le sous-domaine actuel.

**3. `grep -v ';\|SOA'`**

* **`grep`** : Utilisé pour filtrer les lignes contenant un motif spécifique.
* **`-v`** : Exclut les lignes contenant le motif.
* **`';\|SOA'`** : Expression régulière qui sélectionne les lignes contenant un point-virgule (`;`) ou le texte `SOA`.

**Ce que cela fait :** Cela supprime les lignes contenant des commentaires (marqués par `;`) et les enregistrements SOA, qui ne sont pas pertinents pour la liste des sous-domaines.

**4. `sed -r '/^\s*$/d'`**

* **`sed`** : Éditeur de flux pour transformer du texte.
* **`-r`** : Utilise des expressions régulières étendues.
* **`'/^\s*$/d'`** : Expression régulière pour supprimer les lignes vides ou contenant uniquement des espaces.

**Ce que cela fait :** Cela élimine les lignes vides restantes après le filtrage.

**5. `grep $sub`**

* **`grep $sub`** : Filtre les lignes contenant le sous-domaine actuel (`$sub`).

**Ce que cela fait :** Cela sélectionne les lignes qui contiennent le sous-domaine spécifique, vérifiant si la réponse DNS correspond à ce sous-domaine.

**6. `tee -a subdomains.txt`**

* **`tee`** : Commande pour lire depuis l'entrée standard et écrire dans la sortie standard ainsi que dans un ou plusieurs fichiers.
* **`-a`** : Mode "append" (ajouter) ; ajoute les lignes à la fin du fichier sans écraser le contenu existant.

{% code overflow="wrap" %}
```bash
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```
{% endcode %}
{% endhint %}
