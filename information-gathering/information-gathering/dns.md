# DNS

## <mark style="color:red;">Introduction</mark>

Le DNS (Domain Name System) est le système de traduction des noms de domaine en adresses IP, permettant de naviguer sur internet avec des noms mémorables plutôt que des numéros complexes.

***

## <mark style="color:red;">Fonctionnement du DNS</mark>

1. **DNS Query** : Lorsque vous entrez un nom de domaine, votre ordinateur vérifie d'abord son cache.
2. **DNS Resolver** : Si l'adresse IP n'est pas trouvée en cache, le résolveur DNS de votre ISP est consulté.
3. **Root Name Server** : Le résolveur interroge ensuite un serveur racine.
4. **TLD Name Server** : Le serveur racine dirige le résolveur vers le serveur de domaine de premier niveau (TLD).
5. **Authoritative Name Server** : Le serveur TLD pointe vers le serveur faisant autorité pour le domaine spécifique.
6. **Résultat** : Le serveur faisant autorité renvoie l'adresse IP au résolveur, qui la transmet à votre ordinateur.

<figure><img src="../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

***

## <mark style="color:red;">Fichier Hosts</mark>

Le fichier hosts est un fichier texte simple qui mappe des noms d'hôte à des adresses IP, permettant une méthode manuelle de résolution de nom de domaine, contournant ainsi le processus DNS.

* <mark style="color:orange;">**Windows**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark> `C:\Windows\System32\drivers\etc\hosts`
* <mark style="color:orange;">**Linux/MacOS**</mark> : `/etc/hosts`

Format :

```bash
<Adresse IP>    <Nom d'Hôte> [<Alias> ...]
```

Exemples :

```bash
127.0.0.1       localhost
192.168.1.10    devserver.local
```

***

## <mark style="color:red;">Principaux Concepts DNS</mark>

1. **Nom de Domaine** : Label lisible par l'humain (ex: [www.example.com](http://www.example.com)).
2. **Adresse IP** : Identifiant numérique unique (ex: 192.0.2.1).
3. **Résolveur DNS** : Serveur qui traduit les noms de domaine en adresses IP (ex: 8.8.8.8).
4. **Serveur Racine** : Serveurs de niveau supérieur dans la hiérarchie DNS.
5. **Serveur TLD** : Serveurs responsables des domaines de premier niveau (ex: .com, .org).
6. **Serveur Faisant Autorité** : Serveur détenant l'adresse IP d'un domaine spécifique.
7. **Types de Requêtes DNS** : A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR.

{% hint style="info" %}
<mark style="color:green;">**Détails sur la Zone DNS**</mark>

**Qu'est-ce qu'une Zone DNS ?**

* **Zone** : Une zone DNS représente une portion de l'espace de noms de domaine pour laquelle une entité spécifique est responsable. Cette entité gère l'enregistrement des noms et les adresses IP associés à ces noms au sein de cette zone.
* **Responsabilité** : Une zone est gérée par des serveurs de noms faisant autorité qui contiennent les informations de cette zone.
* **Fichier de Zone** : Le fichier de zone est un fichier texte sur le serveur DNS qui définit les enregistrements de ressources dans cette zone.

**Illustration**

* **example.com** est un domaine.
* **mail.example.com** et **blog.example.com** sont des sous-domaines appartenant à **example.com**.
* Tous ces domaines et sous-domaines font partie de la **zone DNS** de **example.com**.
{% endhint %}

***

## <mark style="color:red;">Types de Records DNS</mark>

<table data-full-width="true"><thead><tr><th>Type de Record</th><th>Nom Complet</th><th>Description</th><th>Exemple dans le Fichier de Zone</th></tr></thead><tbody><tr><td>A</td><td>Address Record</td><td>Mappe un nom d'hôte à son adresse IPv4</td><td><a href="http://www.example.com">www.example.com</a>. IN A 192.0.2.1</td></tr><tr><td>AAAA</td><td>IPv6 Address Record</td><td>Mappe un nom d'hôte à son adresse IPv6</td><td><a href="http://www.example.com">www.example.com</a>. IN AAAA 2001:db8:85a3::8a2e:370:7334</td></tr><tr><td>CNAME</td><td>Canonical Name Record</td><td>Crée un alias pour un nom d'hôte</td><td>blog.example.com. IN CNAME webserver.example.net.</td></tr><tr><td>MX</td><td>Mail Exchange Record</td><td>Spécifie le(s) serveur(s) de mail pour le domaine</td><td>example.com. IN MX 10 mail.example.com.</td></tr><tr><td>NS</td><td>Name Server Record</td><td>Délègue une zone DNS à un serveur de noms spécifique</td><td>example.com. IN NS ns1.example.com.</td></tr><tr><td>TXT</td><td>Text Record</td><td>Stocke des informations textuelles arbitraires</td><td>example.com. IN TXT "v=spf1 mx -all"</td></tr><tr><td>SOA</td><td>Start of Authority Record</td><td>Spécifie les informations administratives d'une zone DNS</td><td>example.com. IN SOA ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400</td></tr><tr><td>SRV</td><td>Service Record</td><td>Définit le nom d'hôte et le port pour des services spécifiques</td><td>_sip._udp.example.com. IN SRV 10 5 5060 sipserver.example.com.</td></tr><tr><td>PTR</td><td>Pointer Record</td><td>Utilisé pour les recherches DNS inversées (IP -> nom d'hôte)</td><td>1.2.0.192.in-addr.arpa. IN PTR <a href="http://www.example.com">www.example.com</a>.</td></tr></tbody></table>

{% hint style="info" %}
The "`IN`" in the examples stands for "Internet." It's a class field in DNS records that specifies the protocol family. In most cases, you'll see "`IN`" used, as it denotes the Internet protocol suite (IP) used for most domain names. Other class values exist (e.g., `CH` for Chaosnet, `HS` for Hesiod) but are rarely used in modern DNS configurations.
{% endhint %}

{% hint style="warning" %}
#### <mark style="color:green;">Enregistrement SOA (Start of Authority)</mark>

* **Rôle** : L'enregistrement SOA fournit des informations cruciales sur la zone DNS et sert de point de départ pour la gestion de cette zone.
* **Contenu** : Il inclut des informations telles que le serveur de noms primaire, l'adresse e-mail de l'administrateur, le numéro de série, et des paramètres temporels pour le rafraîchissement, la tentative de nouvelle synchronisation, l'expiration et le TTL minimal.
* **Utilisation** : Il est utilisé pour la gestion de la zone, la synchronisation entre les serveurs DNS et pour informer les serveurs secondaires quand synchroniser les données.

#### <mark style="color:green;">Enregistrements NS (Name Server)</mark>

* **Rôle** : Les enregistrements NS spécifient quels serveurs de noms sont autorisés à répondre pour la zone DNS. En d'autres termes, ils indiquent quels serveurs DNS détiennent les enregistrements pour le domaine et ses sous-domaines.
* **Contenu** : Ils listent les noms des serveurs de noms autoritaires pour la zone.
* **Utilisation** : Ils sont utilisés par les serveurs DNS résolveurs pour déterminer où envoyer les requêtes DNS afin de trouver les informations sur le domaine et ses sous-domaines.
{% endhint %}

***

## <mark style="color:red;">Digging DNS</mark>

### <mark style="color:blue;">DNS Tools</mark>

<table data-full-width="true"><thead><tr><th width="190">Tool</th><th>Key Features</th><th>Use Cases</th></tr></thead><tbody><tr><td><code>dig</code></td><td>Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output.</td><td>Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records.</td></tr><tr><td><code>nslookup</code></td><td>Simpler DNS lookup tool, primarily for A, AAAA, and MX records.</td><td>Basic DNS queries, quick checks of domain resolution and mail server records.</td></tr><tr><td><code>host</code></td><td>Streamlined DNS lookup tool with concise output.</td><td>Quick checks of A, AAAA, and MX records.</td></tr><tr><td><code>dnsenum</code></td><td>Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed).</td><td>Discovering subdomains and gathering DNS information efficiently.</td></tr><tr><td><code>fierce</code></td><td>DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.</td><td>User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.</td></tr><tr><td><code>dnsrecon</code></td><td>Combines multiple DNS reconnaissance techniques and supports various output formats.</td><td>Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.</td></tr><tr><td><code>theHarvester</code></td><td>OSINT tool that gathers information from various sources, including DNS records (email addresses).</td><td>Collecting email addresses, employee information, and other data associated with a domain from multiple sources.</td></tr><tr><td>Online DNS Lookup Services</td><td>User-friendly interfaces for performing DNS lookups.</td><td>Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information</td></tr></tbody></table>

### <mark style="color:blue;">The Domain Information Groper</mark>

The `dig` command (`Domain Information Groper`)

<table data-full-width="true"><thead><tr><th width="345">Command</th><th>Description</th></tr></thead><tbody><tr><td><code>dig domain.com</code></td><td>Performs a default A record lookup for the domain.</td></tr><tr><td><code>dig domain.com A</code></td><td>Retrieves the IPv4 address (A record) associated with the domain.</td></tr><tr><td><code>dig domain.com AAAA</code></td><td>Retrieves the IPv6 address (AAAA record) associated with the domain.</td></tr><tr><td><code>dig domain.com MX</code></td><td>Finds the mail servers (MX records) responsible for the domain.</td></tr><tr><td><code>dig domain.com NS</code></td><td>Identifies the authoritative name servers for the domain.</td></tr><tr><td><code>dig domain.com TXT</code></td><td>Retrieves any TXT records associated with the domain.</td></tr><tr><td><code>dig domain.com CNAME</code></td><td>Retrieves the canonical name (CNAME) record for the domain.</td></tr><tr><td><code>dig domain.com SOA</code></td><td>Retrieves the start of authority (SOA) record for the domain.</td></tr><tr><td><code>dig @1.1.1.1 domain.com</code></td><td>Specifies a specific name server to query; in this case 1.1.1.1</td></tr><tr><td><code>dig +trace domain.com</code></td><td>Shows the full path of DNS resolution.</td></tr><tr><td><code>dig -x 192.168.1.1</code></td><td>Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.</td></tr><tr><td><code>dig +short domain.com</code></td><td>Provides a short, concise answer to the query.</td></tr><tr><td><code>dig +noall +answer domain.com</code></td><td>Displays only the answer section of the query output.</td></tr><tr><td><code>dig domain.com ANY</code></td><td>Retrieves all available DNS records for the domain (Note: Many DNS servers ignore <code>ANY</code> queries to reduce load and prevent abuse, as per <a href="https://datatracker.ietf.org/doc/html/rfc8482">RFC 8482</a>).</td></tr></tbody></table>

{% hint style="info" %}
<mark style="color:orange;">**Digging DNS**</mark>

{% code title="" overflow="wrap" lineNumbers="true" %}
```dns-zone-file
mrroboteLiot@htb[/htb]$ dig google.com

; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       142.251.47.142

;; Query time: 0 msec
;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
;; WHEN: Thu Jun 13 10:45:58 SAST 2024
;; MSG SIZE  rcvd: 54
```
{% endcode %}

1. Header
   * `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449`: This line indicates the type of query (`QUERY`), the successful status (`NOERROR`), and a unique identifier (`16449`) for this specific query.
     * `;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`: This describes the flags in the DNS header:
       * `qr`: Query Response flag - indicates this is a response.
       * `rd`: Recursion Desired flag - means recursion was requested.
       * `ad`: Authentic Data flag - means the resolver considers the data authentic.
       * The remaining numbers indicate the number of entries in each section of the DNS response: 1 question, 1 answer, 0 authority records, and 0 additional records.
   * `;; WARNING: recursion requested but not available`: This indicates that recursion was requested, but the server does not support it.
2. Question Section
   * `;google.com. IN A`: This line specifies the question: "What is the IPv4 address (A record) for `google.com`?"
3. Answer Section
   * `google.com. 0 IN A 142.251.47.142`: This is the answer to the query. It indicates that the IP address associated with `google.com` is `142.251.47.142`. The '`0`' represents the `TTL` (time-to-live), indicating how long the result can be cached before being refreshed.
4. Footer
   * `;; Query time: 0 msec`: This shows the time it took for the query to be processed and the response to be received (0 milliseconds).
   * `;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)`: This identifies the DNS server that provided the answer and the protocol used (UDP).
   * `;; WHEN: Thu Jun 13 10:45:58 SAST 2024`: This is the timestamp of when the query was made.
   * `;; MSG SIZE rcvd: 54`: This indicates the size of the DNS message received (54 bytes).
{% endhint %}

***

## <mark style="color:red;">Subdomains</mark>

<mark style="color:green;">**1. Introduction aux Subdomains**</mark>

* **Définition** : Les sous-domaines sont des extensions du domaine principal, créés pour organiser et séparer différentes sections ou fonctionnalités d'un site web.
* **Exemples** :
  * `blog.example.com` pour un blog
  * `shop.example.com` pour une boutique en ligne
  * `mail.example.com` pour les services de messagerie

<mark style="color:green;">**2. Importance pour la Reconnaissance Web**</mark>

* **Environnements de Développement et de Test** : Utilisés pour tester de nouvelles fonctionnalités ou mises à jour avant de les déployer sur le site principal. Ces environnements peuvent parfois contenir des vulnérabilités ou des informations sensibles en raison de mesures de sécurité moins strictes.
* **Portails de Connexion Cachés** : Hébergent des panneaux administratifs ou d'autres pages de connexion non destinées à être accessibles publiquement.
* **Applications Légacy** : Des applications web anciennes et potentiellement oubliées peuvent résider sur des sous-domaines, contenant des logiciels obsolètes avec des vulnérabilités connues.
* **Informations Sensibles** : Peuvent exposer accidentellement des documents confidentiels, des données internes ou des fichiers de configuration.

<mark style="color:green;">**3. Énumération des Sous-Domaines**</mark>

L'énumération des sous-domaines consiste à identifier et à lister systématiquement ces sous-domaines.

<mark style="color:orange;">**a. Types de Dossiers DNS Concernés**</mark>

* **A (ou AAAA pour IPv6)** : Mappent le nom du sous-domaine à son adresse IP correspondante.
* **CNAME** : Utilisés pour créer des alias pour les sous-domaines, les pointant vers d'autres domaines ou sous-domaines.

<mark style="color:orange;">**b. Approches pour l'Énumération des Sous-Domaines**</mark>

1. **Énumération Active**
   * **Interaction Directe** : Interaction directe avec les serveurs DNS du domaine cible pour découvrir les sous-domaines.
   * **Transfert de Zone DNS** : Une méthode où un serveur mal configuré pourrait accidentellement divulguer une liste complète de sous-domaines. Rarement réussie en raison de mesures de sécurité renforcées.
   * **Brute-force d'Énumération** : Tester systématiquement une liste de noms de sous-domaines potentiels contre le domaine cible. Outils courants : `dnsenum`, `ffuf`, `gobuster`.
2. **Énumération Passive**
   * **Sources Externes d'Information** : Découverte des sous-domaines sans interroger directement les serveurs DNS du domaine cible.
   * **Logs de Transparence des Certificats (CT)** : Répertoires publics de certificats SSL/TLS incluant souvent des sous-domaines dans le champ Subject Alternative Name (SAN).
   * **Moteurs de Recherche** : Utiliser des opérateurs de recherche spécialisés (par exemple, `site:`) pour filtrer les résultats et afficher uniquement les sous-domaines liés au domaine cible.
   * **Bases de Données et Outils en Ligne** : Agrègent des données DNS provenant de multiples sources, permettant de rechercher des sous-domaines sans interagir directement avec la cible.

***

### <mark style="color:blue;">Subdomain Bruteforcing</mark>

1. <mark style="color:green;">**Sélection de la Liste de Mots (Wordlist)**</mark>
   * **Générale** : Contient une large gamme de noms de sous-domaines communs (ex. : dev, staging, blog, mail, admin, test).
   * **Ciblée** : Focalisée sur des industries spécifiques, des technologies ou des schémas de nommage pertinents pour la cible.
   * **Personnalisée** : Créée à partir de mots-clés spécifiques, de schémas ou d'informations recueillies à partir d'autres sources.
2. <mark style="color:green;">**Itération et Requête**</mark>
   * Utilisation d'un script ou d'un outil pour itérer à travers la wordlist.
   * Ajout de chaque mot ou phrase au domaine principal (ex. : dev.example.com, staging.example.com).
3. <mark style="color:green;">**Recherche DNS (DNS Lookup)**</mark>
   * Exécution d'une requête DNS pour chaque sous-domaine potentiel pour vérifier s'il résout à une adresse IP (souvent de type A ou AAAA).
4. <mark style="color:green;">**Filtrage et Validation**</mark>
   * Si un sous-domaine résout avec succès, il est ajouté à une liste de sous-domaines valides.
   * Des étapes de validation supplémentaires peuvent être effectuées (ex. : tentative d'accès via un navigateur web).

<table data-full-width="true"><thead><tr><th>Outil</th><th>Description</th></tr></thead><tbody><tr><td><strong>dnsenum</strong></td><td>Outil complet d'énumération DNS prenant en charge les attaques par dictionnaire et brute-force pour découvrir les sous-domaines.</td></tr><tr><td><strong>fierce</strong></td><td>Outil convivial pour la découverte récursive de sous-domaines, avec détection des wildcards.</td></tr><tr><td><strong>dnsrecon</strong></td><td>Outil polyvalent combinant plusieurs techniques de reconnaissance DNS, avec des formats de sortie personnalisables.</td></tr><tr><td><strong>amass</strong></td><td>Outil maintenu activement, intégré avec d'autres outils et sources de données étendues.</td></tr><tr><td><strong>assetfinder</strong></td><td>Outil simple mais efficace pour trouver des sous-domaines via diverses techniques.</td></tr><tr><td><strong>puredns</strong></td><td>Outil puissant et flexible pour le brute-force DNS, capable de résoudre et de filtrer les résultats efficacement.</td></tr></tbody></table>

### <mark style="color:blue;">**Exemple d'Utilisation : dnsenum**</mark>

<mark style="color:green;">**Fonctions Clés de dnsenum :**</mark>

* **Énumération des Enregistrements DNS** : Récupère divers enregistrements DNS comme A, AAAA, NS, MX et TXT.
* **Tentatives de Transfert de Zone** : Essaye automatiquement les transferts de zone des serveurs de noms découverts.
* **Brute-Force de Sous-Domaines** : Prend en charge le brute-force des sous-domaines à l'aide d'une wordlist.
* **Scraping de Google** : Scrape les résultats de recherche Google pour trouver des sous-domaines supplémentaires.
* **Reverse Lookup** : Effectue des reverse DNS pour identifier les domaines associés à une adresse IP.
* **WHOIS Lookups** : Effectue des requêtes WHOIS pour obtenir des informations sur la propriété et l'enregistrement du domaine.

<mark style="color:green;">**Commande d'Exemple pour dnsenum**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

{% code title="DNS" overflow="wrap" %}
```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r
```
{% endcode %}

* `dnsenum --enum inlanefreight.com` : Spécifie le domaine cible à énumérer avec des options de réglage par défaut `--enum`.
* `-f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` : Indique le chemin vers la wordlist SecLists pour le brute-force.
* `-r` : Active le brute-force récursif, essayant d'énumérer les sous-domaines des sous-domaines trouvés.

<mark style="color:green;">**Exécution de la Commande**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt 

dnsenum VERSION:1.2.6

-----   inlanefreight.com   -----

Host's addresses:
__________________

inlanefreight.com.                       300      IN    A        134.209.24.248

[...]

Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:
_______________________________________________________________________________________

www.inlanefreight.com.                   300      IN    A        134.209.24.248
support.inlanefreight.com.               300      IN    A        134.209.24.248
[...]

done.
```
{% endcode %}

***

## <mark style="color:red;">Transferts de Zone DNS</mark>

Un **transfert de zone DNS** est un mécanisme permettant de copier tous les enregistrements DNS d'une zone (un domaine et ses sous-domaines) d'un serveur de noms primaire vers un serveur secondaire. Ce processus est essentiel pour assurer la cohérence et la redondance des données DNS à travers différents serveurs de noms.

<mark style="color:green;">**Processus d'un Transfert de Zone DNS**</mark>

1. **Demande de Transfert de Zone (AXFR) :**
   * Le serveur secondaire envoie une requête de transfert de zone au serveur primaire, utilisant le type AXFR (transfert de zone complet).
2. **Transfert de l'Enregistrement SOA :**
   * Le serveur primaire répond en envoyant l'enregistrement Start of Authority (SOA) contenant des informations essentielles sur la zone, telles que le numéro de série.
3. **Transmission des Enregistrements DNS :**
   * Le serveur primaire envoie tous les enregistrements DNS pour la zone au serveur secondaire. Cela inclut des enregistrements comme A, AAAA, MX, CNAME, NS, etc.
4. **Fin du Transfert de Zone :**
   * Une fois tous les enregistrements transférés, le serveur primaire indique la fin du transfert de zone.
5. **Accusé de Réception (ACK) :**
   * Le serveur secondaire envoie un message d'accusé de réception au serveur primaire pour confirmer la réception et le traitement des données de la zone.

<mark style="color:green;">**Vulnérabilité des Transferts de Zone**</mark>

Bien que les transferts de zone soient importants pour la gestion des DNS, une mauvaise configuration peut en faire une vulnérabilité significative :

* **Problème de Sécurité :**
  * Si un serveur de noms autoritaire permet les transferts de zone à n'importe quel client, des attaquants peuvent obtenir une copie complète des enregistrements DNS, y compris les sous-domaines cachés, les adresses IP et les serveurs de noms.
* **Informations Révélées :**
  * **Sous-domaines :** Liste complète des sous-domaines, y compris ceux qui ne sont pas facilement découverts autrement.
  * **Adresses IP :** Les IP associées aux sous-domaines, utiles pour des attaques potentielles.
  * **Enregistrements de Serveurs de Noms :** Détails sur les serveurs de noms autoritaires, révélant le fournisseur d'hébergement et des configurations potentielles.

<figure><img src="../../.gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**Prévention et Remédiation**</mark>

Pour éviter les risques associés aux transferts de zone :

* **Restreindre les Transferts :** Configurez les serveurs DNS pour autoriser les transferts de zone uniquement aux serveurs secondaires de confiance.
* **Vérification Régulière :** Assurez-vous que les paramètres de transfert de zone sont correctement configurés et testez la sécurité régulièrement.

<mark style="color:green;">**Exemple de Commande pour Demander un Transfert de Zone**</mark>

Vous pouvez utiliser l'outil `dig` pour tenter de réaliser un transfert de zone. Exemple de commande :

```bash
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

* **`axfr`** : Indique un transfert de zone complet.
* **`@nsztm1.digi.ninja`** : Spécifie le serveur DNS à interroger.
* **`zonetransfer.me`** : Le domaine pour lequel le transfert est demandé.

<mark style="color:green;">**Exemple de Réponse à une Demande de Transfert de Zone :**</mark>

{% code overflow="wrap" %}
```plaintext
; <<>> DiG 9.18.12-1~bpo11+1-Debian <<>> axfr @nsztm1.digi.ninja zonetransfer.me
; (1 server found)
;; global options: +cmd
zonetransfer.me.	7200	IN	SOA	nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
zonetransfer.me.	300	IN	HINFO	"Casio fx-700G" "Windows XP"
zonetransfer.me.	301	IN	TXT	"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
zonetransfer.me.	7200	IN	MX	0 ASPMX.L.GOOGLE.COM.
zonetransfer.me.	7200	IN	A	5.196.105.14
zonetransfer.me.	7200	IN	NS	nsztm1.digi.ninja.
zonetransfer.me.	7200	IN	NS	nsztm2.digi.ninja.
...
```
{% endcode %}
