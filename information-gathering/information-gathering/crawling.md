# Crawling

***

## <mark style="color:red;">**Définition**</mark>

**Crawling** (ou spidering) est le processus automatisé de navigation systématique sur le World Wide Web. Un crawler, ou robot d'exploration, utilise des algorithmes prédéfinis pour découvrir et indexer les pages web, les rendant accessibles via les moteurs de recherche ou pour des analyses de données et des reconnaissances web.

***

## <mark style="color:red;">**Fonctionnement des Crawlers**</mark>

1. **URL de départ**: Le crawler commence par une URL initiale (seed URL).
2. **Extraction de liens**: Il récupère la page, analyse son contenu, et extrait tous les liens présents.
3. **Ajout à la file d'attente**: Ces liens sont ajoutés à une file d'attente.
4. **Exploration itérative**: Le crawler visite ces liens un par un, répétant le processus.

<mark style="color:green;">Illustration</mark>:

*   **Homepage**: Contient `link1`, `link2`, et `link3`.

    ```plaintext
    Homepage
    ├── link1
    ├── link2
    └── link3
    ```
*   **Visite de `link1`**: Affiche la page d'accueil, `link2`, ainsi que `link4` et `link5`.

    ```plaintext
    Link1 Page
    ├── Homepage
    ├── link2
    ├── link4
    └── link5
    ```

***

## <mark style="color:red;">**Stratégies de Crawling**</mark>

1. <mark style="color:green;">**Crawling en largeur (Breadth-First Crawling)**</mark>
   * Priorité à l'exploration de tous les liens d'une page avant de passer aux pages suivantes.
   * Idéal pour obtenir une vue d'ensemble de la structure et du contenu d'un site.
2. <mark style="color:green;">**Crawling en profondeur (Depth-First Crawling)**</mark>
   * Priorité à l'exploration d'une chaîne de liens aussi loin que possible avant de revenir en arrière.
   * Utile pour trouver du contenu spécifique ou atteindre les pages profondes d'un site.

***

## <mark style="color:red;">**Extraction d'informations précieuses**</mark>

1. <mark style="color:green;">**Liens (internes et externes)**</mark>
   * Cartographie de la structure d'un site, découverte de pages cachées, identification de relations avec des ressources externes.
2. <mark style="color:green;">**Commentaires**</mark>
   * Les sections de commentaires peuvent révéler des informations sensibles ou des indices de vulnérabilités.
3. <mark style="color:green;">**Métadonnées**</mark>
   * Informations comme les titres de pages, descriptions, mots-clés, noms d'auteurs, et dates fournissant un contexte sur le contenu et la pertinence des pages.
4. <mark style="color:green;">**Fichiers sensibles**</mark>
   * Recherche de fichiers sensibles (e.g., `.bak`, `.old`, `web.config`, `settings.php`, `error_log`, `access_log`), souvent exposés par inadvertance.

***

## <mark style="color:red;">Robots.txt</mark>

<mark style="color:green;">**Définition**</mark>

Le fichier `robots.txt` est un fichier texte simple placé à la racine d'un site web (par exemple, `www.example.com/robots.txt`). Il suit le standard d'exclusion des robots (Robots Exclusion Standard), définissant des directives indiquant aux bots quelles parties du site ils peuvent ou ne peuvent pas explorer.

***

### <mark style="color:blue;">**Fonctionnement de**</mark><mark style="color:blue;">**&#x20;**</mark><mark style="color:blue;">**`robots.txt`**</mark>

1. **User-Agent**: Spécifie à quel crawler ou bot s'appliquent les règles suivantes. Un joker (\*) indique que les règles s'appliquent à tous les bots. Des user-agents spécifiques comme "Googlebot" (le crawler de Google) ou "Bingbot" (le crawler de Microsoft) peuvent également être ciblés.
2. **Directives**: Fournissent des instructions spécifiques au user-agent identifié. Les directives communes incluent :
   * **Disallow**: Indique les chemins que le bot ne doit pas explorer.
   * **Allow**: Permet explicitement au bot d'explorer des chemins spécifiques, même s'ils sont couverts par une règle Disallow plus large.
   * **Crawl-delay**: Définit un délai (en secondes) entre les requêtes successives du bot pour éviter de surcharger le serveur.
   * **Sitemap**: Fournit l'URL d'un sitemap XML pour un crawl plus efficace.

<mark style="color:green;">**Exemple**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

```txt
User-agent: *
Disallow: /private/
```

Cette directive indique à tous les user-agents ( \* étant un joker) de ne pas accéder aux URL commençant par `/private/`.

***

<mark style="color:green;">**Structure de**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`robots.txt`**</mark>

Le fichier `robots.txt` suit une structure simple :

* Chaque ensemble d'instructions, ou "enregistrement", est séparé par une ligne vide.
* Chaque enregistrement comprend deux composants principaux :
  * **User-agent**: Spécifie le bot cible.
  * **Directives**: Fournissent des instructions spécifiques.

<mark style="color:green;">**Exemple de directives**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

<table data-full-width="true"><thead><tr><th>Directive</th><th>Description</th><th>Exemple</th></tr></thead><tbody><tr><td>Disallow</td><td>Spécifie les chemins que le bot ne doit pas explorer</td><td><code>Disallow: /admin/</code></td></tr><tr><td>Allow</td><td>Permet au bot d'explorer des chemins spécifiques, même s'ils sont disallow</td><td><code>Allow: /public/</code></td></tr><tr><td>Crawl-delay</td><td>Définit un délai entre les requêtes successives du bot</td><td><code>Crawl-delay: 10</code></td></tr><tr><td>Sitemap</td><td>Fournit l'URL d'un sitemap pour un crawl plus efficace</td><td><code>Sitemap: https://www.example.com/sitemap.xml</code></td></tr></tbody></table>

***

#### <mark style="color:green;">**Exemple de**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`robots.txt`**</mark>

```txt
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Googlebot
Crawl-delay: 10

Sitemap: https://www.example.com/sitemap.xml
```

***

## <mark style="color:red;">Les URIs Bien Connus (</mark><mark style="color:red;">`.well-known`</mark><mark style="color:red;">)</mark>

***

<mark style="color:green;">**Définition et Fonction**</mark>

Les URIs bien connus (`.well-known`), définis dans la RFC 8615, désignent un répertoire standardisé au sein du domaine racine d'un site web. Accessible via le chemin `/.well-known/` sur un serveur web, ce répertoire centralise les métadonnées critiques du site, incluant les fichiers de configuration et les informations liées à ses services, protocoles et mécanismes de sécurité.

<mark style="color:green;">**Objectif**</mark> :

* Simplifier la découverte et l'accès aux données importantes pour divers intervenants (navigateurs web, applications, outils de sécurité).
* Permettre aux clients de localiser et récupérer automatiquement des fichiers de configuration spécifiques en construisant l'URL appropriée, par exemple `https://example.com/.well-known/security.txt` pour accéder à la politique de sécurité d'un site.

<mark style="color:green;">**Gestion**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

* L'Internet Assigned Numbers Authority (IANA) maintient un registre des URIs `.well-known`, chaque entrée servant un but spécifique défini par diverses spécifications et normes.

***

**Exemples Notables d'URIs .well-known**

<table data-full-width="true"><thead><tr><th>URI Suffix</th><th>Description</th><th>Statut</th><th>Référence</th></tr></thead><tbody><tr><td><strong>security.txt</strong></td><td>Contient les informations de contact pour les chercheurs en sécurité.</td><td>Permanent</td><td>RFC 9116</td></tr><tr><td><strong>change-password</strong></td><td>Fournit une URL standard pour diriger les utilisateurs vers une page de changement de mot de passe.</td><td>Provisoire</td><td><a href="https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri">W3C Change Password URL</a></td></tr><tr><td><strong>openid-configuration</strong></td><td>Définit les détails de configuration pour OpenID Connect.</td><td>Permanent</td><td><a href="http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery</a></td></tr><tr><td><strong>assetlinks.json</strong></td><td>Utilisé pour vérifier la propriété des actifs numériques associés à un domaine.</td><td>Permanent</td><td><a href="https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md">Google Digital Asset Links</a></td></tr><tr><td><strong>mta-sts.txt</strong></td><td>Spécifie la politique pour SMTP MTA Strict Transport Security (MTA-STS) pour améliorer la sécurité des emails.</td><td>Permanent</td><td>RFC 8461</td></tr></tbody></table>

***

### <mark style="color:blue;">**Utilisation des URIs .well-known dans la Reconnaissance Web**</mark>

<mark style="color:green;">**Importance**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

* **Découverte d'Endpoints et de Détails de Configuration** : Les URIs `.well-known` peuvent révéler des points d'accès et des informations de configuration cruciales pour les tests de pénétration.

<mark style="color:green;">Exemple : openid-configuration</mark>

* **Fonction** : Fait partie du protocole OpenID Connect Discovery, une couche d'identité sur le protocole OAuth 2.0.
* **Utilisation** : Les applications clientes utilisent cette configuration pour l'authentification en récupérant les détails du fournisseur OpenID Connect via l'endpoint `https://example.com/.well-known/openid-configuration`.

**Exemple de Réponse JSON** :

```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/oauth2/authorize",
  "token_endpoint": "https://example.com/oauth2/token",
  "userinfo_endpoint": "https://example.com/oauth2/userinfo",
  "jwks_uri": "https://example.com/oauth2/jwks",
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"]
}
```

<mark style="color:green;">**Informations Utiles**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

* **Découverte des Endpoints** :
  * `authorization_endpoint` : URL pour les demandes d'autorisation des utilisateurs.
  * `token_endpoint` : URL où les tokens sont émis.
  * `userinfo_endpoint` : Endpoint fournissant les informations de l'utilisateur.
  * `jwks_uri` : URI pour le JSON Web Key Set, détaillant les clés cryptographiques utilisées par le serveur.
* <mark style="color:green;">**Détails des Scopes et Types de Réponse**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * Comprendre les scopes et types de réponse supportés aide à cartographier les fonctionnalités et limitations de l'implémentation OpenID Connect.
* <mark style="color:green;">**Détails sur les Algorithmes**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * Informations sur les algorithmes de signature supportés, cruciales pour comprendre les mesures de sécurité en place.

***

## <mark style="color:red;">Web Crawlers et Utilisation de Scrapy</mark>

***

### <mark style="color:blue;">**Outils de Web Crawling Populaires**</mark>

1. <mark style="color:green;">**Burp Suite Spider :**</mark>
   * **Description :** Outil intégré dans Burp Suite, une plateforme largement utilisée pour tester les applications web.
   * **Points Forts :** Mapping des applications web, identification de contenu caché, détection de vulnérabilités potentielles.
2. <mark style="color:green;">**OWASP ZAP (Zed Attack Proxy) :**</mark>
   * **Description :** Scanner de sécurité pour applications web, gratuit et open-source.
   * **Points Forts :** Utilisable en modes automatisé et manuel, inclut un composant spider pour identifier les vulnérabilités.
3. <mark style="color:green;">**Scrapy (Framework Python) :**</mark>
   * **Description :** Framework Python flexible et évolutif pour créer des crawlers personnalisés.
   * **Points Forts :** Extraction de données structurées, gestion de scénarios complexes de crawling, automatisation du traitement des données.
4. <mark style="color:green;">**Apache Nutch :**</mark>
   * **Description :** Crawler open-source extensible et évolutif écrit en Java.
   * **Points Forts :** Capable de gérer des crawls massifs à travers tout le web ou sur des domaines spécifiques, nécessite une expertise technique pour la configuration.

***

### <mark style="color:blue;">**Utilisation de Scrapy pour le Crawling Web**</mark>

1. <mark style="color:green;">**Installation de Scrapy :**</mark>
   *   Commande pour installer Scrapy :

       ```bash
       pip3 install scrapy
       ```
2. <mark style="color:green;">**Téléchargement de ReconSpider :**</mark>
   *   Commande pour télécharger et extraire ReconSpider :

       ```bash
       wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
       unzip ReconSpider.zip
       ```
3. <mark style="color:green;">**Exécution de ReconSpider :**</mark>
   *   Commande pour exécuter ReconSpider :

       ```bash
       python3 ReconSpider.py http://inlanefreight.com
       ```
   * **Remplacer** `inlanefreight.com` par le domaine cible que vous souhaitez crawler.
4. <mark style="color:green;">**Analyse des Résultats :**</mark>
   * Les données collectées seront enregistrées dans un fichier JSON `results.json`.
   *   Structure du fichier JSON :

       ```json
       {
           "emails": [
               "lily.floid@inlanefreight.com",
               "cvs@inlanefreight.com",
               ...
           ],
           "links": [
               "https://www.themeansar.com",
               "https://www.inlanefreight.com/index.php/offices/",
               ...
           ],
           "external_files": [
               "https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf",
               ...
           ],
           "js_files": [
               "https://www.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2",
               ...
           ],
           "form_fields": [],
           "images": [
               "https://www.inlanefreight.com/wp-content/uploads/2021/03/AboutUs_01-1024x810.png",
               ...
           ],
           "videos": [],
           "audio": [],
           "comments": [
               "<!-- #masthead -->",
               ...
           ]
       }
       ```

<mark style="color:green;">**Clés JSON et Description :**</mark>

| JSON Key            | Description                                                |
| ------------------- | ---------------------------------------------------------- |
| **emails**          | Adresses email trouvées sur le domaine.                    |
| **links**           | URLs des liens trouvés sur le domaine.                     |
| **external\_files** | URLs des fichiers externes (e.g., PDFs).                   |
| **js\_files**       | URLs des fichiers JavaScript utilisés par le site.         |
| **form\_fields**    | Champs de formulaire trouvés sur le domaine (vide ici).    |
| **images**          | URLs des images trouvées sur le domaine.                   |
| **videos**          | URLs des vidéos trouvées sur le domaine (vide ici).        |
| **audio**           | URLs des fichiers audio trouvés sur le domaine (vide ici). |
| **comments**        | Commentaires HTML trouvés dans le code source.             |
