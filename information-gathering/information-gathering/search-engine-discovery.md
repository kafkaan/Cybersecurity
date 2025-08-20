# Search Engine Discovery

***

**Définition :** Search Engine Discovery, ou collecte d'OSINT (Open Source Intelligence), utilise les moteurs de recherche pour extraire des informations sur des sites web, des organisations ou des individus. Cette méthode permet de découvrir des données précieuses qui ne sont pas forcément visibles directement sur les sites web.

***

### <mark style="color:blue;">**Pourquoi Search Engine Discovery est Important :**</mark>

1. **Source Ouverte :** Informations accessibles publiquement, donc légales et éthiques.
2. **Largeur de l'Information :** Les moteurs de recherche indexent une grande partie du web, offrant une multitude de sources potentielles.
3. **Facilité d'Utilisation :** Les moteurs de recherche sont conviviaux et ne nécessitent pas de compétences techniques spécifiques.
4. **Coût Efficace :** Ressource gratuite et facilement disponible pour la collecte d'informations.

***

### <mark style="color:blue;">**Applications de Search Engine Discovery :**</mark>

1. **Évaluation de la Sécurité :** Identification de vulnérabilités, données exposées, et vecteurs d'attaque potentiels.
2. **Intelligence Concurrentielle :** Collecte d'informations sur les produits, services et stratégies des concurrents.
3. **Journalisme d'Investigation :** Découverte de connexions cachées, transactions financières et pratiques non éthiques.
4. **Renseignement sur les Menaces :** Identification des menaces émergentes, suivi des acteurs malveillants, et prédiction des attaques potentielles.

***

## <mark style="color:red;">**Opérateurs de Recherche :**</mark>

Les opérateurs de recherche sont des commandes spéciales qui permettent de cibler précisément certains types d'informations. Voici quelques opérateurs essentiels et avancés :

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Opérateur</strong></td><td><strong>Description</strong></td><td><strong>Exemple</strong></td><td><strong>Description de l'Exemple</strong></td></tr><tr><td><strong>site:</strong></td><td>Limite les résultats à un site ou domaine spécifique.</td><td>site.com</td><td>Trouve toutes les pages accessibles publiquement sur example.com.</td></tr><tr><td><strong>inurl:</strong></td><td>Trouve les pages avec un terme spécifique dans l'URL.</td><td>inurl</td><td>Recherche des pages de connexion sur n'importe quel site.</td></tr><tr><td><strong>filetype:</strong></td><td>Recherche des fichiers d'un type particulier.</td><td>filetype</td><td>Trouve des documents PDF téléchargeables.</td></tr><tr><td><strong>intitle:</strong></td><td>Trouve des pages avec un terme spécifique dans le titre.</td><td>intitle:"confidential report"</td><td>Cherche des documents intitulés "confidential report".</td></tr><tr><td><strong>intext:</strong> ou <strong>inbody:</strong></td><td>Recherche un terme dans le texte du corps des pages.</td><td>intext:"password reset"</td><td>Identifie les pages contenant le terme "password reset".</td></tr><tr><td><strong>cache:</strong></td><td>Affiche la version en cache d'une page web.</td><td>cache.com</td><td>Voir la version en cache de example.com.</td></tr><tr><td><strong>link:</strong></td><td>Trouve les pages qui lient à une page spécifique.</td><td>link.com</td><td>Identifie les sites liant à example.com.</td></tr><tr><td><strong>related:</strong></td><td>Trouve les sites web liés à une page spécifique.</td><td>related.com</td><td>Découvre des sites similaires à example.com.</td></tr><tr><td><strong>info:</strong></td><td>Fournit un résumé d'informations sur une page web.</td><td>info.com</td><td>Obtiens des détails de base sur example.com.</td></tr><tr><td><strong>define:</strong></td><td>Fournit des définitions d'un mot ou d'une phrase.</td><td>define</td><td>Obtiens une définition de "phishing".</td></tr><tr><td><strong>numrange:</strong></td><td>Recherche des nombres dans une plage spécifique.</td><td>site.com numrange:1000-2000</td><td>Trouve des pages sur example.com contenant des nombres entre 1000 et 2000.</td></tr><tr><td><strong>allintext:</strong></td><td>Trouve des pages contenant tous les mots spécifiés dans le texte du corps.</td><td>allintextpassword reset</td><td>Cherche des pages contenant "admin" et "password reset" dans le texte.</td></tr><tr><td><strong>allinurl:</strong></td><td>Trouve des pages contenant tous les mots spécifiés dans l'URL.</td><td>allinurlpanel</td><td>Cherche des pages avec "admin" et "panel" dans l'URL.</td></tr><tr><td><strong>allintitle:</strong></td><td>Trouve des pages contenant tous les mots spécifiés dans le titre.</td><td>allintitlereport 2023</td><td>Cherche des pages avec "confidential," "report," et "2023" dans le titre.</td></tr><tr><td><strong>AND</strong></td><td>Réduit les résultats en exigeant la présence de tous les termes.</td><td>site.com AND (inurlOR inurl)</td><td>Trouve des pages admin ou login spécifiquement sur example.com.</td></tr><tr><td><strong>OR</strong></td><td>Élargit les résultats en incluant les pages avec n'importe quel terme.</td><td>"linux" OR "ubuntu" OR "debian"</td><td>Recherche des pages mentionnant Linux, Ubuntu, ou Debian.</td></tr><tr><td><strong>NOT</strong></td><td>Exclut les résultats contenant le terme spécifié.</td><td>site.com NOT inurl</td><td>Trouve des pages sur bank.com excluant les pages de connexion.</td></tr><tr><td><strong>*</strong> (wildcard)</td><td>Représente n'importe quel caractère ou mot.</td><td>site.com filetypeuser* manual</td><td>Recherche des manuels utilisateurs (guide utilisateur, manuel d'utilisateur) en PDF sur socialnetwork.com.</td></tr><tr><td><strong>..</strong> (range search)</td><td>Trouve des résultats dans une plage numérique spécifiée.</td><td>site.com "price" 100..500</td><td>Cherche des produits entre 100 et 500 sur un site e-commerce.</td></tr><tr><td><strong>" "</strong> (guillemets)</td><td>Recherche des phrases exactes.</td><td>"information security policy"</td><td>Trouve des documents mentionnant précisément "information security policy".</td></tr><tr><td><strong>-</strong> (signe moins)</td><td>Exclut les termes des résultats de recherche.</td><td>site.com -inurl</td><td>Recherche des articles de news sur news.com en excluant le contenu sportif.</td></tr></tbody></table>

***

## <mark style="color:red;">**Google Dorking**</mark>

**Définition :** Google Dorking, ou Google Hacking, utilise les opérateurs de recherche pour découvrir des informations sensibles, des vulnérabilités de sécurité ou du contenu caché sur les sites web, en utilisant Google Search.

<mark style="color:green;">**Exemples Communs de Google Dorks :**</mark>

1. **Trouver des Pages de Connexion :**
   * `site:example.com inurl:login`
   * `site:example.com (inurl:login OR inurl:admin)`
2. **Identifier des Fichiers Exposés :**
   * `site:example.com filetype:pdf`
   * `site:example.com (filetype:xls OR filetype:docx)`
3. **Découvrir des Fichiers de Configuration :**
   * `site:example.com inurl:config.php`
   * `site:example.com (ext:conf OR ext:cnf)`
4. **Localiser des Sauvegardes de Base de Données :**
   * `site:example.com inurl:backup`
   * `site:example.com filetype:sql`

***
