# Les API Web (Web APIs)

### <mark style="color:blue;">Définition</mark>

Une **API Web** (Web Application Programming Interface) est un ensemble de règles et de spécifications qui permettent à différentes applications logicielles de communiquer via le web. Elle fonctionne comme un langage universel, permettant à divers composants logiciels d'échanger des données et des services de manière transparente, indépendamment de leurs technologies ou langages de programmation sous-jacents.

#### <mark style="color:green;">Rôle</mark>

L'API Web sert de **pont** entre :

* **Le serveur** : héberge les données et les fonctionnalités
* **Le client** : navigateur web, application mobile, ou autre serveur qui souhaite accéder ou utiliser ces données

***

### <mark style="color:blue;">Types d'API Web</mark>

#### <mark style="color:green;">1. REST (Representational State Transfer)</mark>

**Architecture populaire** pour la création de services web.

**Caractéristiques :**

* Modèle de communication **sans état** (stateless) client-serveur
* Utilise les **méthodes HTTP standard** : GET, POST, PUT, DELETE
* Effectue les opérations **CRUD** (Create, Read, Update, Delete)
* Les ressources sont identifiées par des **URLs uniques**
* Échange de données en formats légers : **JSON ou XML**
* Facile à intégrer avec diverses applications et plateformes

**Exemple de requête :**

```http
GET /users/123
```

***

#### <mark style="color:green;">2. SOAP (Simple Object Access Protocol)</mark>

**Protocole formel et standardisé** pour l'échange d'informations structurées.

**Caractéristiques :**

* Utilise **XML** pour définir les messages
* Messages encapsulés dans des **enveloppes SOAP**
* Transmission via protocoles réseau : **HTTP ou SMTP**
* Fonctionnalités intégrées :
  * Sécurité
  * Fiabilité
  * Gestion des transactions
* Adapté aux **applications d'entreprise** nécessitant une intégrité stricte des données

**Exemple de requête :**

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                  xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
      <tem:GetStockPrice>
         <tem:StockName>AAPL</tem:StockName>
      </tem:GetStockPrice>
   </soapenv:Body>
</soapenv:Envelope>
```

***

#### <mark style="color:green;">3. GraphQL</mark>

**Langage de requête** et runtime relativement récent pour les API.

**Caractéristiques :**

* **Point de terminaison unique** (contrairement à REST avec plusieurs endpoints)
* Les clients demandent exactement les données dont ils ont besoin
* Langage de requête **flexible**
* Élimine les problèmes de :
  * **Sur-récupération** (over-fetching)
  * **Sous-récupération** (under-fetching)
* **Typage fort** et capacités d'introspection
* Facilite l'évolution des API sans casser les clients existants
* Populaire pour les applications web et mobiles modernes

**Exemple de requête :**

```graphql
query {
  user(id: 123) {
    name
    email
  }
}
```

***

### <mark style="color:blue;">Avantages des API Web</mark>

#### 1. Standardisation

Fournissent des moyens standardisés pour que les clients accèdent et manipulent les données stockées sur le serveur.

#### 2. Réutilisabilité du Code

Permettent aux développeurs d'exposer des fonctionnalités spécifiques à des utilisateurs externes ou d'autres applications.

#### 3. Intégration de Services Tiers

Facilitent l'intégration de services externes :

* Connexion via réseaux sociaux
* Traitement sécurisé des paiements
* Fonctionnalités de cartographie

#### 4. Architecture Microservices

Les API sont la **pierre angulaire** de l'architecture microservices :

* Applications monolithiques divisées en services plus petits et indépendants
* Communication via des API bien définies
* Améliore la **scalabilité**, la **flexibilité** et la **résilience**

### <mark style="color:blue;">Différences : Serveur Web vs API</mark>

| **Caractéristique**         | **Serveur Web**                                                            | **API**                                                                                               |
| --------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **Objectif**                | Servir du contenu statique (HTML, CSS, images) et des pages web dynamiques | Permettre aux applications logicielles de communiquer, échanger des données et déclencher des actions |
| **Communication**           | HTTP (Hypertext Transfer Protocol) avec les navigateurs                    | Divers protocoles : HTTP, HTTPS, SOAP, etc.                                                           |
| **Format de Données**       | HTML, CSS, JavaScript, formats web                                         | JSON, XML, et autres formats selon les spécifications                                                 |
| **Interaction Utilisateur** | Directe via navigateurs web                                                | Indirecte : les applications utilisent les API au nom de l'utilisateur                                |
| **Accès**                   | Généralement publiquement accessible sur Internet                          | Peut être public, privé (usage interne) ou partenaire (accès spécifique)                              |
| **Exemple**                 | Accéder à https://www.example.com pour voir une page web                   | Une application météo utilise une API météo pour récupérer des données                                |

#### <mark style="color:green;">Exemple Pratique</mark>

**Serveur Web** : Lorsque vous accédez à un site web, le serveur vous envoie le code HTML, CSS et JavaScript pour afficher la page dans votre navigateur.

**API** : Une application météo sur votre téléphone utilise une API météo pour récupérer les données d'un serveur distant. L'application traite ces données et les affiche dans un format convivial. Vous n'interagissez pas directement avec l'API, mais l'application l'utilise en arrière-plan.

***

### <mark style="color:blue;">Implications pour le Fuzzing</mark>

En comprenant ces différences, vous pouvez adapter votre approche de fuzzing :

#### Pour les Serveurs Web :

* Fuzzing de répertoires et fichiers cachés

#### Pour les API :

* **Focus sur les endpoints** de l'API et leurs paramètres
* **Attention aux formats de données** utilisés dans les requêtes et réponses (JSON, XML)
* Test des différentes méthodes HTTP (GET, POST, PUT, DELETE)
* Analyse de la structure des requêtes et réponses

### <mark style="color:blue;">Points Clés à Retenir</mark>

* Les API Web sont essentielles à l'écosystème web moderne
* Chaque type d'API (REST, SOAP, GraphQL) a ses propres forces et cas d'usage
* Les API diffèrent fondamentalement des serveurs web traditionnels
* Comprendre ces différences est crucial pour un fuzzing efficace
* Les API favorisent l'intégration, la modularité et la scalabilité des applications

***

## <mark style="color:red;">Identification des Endpoints d'API</mark>

### <mark style="color:blue;">Introduction</mark>

Avant de commencer le fuzzing d'API Web, vous devez savoir où chercher. **L'identification des endpoints** exposés par l'API est la première étape cruciale. Cela nécessite un travail de détective, mais plusieurs méthodes peuvent aider à découvrir ces portes cachées vers les données et fonctionnalités de l'application.

***

### <mark style="color:blue;">API REST</mark>

#### <mark style="color:green;">Structure des Endpoints</mark>

Les API REST sont construites autour du concept de **ressources**, identifiées par des URLs uniques appelées endpoints.

**Exemples de Structure Hiérarchique :**

* `/users` → Collection de ressources utilisateurs
* `/users/123` → Utilisateur spécifique avec l'ID 123
* `/products` → Collection de ressources produits
* `/products/456` → Produit spécifique avec l'ID 456

#### <mark style="color:green;">Types de Paramètres REST</mark>

| **Type**                    | **Description**                                                                                            | **Exemple**                                 |
| --------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| **Query Parameters**        | Ajoutés à l'URL après un point d'interrogation (?). Utilisés pour le filtrage, le tri ou la pagination     | `/users?limit=10&sort=name`                 |
| **Path Parameters**         | Intégrés directement dans l'URL. Utilisés pour identifier des ressources spécifiques                       | `/products/{id}`                            |
| **Request Body Parameters** | Envoyés dans le corps des requêtes POST, PUT ou PATCH. Utilisés pour créer ou mettre à jour des ressources | `{ "name": "New Product", "price": 99.99 }` |

#### <mark style="color:green;">Découverte des Endpoints et Paramètres REST</mark>

**1. Documentation de l'API**

* Méthode la plus fiable
* Liste des endpoints disponibles
* Paramètres, formats de requête/réponse attendus
* Exemples d'utilisation
* Spécifications : **Swagger (OpenAPI)** ou **RAML**

**2. Analyse du Trafic Réseau**

* Si la documentation est indisponible ou incomplète
* **Outils** : Burp Suite, outils de développement du navigateur
* Intercepter et inspecter les requêtes/réponses API
* Révèle les endpoints, paramètres et formats de données

**3. Fuzzing de Noms de Paramètres**

* Similaire au fuzzing de répertoires et fichiers
* **Outils** : ffuf, wfuzz avec des wordlists appropriées
* Découvrir des paramètres cachés ou non documentés

***

### <mark style="color:blue;">API SOAP</mark>

#### <mark style="color:green;">Structure des Endpoints SOAP</mark>

Contrairement aux API REST, les API SOAP :

* Exposent généralement **un seul endpoint**
* Utilisent des messages basés sur **XML**
* Utilisent **WSDL** (Web Services Description Language) pour définir leurs interfaces

Le contenu du message SOAP détermine l'opération spécifique à effectuer.

#### <mark style="color:green;">Paramètres SOAP</mark>

Les paramètres sont définis dans le corps du message SOAP (document XML) :

* Organisés en **éléments** et **attributs**
* Structure hiérarchique
* Définis dans le fichier **WSDL**

#### <mark style="color:green;">Exemple : API de Bibliothèque</mark>

**Opération** : `SearchBooks`

**Paramètres d'entrée** :

* `keywords` (string) : Termes de recherche
* `author` (string) : Nom de l'auteur (optionnel)
* `genre` (string) : Genre du livre (optionnel)

**Requête SOAP** :

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                  xmlns:lib="http://example.com/library">
   <soapenv:Header/>
   <soapenv:Body>
      <lib:SearchBooks>
         <lib:keywords>cybersecurity</lib:keywords>
         <lib:author>Dan Kaminsky</lib:author>
      </lib:SearchBooks>
   </soapenv:Body>
</soapenv:Envelope>
```

#### <mark style="color:green;">Découverte des Endpoints et Paramètres SOAP</mark>

**1. Analyse WSDL**

Ressource la plus précieuse. Le fichier WSDL décrit :

* Opérations disponibles (endpoints)
* Paramètres d'entrée (types de messages, éléments, attributs)
* Paramètres de sortie (types de messages de réponse)
* Types de données utilisés
* Localisation (URL) de l'endpoint SOAP

**Méthode** : Analyse manuelle ou outils de parsing WSDL

**2. Analyse du Trafic Réseau**

* **Outils** : Wireshark, tcpdump
* Capturer le trafic SOAP
* Examiner la structure des messages SOAP
* Extraire les informations sur les endpoints et paramètres

**3. Fuzzing**

* Utile même avec une structure bien définie
* Découvrir des opérations ou paramètres cachés
* Envoyer des valeurs malformées ou inattendues
* Observer les réponses du serveur

***

### <mark style="color:blue;">API GraphQL</mark>

#### <mark style="color:green;">Structure des Endpoints GraphQL</mark>

GraphQL offre plus de **flexibilité** et d'**efficacité** que REST et SOAP :

* Généralement **un seul endpoint** : `/graphql`
* Point d'entrée pour toutes les requêtes et mutations
* Les clients demandent précisément les données nécessaires en une seule requête

#### <mark style="color:green;">GraphQL Queries (Requêtes)</mark>

Conçues pour **récupérer des données** du serveur.

**Composants des Queries**

| **Composant**     | **Description**                             | **Exemple**             |
| ----------------- | ------------------------------------------- | ----------------------- |
| **Field**         | Donnée spécifique à récupérer               | `name`, `email`         |
| **Relationship**  | Connexion entre différents types de données | `posts`                 |
| **Nested Object** | Champ retournant un autre objet             | `posts { title, body }` |
| **Argument**      | Modifie le comportement d'une requête       | `posts(limit: 5)`       |

**Exemple de Query :**

```graphql
query {
  user(id: 123) {
    name
    email
    posts(limit: 5) {
      title
      body
    }
  }
}
```

**Explication** :

* Requête pour un utilisateur avec l'ID 123
* Récupère son nom et email
* Récupère ses 5 premiers posts (titre et corps)

#### <mark style="color:green;">GraphQL Mutations</mark>

Conçues pour **modifier des données** sur le serveur (créer, mettre à jour, supprimer).

**Composants des Mutations**

| **Composant** | **Description**                      | **Exemple**                                 |
| ------------- | ------------------------------------ | ------------------------------------------- |
| **Operation** | Action à effectuer                   | `createPost`, `updateUser`, `deleteComment` |
| **Argument**  | Données d'entrée requises            | `title: "New Post"`                         |
| **Selection** | Champs à récupérer après l'opération | `id`, `title`                               |

**Exemple de Mutation :**

```graphql
mutation {
  createPost(title: "New Post", body: "This is the content of the new post") {
    id
    title
  }
}
```

**Résultat** : Crée un nouveau post et retourne son `id` et `title`.

#### <mark style="color:green;">Découverte des Queries et Mutations GraphQL</mark>

**1. Introspection**

* Système d'introspection intégré à GraphQL
* Envoyer une requête d'introspection à l'endpoint
* Récupère le schéma complet de l'API :
  * Types disponibles
  * Champs
  * Queries et mutations
  * Arguments
* **Outils** : Auto-complétion, validation, documentation

**2. Documentation de l'API**

* Guides et références complets
* Explique l'objectif et l'utilisation des queries/mutations
* Exemples de structures valides
* Détails sur les arguments et formats de réponse
* **Outils** : GraphiQL, GraphQL Playground (environnements interactifs)

**3. Analyse du Trafic Réseau**

* Capturer et inspecter les requêtes/réponses vers `/graphql`
* Observer les queries et mutations réelles
* Comprendre le format attendu des requêtes
* Identifier les types de données retournées
* Aide à adapter les efforts de fuzzing

***

### <mark style="color:blue;">Comparaison Récapitulative</mark>

| **Aspect**             | **REST**           | **SOAP**     | **GraphQL**        |
| ---------------------- | ------------------ | ------------ | ------------------ |
| **Nombre d'Endpoints** | Multiple           | Unique       | Unique             |
| **Structure**          | URLs hiérarchiques | Messages XML | Langage de requête |
| **Documentation**      | Swagger/OpenAPI    | WSDL         | Introspection      |
| **Flexibilité**        | Modérée            | Rigide       | Très flexible      |
| **Format de Données**  | JSON/XML           | XML          | JSON               |

***

### <mark style="color:blue;">Points Clés à Retenir</mark>

* **REST** : Multiples endpoints avec structure hiérarchique
* **SOAP** : Endpoint unique avec messages XML et WSDL
* **GraphQL** : Endpoint unique avec flexibilité maximale via introspection
* La **documentation officielle** est toujours la meilleure source
* L'**analyse du trafic réseau** est cruciale en l'absence de documentation
* Le **fuzzing** peut révéler des paramètres cachés ou non documentés
* GraphQL privilégie la **flexibilité** : comprendre le schéma est essentiel

***

## <mark style="color:red;">Fuzzing d'API (API Fuzzing)</mark>

### <mark style="color:blue;">Définition</mark>

Le **fuzzing d'API** est une forme spécialisée de fuzzing adaptée aux API Web. Bien que les principes fondamentaux restent les mêmes (envoyer des entrées inattendues ou invalides), le fuzzing d'API se concentre sur la structure et les protocoles uniques utilisés par les API Web.

### <mark style="color:blue;">Principe de Fonctionnement</mark>

Le fuzzing d'API consiste à bombarder une API avec une série de tests automatisés. Chaque test envoie une requête légèrement modifiée à un endpoint de l'API.

#### <mark style="color:blue;">Types de Modifications</mark>

* Altération des valeurs de paramètres
* Modification des en-têtes de requête
* Changement de l'ordre des paramètres
* Introduction de types de données ou formats inattendus

#### <mark style="color:blue;">Objectif</mark>

Déclencher des erreurs, des plantages ou des comportements inattendus de l'API, révélant des vulnérabilités potentielles comme :

* Défauts de validation d'entrée
* Attaques par injection
* Problèmes d'authentification

***

### <mark style="color:blue;">Pourquoi Fuzzer les API ?</mark>

#### 1. Découvrir des Vulnérabilités Cachées

Les API ont souvent des endpoints et paramètres cachés ou non documentés susceptibles d'être attaqués.

#### 2. Tester la Robustesse

Évaluer la capacité de l'API à gérer gracieusement les entrées inattendues ou malformées sans planter ou exposer des données sensibles.

#### 3. Automatiser les Tests de Sécurité

Les tests manuels de toutes les combinaisons d'entrées possibles sont impossibles. Le fuzzing automatise ce processus.

#### 4. Simuler des Attaques Réelles

Le fuzzing imite les actions d'acteurs malveillants, permettant d'identifier les vulnérabilités avant que les attaquants ne les exploitent.

***

### <mark style="color:blue;">Types de Fuzzing d'API</mark>

#### 1. Parameter Fuzzing (Fuzzing de Paramètres)

**Technique principale** qui teste systématiquement différentes valeurs pour les paramètres de l'API.

**Cibles :**

* **Query parameters** : Ajoutés à l'URL de l'endpoint
* **Headers** : Contenant les métadonnées de la requête
* **Request bodies** : Contenant la charge utile de données

**Vulnérabilités Exposées :**

* Attaques par injection (SQL injection, command injection)
* Cross-Site Scripting (XSS)
* Falsification de paramètres (parameter tampering)

#### 2. Data Format Fuzzing (Fuzzing de Format de Données)

Cible les **formats de données structurés** comme JSON ou XML.

**Actions :**

* Manipulation de la structure des données
* Modification du contenu
* Altération de l'encodage

**Vulnérabilités Exposées :**

* Erreurs de parsing
* Buffer overflows
* Mauvaise gestion des caractères spéciaux

#### 3. Sequence Fuzzing (Fuzzing de Séquence)

Examine les **séquences de requêtes** vers des endpoints interconnectés.

**Focus :**

* Ordre des requêtes
* Timing des requêtes
* Paramètres des appels API

**Vulnérabilités Exposées :**

* Race conditions
* IDOR (Insecure Direct Object References)
* Contournement d'autorisation
* Failles dans la logique et la gestion d'état de l'API

***

### <mark style="color:blue;">Exemple Pratique : Fuzzing d'une API FastAPI</mark>

#### <mark style="color:green;">Documentation de l'API</mark>

L'API fournit une documentation automatique via l'endpoint `/docs` : `http://IP:PORT/docs`

**Endpoints Documentés :**

| **Méthode** | **Endpoint**       | **Fonction**                                      |
| ----------- | ------------------ | ------------------------------------------------- |
| GET         | `/`                | Récupère la ressource root (message de bienvenue) |
| GET         | `/items/{item_id}` | Récupère un item spécifique                       |
| DELETE      | `/items/{item_id}` | Supprime un item                                  |
| PUT         | `/items/{item_id}` | Met à jour un item existant                       |
| POST        | `/items/`          | Crée ou met à jour un item                        |

#### <mark style="color:green;">Endpoints Cachés</mark>

**Important** : Les API peuvent contenir des endpoints non documentés ou "cachés" :

* Fonctions internes non destinées à l'usage externe
* Tentative de sécurité par l'obscurité
* Endpoints en développement non prêts pour la publication

***

### <mark style="color:blue;">Processus de Fuzzing</mark>

#### <mark style="color:green;">Étape 1 : Installation du Fuzzer</mark>

```bash
git clone https://github.com/PandaSt0rm/webfuzz_api.git
cd webfuzz_api
pip3 install -r requirements.txt
```

#### <mark style="color:green;">Étape 2 : Exécution du Fuzzer</mark>

```bash
python3 api_fuzzer.py http://IP:PORT
```

#### <mark style="color:green;">Étape 3 : Analyse des Résultats</mark>

**Exemple de sortie** :

```
[-] Invalid endpoint: http://localhost:8000/~webmaster (Status code: 404)
[-] Invalid endpoint: http://localhost:8000/~www (Status code: 404)

Fuzzing completed.
Total requests: 4730
Failed requests: 0
Retries: 0
Status code counts:
404: 4727
200: 2
405: 1
Found valid endpoints:
- http://localhost:8000/cz...
- http://localhost:8000/docs
Unusual status codes:
405: http://localhost:8000/items
```

**Interprétation :**

* **404 (Not Found)** : Nombreux endpoints invalides identifiés
* **200 (OK)** : Deux endpoints valides découverts :
  * `/cz...` : **Endpoint non documenté** (absent de la documentation)
  * `/docs` : Endpoint documenté (Swagger UI)
* **405 (Method Not Allowed)** : Méthode HTTP incorrecte utilisée pour `/items`

#### <mark style="color:green;">Étape 4 : Exploration de l'Endpoint Caché</mark>

```bash
curl http://localhost:8000/cz...
```

**Réponse** :

```json
{"flag":"<snip>"}
```

***

### <mark style="color:blue;">Vulnérabilités Découvrables par Fuzzing</mark>

#### 1. Broken Object-Level Authorization

Manipulation de valeurs de paramètres permettant un accès non autorisé à des objets ou ressources spécifiques.

#### 2. Broken Function Level Authorization

Découverte de cas où des appels de fonction non autorisés peuvent être effectués en manipulant les paramètres.

#### 3. Server-Side Request Forgery (SSRF)

Injection de valeurs malveillantes dans des paramètres pour tromper le serveur et lui faire effectuer des requêtes non intentionnelles vers des ressources internes ou externes.

***

### <mark style="color:blue;">Codes de Statut HTTP Importants</mark>

| **Code** | **Signification**     | **Interprétation**                                  |
| -------- | --------------------- | --------------------------------------------------- |
| **200**  | OK                    | Endpoint valide et accessible                       |
| **404**  | Not Found             | Endpoint inexistant                                 |
| **405**  | Method Not Allowed    | Endpoint existe mais mauvaise méthode HTTP utilisée |
| **500**  | Internal Server Error | Erreur serveur potentielle (vulnérabilité ?)        |
| **403**  | Forbidden             | Accès refusé (problème d'autorisation ?)            |

***

### <mark style="color:blue;">Bonnes Pratiques</mark>

#### 1. Utiliser des Wordlists Appropriées

* Listes spécifiques aux API
* Noms de paramètres communs
* Endpoints typiques

#### 2. Analyser les Réponses

* Examiner les codes de statut inhabituels
* Identifier les patterns d'erreur
* Chercher les fuites d'information

#### 3. Tester Tous les Types de Paramètres

* Query parameters
* Path parameters
* Headers
* Request body

#### 4. Respecter l'Éthique

* Obtenir une autorisation avant de fuzzer
* Ne pas surcharger le serveur
* Documenter les vulnérabilités trouvées

***

### <mark style="color:blue;">Outils Recommandés</mark>

* **ffuf** : Fuzzer web rapide et flexible
* **wfuzz** : Fuzzer d'applications web
* **Burp Suite** : Suite complète pour les tests de sécurité
* **OWASP ZAP** : Proxy de sécurité open-source
* **Fuzzers personnalisés** : Scripts Python adaptés aux besoins spécifiques

***

### <mark style="color:blue;">Points Clés à Retenir</mark>

* Le fuzzing d'API est **essentiel** pour découvrir des vulnérabilités cachées
* **Trois types principaux** : Parameter, Data Format, et Sequence Fuzzing
* Les endpoints **non documentés** sont des cibles prioritaires
* L'**analyse des codes de statut** révèle des informations cruciales
* Le fuzzing **automatise** les tests de sécurité impossibles manuellement
* Toujours fuzzer de manière **responsable et autorisée**
* Les vulnérabilités d'API peuvent avoir un **impact critique** sur la sécurité

***
