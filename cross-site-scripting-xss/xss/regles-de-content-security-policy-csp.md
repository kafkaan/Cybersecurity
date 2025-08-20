# Règles de Content Security Policy (CSP)

## <mark style="color:red;">**Règles de Content Security Policy (CSP)**</mark>

> La Content Security Policy (CSP) est une technologie de sécurité pour navigateurs web destinée à prévenir des attaques telles que le Cross-Site Scripting (XSS). CSP permet aux développeurs de spécifier les sources de contenu autorisées à être chargées par le navigateur.

***

### <mark style="color:blue;">**Directives Principales :**</mark>

1. **default-src** : Directive par défaut utilisée si aucune autre directive spécifique n'est mentionnée.
   * Exemple : `default-src 'self';`
2. **script-src** : Spécifie les sources autorisées pour le chargement de scripts JavaScript.
   * Exemple : `script-src 'self' https://code.jquery.com;`
3. **img-src** : Définit les sources autorisées pour les images.
   * Exemple : `img-src 'self' https://example.com;`
4. **style-src** : Spécifie les sources pour les feuilles de style CSS.
   * Exemple : `style-src 'self' 'unsafe-inline';`
5. **font-src** : Autorise les sources pour les polices de caractères.
   * Exemple : `font-src 'self' https://fonts.googleapis.com;`
6. **connect-src** : Spécifie les URLs pouvant être contactées via des interfaces comme fetch, XMLHttpRequest, etc.
   * Exemple : `connect-src 'self' https://api.example.com;`
7. **frame-src** : Limite les URLs autorisées pour les frames.
   * Exemple : `frame-src 'self' https://www.youtube.com;`
8. **base-uri** : Définit les URLs autorisées pour les éléments `<base>`.
   * Exemple : `base-uri 'self';`
9. **form-action** : Spécifie les endpoints valides pour les soumissions de formulaires.
   * Exemple : `form-action 'self' https://secure.example.com;`
10. **sandbox** : Applique des restrictions semblables à l'attribut `sandbox` d'un `<iframe>`.
    * Exemple : `sandbox;`
11. **report-uri** : Indique où envoyer les rapports de violation de la CSP.
    * Exemple : `report-uri /csp-report-endpoint;`
12. **object-src** : Spécifie les sources autorisées pour les objets intégrés `<object>`, `<embed>`, et `<applet>`.
    * Exemple : `object-src 'none';`

**Sources spécifiques :**

* `'self'` : Charge uniquement le contenu depuis le même domaine.
* `'none'` : Bloque tout chargement depuis une source.
* `'unsafe-inline'` : Autorise les scripts inline (non recommandé pour des raisons de sécurité).
* `'unsafe-eval'` : Permet l'utilisation de `eval()` (non recommandé).

**En-têtes de CSP :**

* `Content-Security-Policy` : Applique la CSP et bloque les violations.
* `Content-Security-Policy-Report-Only` : Utilisé pour surveiller les violations sans les bloquer.

***

## <mark style="color:red;">**Règles CSP dangereuses et vulnérabilités associées**</mark>

Certaines règles de CSP, mal configurées, peuvent introduire des vulnérabilités graves dans une application web, compromettant la sécurité des utilisateurs.

<mark style="color:yellow;">**Vulnérabilités liées à certaines règles CSP :**</mark>

1. **'unsafe-inline'**
   * **Danger** : Permet l'exécution de scripts inline, ce qui peut facilement être exploité via des attaques XSS.
   * **Exemple de payload malveillant** : `"><script>alert(1);</script>`
2. **'unsafe-eval'**
   * **Danger** : Autorise l'exécution de code via `eval()` ou des méthodes similaires, ce qui peut permettre l'exécution de scripts injectés.
   * **Exemple** : `script-src https://example.com 'unsafe-eval';`
3. **'strict-dynamic'**
   * **Danger** : Si combinée avec une source whitelistée, cette directive permet à tout script chargé dynamiquement par une source autorisée de contourner la politique CSP.
4. **Wildcard ('\*')**
   * **Danger** : Autoriser toutes les sources peut rendre une application vulnérable à l'exécution de scripts malveillants provenant de sources non fiables.
   * **Exemple** : `script-src 'self' https://example.com https: data *;`
5. **Absence de `object-src` et `default-src`**
   * **Danger** : Sans ces directives, des objets dangereux peuvent être chargés, exposant l'application à des risques d'injection de contenu.
6. **File Upload + 'self'**
   * **Danger** : Si une application permet de télécharger un fichier contenant du code JavaScript, celui-ci pourrait être exécuté malgré une CSP supposée restrictive.
   * **Exemple** : `script-src 'self'; object-src 'none';` combiné avec un téléchargement mal sécurisé.
7. **Redirection et Relative Path Overwrite (RPO)**
   * **Danger** : Certaines redirections peuvent être exploitées pour contourner les règles CSP via l'interprétation incorrecte des chemins.
   * **Exemple** : Utiliser des chemins relatifs pour charger des scripts interdits initialement.
