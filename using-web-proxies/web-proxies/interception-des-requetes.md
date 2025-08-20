# Interception des Requêtes

***

## <mark style="color:red;">**1. Interception des Requêtes Web**</mark>

L'interception des requêtes HTTP permet de capturer, modifier et analyser les échanges entre une application web et un serveur. C'est une étape clé dans les tests d'intrusion (pentesting) web.

***

## <mark style="color:red;">**2. Outils Utilisés**</mark>

* **Burp Suite** : Proxy le plus utilisé pour le pentesting web.
* **OWASP ZAP** : Proxy open-source et gratuit, en constante évolution.

***

## <mark style="color:red;">**3. Intercepter des Requêtes**</mark>

<mark style="color:green;">**Avec Burp Suite**</mark>

1. **Activer l'interception** :
   * Onglet **Proxy** → **Intercept** → Cliquez sur **Intercept is on**.
2. **Capturer la requête** :
   * Ouvrez le navigateur configuré (depuis Burp) et visitez une cible.
   * La requête s'affiche dans Burp → Cliquez sur **Forward** pour l'envoyer au serveur.

<mark style="color:green;">**Avec OWASP ZAP**</mark>

1. **Activer l'interception** :
   * Bouton vert (en haut à droite) → Passez au rouge (interception activée).
   * Raccourci : **CTRL+B**.
2. **Capturer la requête** :
   * Ouvrez le navigateur configuré (via ZAP) et visitez une cible.
   * La requête s'affiche → Cliquez sur **Step** pour l'envoyer ou **Continue** pour passer à la suivante.

***

## <mark style="color:red;">**4. Manipulation des Requêtes Interceptées**</mark>

1. Modifiez les paramètres de la requête (exemple : `ip=1` → `ip=;ls;`).
2. **Envoyez la requête modifiée**.
3. Analysez la réponse pour détecter des vulnérabilités (ex : injections SQL, bypass d'authentification, etc.).

***

## <mark style="color:red;">**5. Cas d'Utilisation**</mark>

* **Tests de sécurité** : Injection SQL, XSS, Command Injection.
* **Bypass des protections front-end**.
* **Exploration des vulnérabilités**.

***

## <mark style="color:red;">**6. Exemple de Requête Interceptée**</mark>

```http
POST /ping HTTP/1.1
Host: 46.101.23.188:30820
Content-Length: 4
...
ip=1
```

**Manipulation** : `ip=;ls;`\
**Résultat** : Retour de la commande `ls` à la place de la réponse initiale.

***
