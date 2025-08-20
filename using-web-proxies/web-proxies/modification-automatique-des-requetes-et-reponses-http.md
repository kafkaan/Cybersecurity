# Modification Automatique des Requêtes et Réponses HTTP

## <mark style="color:red;">1.</mark> <mark style="color:red;"></mark><mark style="color:red;">**Modification Automatique des Requêtes**</mark>

**Principe :**\
Automatiser la modification des requêtes HTTP sortantes pour manipuler des en-têtes ou des paramètres sans interception manuelle.

<mark style="color:green;">**Exemple : Changer l'User-Agent**</mark>

* **Burp Suite :**
  * Aller dans **Proxy > Options > Match and Replace**.
  * Cliquer sur **Add**.
  * **Options :**
    * **Type :** Request header.
    * **Match :** `^User-Agent.*$` (regex pour capturer la ligne User-Agent).
    * **Replace :** `User-Agent: HackTheBox Agent 1.0`.
    * **Regex match :** True.
  * Résultat : L'User-Agent est automatiquement remplacé dans chaque requête interceptée.
* **ZAP :**
  * Appuyer sur **\[CTRL+R]** ou aller dans **Replacer** dans les options.
  * Cliquer sur **Add** et configurer :
    * **Match Type :** Request Header.
    * **Match String :** User-Agent.
    * **Replacement String :** HackTheBox Agent 1.0.
    * **Enable :** True.
  * Appliquer à toutes les requêtes HTTP(S) (option par défaut).

***

## <mark style="color:red;">2.</mark> <mark style="color:red;"></mark><mark style="color:red;">**Modification Automatique des Réponses**</mark>

**Principe :**\
Modifier automatiquement les réponses HTTP pour manipuler des champs et contourner des restrictions côté client.

<mark style="color:green;">**Exemple : Modifier un Champ d'Input**</mark>

* **Objectif :** Transformer un champ `type="number"` en `type="text"` pour contourner la validation frontend.
* **Burp Suite :**
  * Aller dans **Proxy > Options > Match and Replace**.
  * Cliquer sur **Add**.
  * **Options :**
    * **Type :** Response body.
    * **Match :** `type="number"`.
    * **Replace :** `type="text"`.
    * **Regex match :** False.
  * Exemple supplémentaire : Modifier `maxlength="3"` en `maxlength="100"`.
* **ZAP :**
  * Aller dans **Replacer** et ajouter une nouvelle règle :
    * **Match Type :** Response Body String.
    * **Match String :** `type="number"`.
    * **Replacement String :** `type="text"`.
    * **Enable :** True.
  * Ajouter une règle pour `maxlength="3"` vers `maxlength="100"`.

***

## <mark style="color:red;">3.</mark> <mark style="color:red;"></mark><mark style="color:red;">**Exercice Pratique : Injection de Commandes Automatisée**</mark>

* **Objectif :** Automatiser l'ajout de `;ls;` dans les requêtes Ping.
* **Méthode :**
  * **Burp/ZAP** : Ajouter une règle pour modifier le corps de la requête (Request body).
  * **Match Type :** Request Body.
  * **Match String :** `ip=1`.
  * **Replace :** `ip=;ls;`.
  * **Enable :** True.

**Astuce :** Cette technique est utile pour tester la validation des entrées côté serveur et exploiter des vulnérabilités comme les injections SQL, XSS ou Command Injection.
