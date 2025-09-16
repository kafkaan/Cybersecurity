# Injecting Commands

### <mark style="color:blue;">**1. Principe**</mark>

* Une **injection de commandes** permet à un attaquant d’exécuter des commandes système sur le serveur via une application web.
* Les vulnérabilités surviennent souvent lorsque les **entrées utilisateur ne sont pas validées ou échappées** avant d’être utilisées dans des commandes système.

***

### <mark style="color:blue;">**2. Exemple de base**</mark>

*   Commande initiale :

    ```
    ping -c 1 127.0.0.1
    ```
*   Injection via un **point-virgule `;`** :

    ```
    127.0.0.1; whoami
    ```

    Commande finale exécutée :

    ```
    ping -c 1 127.0.0.1; whoami
    ```
* Résultat : exécution des deux commandes et affichage des résultats.

***

### <mark style="color:blue;">**3. Front-end vs Back-end**</mark>

* **Validation front-end** : empêche souvent les entrées malveillantes côté navigateur (ex. format IP obligatoire).
* **Risque** : si le back-end ne valide pas les entrées, il est toujours vulnérable malgré la validation front-end.
* Vérification possible avec **Firefox Developer Tools → Network Tab** :
  * Si aucune requête réseau n’est envoyée mais qu’un message d’erreur apparaît → validation côté client.

***

### <mark style="color:blue;">**4. Contournement de la validation front-end**</mark>

* Modifier directement la **requête HTTP POST** (ex. via Burp Suite).
* **URL-encoder** les payloads pour qu’ils soient acceptés par le serveur.
*   Exemple :

    ```
    127.0.0.1; whoami
    ```

    → renvoie l’exécution des deux commandes côté serveur.

***

### <mark style="color:blue;">**5. Opérateurs d’injection courants**</mark>

1. **Point-virgule `;`**
   * Exécute la commande suivante indépendamment de la précédente.
   *   Exemple :

       ```
       ping -c 1 127.0.0.1; whoami
       ```
2. **ET logique `&&`**
   * Exécute la deuxième commande **seulement si la première réussit**.
   *   Exemple :

       ```
       ping -c 1 127.0.0.1 && whoami
       ```
3. **OU logique `||`**
   * Exécute la deuxième commande **si la première échoue**.
   *   Exemple :

       ```
       ping -c 1 || whoami
       ```
   * Utile pour obtenir un résultat propre si la commande originale pourrait échouer.

***

### <mark style="color:blue;">**6. Étapes pratiques pour tester**</mark>

1. Vérifier sur votre machine Linux que la commande fonctionne.
2. Identifier la **zone de saisie vulnérable** dans l’application web.
3. Tester différentes **méthodes d’injection** (`;`, `&&`, `||`).
4. Contourner la **validation front-end** avec Burp Suite ou autre proxy.
5. Observer la **réponse du serveur** pour confirmer l’exécution des commandes.

***

### <mark style="color:blue;">**7. Notes importantes**</mark>

* Les mêmes concepts et opérateurs peuvent s’appliquer à d’autres injections :
  * SQL, LDAP, XSS, SSRF, XML, etc.
* Toujours commencer par **tester les commandes sur un environnement local** pour éviter les erreurs.

***
