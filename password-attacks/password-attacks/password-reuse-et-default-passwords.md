# Password Reuse et Default Passwords

## <mark style="color:red;">**Concepts Clés :**</mark>

* **Réutilisation des mots de passe :**
  * Les administrateurs et utilisateurs réutilisent souvent les mêmes mots de passe pour simplifier la gestion.
  * Cela est courant lors des configurations initiales ou lorsque l'authentification SSO (Single Sign-On) n'est pas encore disponible.
* **Mots de passe par défaut :**
  * Beaucoup de logiciels, équipements réseau (routeurs, imprimantes, etc.) et applications sont livrés avec des identifiants par défaut.
  * Ces identifiants sont parfois oubliés ou supposés "sûrs" dans des environnements internes, ce qui les rend vulnérables.

**Risques :**

* **Oublis de modification des mots de passe :**
  * Interfaces non modifiées (par ex., routeurs en test interne).
* **Utilisation de mots de passe faibles ou prédictibles :**
  * Exemples : "admin", "12345", ou "password".

***

## <mark style="color:red;">**Credential Stuffing (Remplissage des Identifiants)**</mark>

**Définition :**

* Une attaque où des listes d'identifiants (nom d'utilisateur : mot de passe) connus sont utilisées pour accéder à des services.
* C'est une méthode simplifiée de brute-force, où seuls les identifiants déjà associés sont testés.

**Exemples de mots de passe par défaut courants :**

| Produit/Vendeur | Nom d’utilisateur | Mot de passe |
| --------------- | ----------------- | ------------ |
| Zyxel (SSH)     | zyfwp             | PrOw!aN\_fXp |
| APC UPS (web)   | apc               | apc          |
| Weblogic (web)  | weblogic          | welcome(1)   |
| D-Link (web)    | admin             | admin        |
| Kali Linux (OS) | kali              | kali         |
| JioFiber        | admin             | jiocentrum   |

**Sources des identifiants par défaut :**

1. Documentation produit.
2. Bases de données publiques, ex. : _DefaultCreds-Cheat-Sheet_.

***

## <mark style="color:red;">**Techniques et Outils :**</mark>

<mark style="color:green;">**Hydra (outil de Credential Stuffing) :**</mark>

Commande pour tester des listes d'identifiants sur un service :

```
hydra -C <user_pass.list> <protocol>://<IP>
```

```
hydra -C user_pass.list ssh://10.129.42.197
```

<mark style="color:green;">**OSINT (Renseignement en source ouverte) :**</mark>

* Utilisé pour :
  * Comprendre l'infrastructure de la cible.
  * Identifier les mots de passe possibles ou des applications avec des identifiants codés en dur.
  * Rechercher sur Google des identifiants par défaut spécifiques.

<mark style="color:green;">**Recherche Google :**</mark>

* Exemple pour trouver des identifiants par défaut :

```
"<product> default username password site:example.com"
```

***

## <mark style="color:red;">**Attaques ciblant les Routeurs**</mark>

<mark style="color:green;">**Caractéristiques des mots de passe par défaut des routeurs :**</mark>

* Les administrateurs surveillent davantage les routeurs, mais certains peuvent être négligés, notamment dans des environnements de test.

**Exemples de configurations par défaut :**

| Marque  | IP par défaut                            | Nom d’utilisateur | Mot de passe |
| ------- | ---------------------------------------- | ----------------- | ------------ |
| 3Com    | [http://192.168.1.1](http://192.168.1.1) | admin             | Admin        |
| Belkin  | [http://192.168.2.1](http://192.168.2.1) | admin             | admin        |
| Linksys | [http://192.168.1.1](http://192.168.1.1) | admin             | Admin        |
| Netgear | [http://192.168.0.1](http://192.168.0.1) | admin             | password     |
