---
description: https://faresbltagy.gitbook.io/footprintinglabs/password-attacks/lab-hard
---

# Password Attacks

## <mark style="color:red;">**1. Principes fondamentaux de la sécurité : CIA**</mark>

La **sécurité informatique** repose sur trois grands principes appelés le **modèle CIA** :

* **Confidentialité** : Assurer que seules les personnes autorisées peuvent accéder à certaines informations.
* **Intégrité** : Garantir que les données sont exactes et n'ont pas été modifiées de manière non autorisée.
* **Disponibilité** : Assurer que les systèmes et données sont disponibles et accessibles quand les utilisateurs en ont besoin.

Ces trois principes sont **interdépendants** et forment la base de toute stratégie de sécurité. Le but de la sécurité informatique est de maintenir un équilibre entre ces principes.

***

## <mark style="color:red;">**2. Authentification, Autorisation et Comptabilisation**</mark>

* **Authentification** : Processus de vérification de l'identité d'un utilisateur, généralement par une combinaison de facteurs.
* **Autorisation** : Une fois authentifié, l'utilisateur se voit attribuer des permissions qui définissent ce qu'il peut faire sur les ressources.
* **Comptabilisation (Audit)** : Processus d'enregistrement des actions d'un utilisateur pour s'assurer que les activités sont suivies et peuvent être vérifiées en cas d'incident.

Ces mécanismes sont utilisés pour garantir que **seuls les utilisateurs autorisés** peuvent accéder aux ressources et effectuer des actions spécifiques.

***

## <mark style="color:red;">**3. Les facteurs d'authentification**</mark>

L'authentification repose sur trois **facteurs** :

1. **Quelque chose que vous savez** : Mot de passe, code PIN, réponses à des questions secrètes, etc.
2. **Quelque chose que vous avez** : Carte d'identité, token, clé de sécurité, etc.
3. **Quelque chose que vous êtes** : Identification biométrique, empreinte digitale, reconnaissance faciale, etc.

L'authentification peut reposer sur **un ou plusieurs** de ces facteurs, en fonction du niveau de sécurité requis. Par exemple :

* **Authentification simple** : Un mot de passe.
* **Authentification à deux facteurs (2FA)** : Un mot de passe + un code reçu sur un téléphone.
* **Authentification à trois facteurs** : Carte de sécurité, mot de passe + identification biométrique.

***

## <mark style="color:red;">**4. Attaque et contournement des mots de passe**</mark>

Les **mots de passe** sont l'un des **mécanismes d'authentification** les plus utilisés. Cependant, leur sécurité peut être compromise par différentes méthodes :

### <mark style="color:blue;">**4.1. Types de mots de passe**</mark>

Un mot de passe peut être :

* **Simple** : Une chaîne de caractères basique (ex. : `123456`, `password`).
* **Complexe** : Mélange de lettres, chiffres et symboles.
* **Phrase secrète** : Une phrase facile à mémoriser mais longue (ex. : "MonChienEstLePlusFort!").

### <mark style="color:blue;">**4.2. Statistiques sur les mots de passe**</mark>

* **Réutilisation des mots de passe** : 66 % des utilisateurs utilisent le même mot de passe pour plusieurs comptes, ce qui augmente les risques de compromission.
* **Utilisation de mots de passe faibles** : 24 % des Américains utilisent des mots de passe comme `password`, `123456`, ou `qwerty`.
* **Changement de mot de passe après une violation** : Seuls 45 % des utilisateurs changent leur mot de passe après une violation de données, laissant 55 % des utilisateurs vulnérables.

### <mark style="color:blue;">**4.3. Méthodes d'attaque des mots de passe**</mark>

Les mots de passe peuvent être attaqués de différentes manières :

* **Brute force** : Essayer toutes les combinaisons possibles de caractères.
* **Dictionnaire** : Utiliser une liste de mots courants ou de phrases populaires pour deviner le mot de passe.
* **Attaque par injection de mots de passe (Pass the Hash)** : Exploiter les hachages de mots de passe pour contourner l'authentification sans connaître le mot de passe en clair.
* **Phishing** : Manipuler l'utilisateur pour qu'il fournisse son mot de passe, souvent via des emails ou des sites web frauduleux.

***

## <mark style="color:red;">**5. Mécanismes de stockage et de protection des mots de passe**</mark>

Les mots de passe sont **stockés de manière sécurisée** pour éviter leur compromission. Les pratiques courantes incluent :

* **Hachage des mots de passe** : Utiliser un algorithme de hachage (ex. : bcrypt, Argon2) pour convertir un mot de passe en une valeur irréversible.
* **Salt** : Ajouter une valeur aléatoire (le "sel") à un mot de passe avant de le hacher pour rendre plus difficile les attaques par dictionnaire ou par table de hachage pré-calculée (rainbow tables).
* **Chiffrement** : Stocker des mots de passe ou autres secrets dans un format chiffré, qui ne peut être récupéré que par des utilisateurs ou systèmes autorisés.

***

## <mark style="color:red;">**6. Protection et gestion des mots de passe**</mark>

Pour renforcer la sécurité des mots de passe dans une organisation, voici quelques bonnes pratiques :

1. **Exiger des mots de passe longs et complexes**.
2. **Appliquer l'authentification multifactorielle (MFA)** lorsque possible.
3. **Éduquer les utilisateurs** sur les risques de réutilisation des mots de passe et l'importance de les changer régulièrement.
4. **Utiliser des gestionnaires de mots de passe** pour générer et stocker des mots de passe uniques et complexes.
5. **Mettre en place des politiques de verrouillage après plusieurs tentatives échouées** pour limiter les attaques par brute force.

***

## <mark style="color:red;">**7. Outils pour tester et attaquer les mots de passe**</mark>

Les professionnels de la sécurité utilisent plusieurs outils pour tester la résistance des mots de passe dans les systèmes. Par exemple :

* **Hashcat** et **John the Ripper** pour effectuer des attaques par force brute ou dictionnaire sur des hachages de mots de passe.
* **Metasploit** pour les attaques par exploitation de failles dans les mécanismes d'authentification.
* **Mimikatz** pour récupérer les mots de passe en clair, les hachages ou les secrets LSA (Local Security Authority) sur des systèmes compromis.
