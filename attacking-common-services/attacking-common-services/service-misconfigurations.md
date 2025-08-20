# Service Misconfigurations

***

## <mark style="color:red;">1. Qu'est-ce qu'une Erreur de Configuration ?</mark>

<mark style="color:green;">**Définition :**</mark>

* Une erreur de configuration survient lorsqu'un administrateur, développeur ou technicien ne configure pas correctement la sécurité d'une application, d'un serveur ou d'un site web.
* Cela ouvre des failles exploitables par des utilisateurs non autorisés.

<mark style="color:green;">**Exemples courants :**</mark>

* Mots de passe par défaut non changés
* Droits d'accès trop étendus
* Services inutiles activés

***

## <mark style="color:red;">2. Erreurs de Configuration les Plus Courantes</mark>

<mark style="color:green;">**1. Authentification**</mark>

**Problème :**

* Utilisation de **mots de passe par défaut** (admin:admin, root:123456).
* Absence de mot de passe ou utilisation de mots de passe faibles.

**Solution :**

* **Définir une politique de mots de passe forts** :
  * Exiger des mots de passe complexes.
  * Changer immédiatement les mots de passe par défaut.
* Éviter des combinaisons classiques (admin:password).

**Exemples de mots de passe faibles :**

* admin:password
* admin:
* root:123456

***

<mark style="color:green;">**2. Authentification Anonyme**</mark>

**Problème :**

* Certains services acceptent l'**authentification anonyme** par défaut.
* Permet à quiconque d'accéder à des répertoires ou fichiers sensibles sans identification.

**Solution :**

* **Désactiver l'authentification anonyme** sur les services sensibles.
* Restreindre l'accès par défaut.

***

<mark style="color:green;">**3. Droits d'Accès Mal Configurés**</mark>

**Problème :**

* Des utilisateurs ont des **droits trop élevés** (ex : un utilisateur FTP peut lire tous les fichiers du serveur).
* Risque de fuite de données sensibles (PII, identifiants, etc.).

**Solution :**

* Appliquer le principe du **moindre privilège**.
* Utiliser des méthodes comme :
  * **Contrôle d'accès basé sur les rôles (RBAC)**.
  * **Listes de contrôle d'accès (ACL)**.

***

<mark style="color:green;">**4. Valeurs Par Défaut Inutiles**</mark>

**Problème :**

* Lors de l'installation, des services, ports ou comptes inutiles sont activés par défaut.
* Cela augmente la surface d'attaque.

**Solution :**

* Désactiver les **services et comptes inutiles**.
* Configurer systématiquement les options de sécurité lors de l'installation.

**Exemples :**

* Ports ouverts sans besoin.
* Services de debug laissés actifs.

***

## <mark style="color:red;">3. Prévention des Erreurs de Configuration</mark>

1. **Verrouiller l'infrastructure critique** :

* Désactiver toutes les interfaces d'administration non essentielles.
* Désactiver les options de debug.
* Refuser l'utilisation de noms d'utilisateur et mots de passe par défaut.

2. **Automatiser les processus de configuration sécurisée** :

* Utiliser des scripts pour configurer chaque environnement (Production, QA, Dev) de manière identique.
* Différencier les identifiants pour chaque environnement.

3. **Utiliser des plateformes minimales** :

* N'installer que les composants essentiels.
* Supprimer les fonctionnalités inutilisées (pages d'exemple, services non nécessaires, etc.).

4. **Vérification et audit réguliers** :

* Effectuer des scans de vulnérabilités.
* Auditer régulièrement les paramètres de sécurité.

***

## <mark style="color:red;">4. OWASP Top 10 et Misconfigurations</mark>

Les erreurs de configuration font partie du **Top 10 OWASP** des vulnérabilités.

**Exemples :**

* Services inutiles activés (ports, privilèges non requis).
* Comptes par défaut non changés.
* Messages d'erreur trop détaillés (stack traces).
* Absence de mise à jour des options de sécurité.

**Pratiques recommandées OWASP :**

* Appliquer des processus de durcissement (hardening) répétables et automatisés.
* Utiliser une architecture segmentée (conteneurs, ACL cloud, etc.).
* Vérifier les permissions de stockage cloud (ex : S3 bucket).
* Envoyer des en-têtes HTTP de sécurité aux clients.

***
