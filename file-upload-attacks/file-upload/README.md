# File Upload

## <mark style="color:red;">**1. Qu'est-ce que le téléversement de fichiers ?**</mark>

* Permet aux utilisateurs d'ajouter des fichiers dans des applications web.
* Exemple :
  * Réseaux sociaux : Téléversement d’images de profil.
  * Sites d’entreprise : Téléversement de documents PDF.

***

## <mark style="color:red;">**2. Risques liés au téléversement de fichiers**</mark>

* Les fichiers téléversés peuvent contenir des données malveillantes.
* Une validation insuffisante ou absente permet aux attaquants d’exploiter cette fonctionnalité pour :
  * Exécuter des commandes arbitraires.
  * Prendre le contrôle du serveur.

***

## <mark style="color:red;">**3. Vulnérabilités courantes**</mark>

* Mauvaise validation des fichiers téléversés :
  * Extensions non vérifiées.
  * Contenu des fichiers non analysé.
* **Vulnérabilité critique : Téléversement arbitraire de fichiers non authentifié**
  * Permet à n’importe quel utilisateur de téléverser n’importe quel fichier.

***

## <mark style="color:red;">**4. Types d’attaques courantes via téléversement de fichiers**</mark>

* **Téléversement arbitraire de fichiers** :
  * Gagne un accès distant via :
    * Web shell : Interface pour exécuter des commandes sur le serveur.
    * Reverse shell : Script qui renvoie un accès au serveur à l’attaquant.
* **Attaques avec types de fichiers limités** :
  * Exploitation possible même si seuls certains types de fichiers sont autorisés.
  * Exemples :
    * **XSS (Cross-Site Scripting)** ou **XXE (XML External Entity)**.
    * Déni de service (DoS) via surcharge des ressources du serveur.
    * Écrasement de fichiers ou configurations critiques.

***
