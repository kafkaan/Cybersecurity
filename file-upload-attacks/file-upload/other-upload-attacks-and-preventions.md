# Other Upload Attacks and Preventions

## <mark style="color:red;">Other Upload Attacks</mark>

### <mark style="color:blue;">**1. Injections dans le nom du fichier**</mark>

* Utilisation de noms de fichiers malveillants pour provoquer des exécutions de commandes ou des failles :
  * **Injection de commande** : Si le nom du fichier est utilisé dans une commande du système d'exploitation sans validation (ex. `file$(whoami).jpg`), il peut exécuter des commandes comme `whoami`.
  * **Injection XSS** : Un nom de fichier contenant du JavaScript (ex. `<script>alert(window.origin);</script>`) pourrait déclencher un script sur la machine de la cible.
  * **Injection SQL** : Des noms contenant des requêtes SQL (ex. `file';select+sleep(5);--.jpg`) peuvent conduire à une injection SQL.

***

### <mark style="color:blue;">**2. Détection du répertoire de téléversement**</mark>

* Si l'emplacement du fichier téléversé n'est pas connu, plusieurs techniques peuvent aider :
  * **Fuzzing** : Tester différents chemins pour localiser le répertoire.
  * **Exploration de failles** : Exploiter des vulnérabilités (LFI, XXE) pour lire le code source de l’application et trouver l’emplacement.
  * **Erreurs forcées** : Provoquer des erreurs pour obtenir des informations :
    * En téléversant un fichier au nom déjà existant.
    * En envoyant des requêtes simultanées.
    * En utilisant des noms de fichiers trop longs pour déclencher des messages d’erreur.

***

### <mark style="color:blue;">**3. Attaques spécifiques à Windows**</mark>

* **Caractères réservés** : Utiliser des caractères spéciaux (ex. `|, <, >, *, ?`) peut provoquer des erreurs si l'application ne les gère pas correctement.
* **Noms réservés Windows** : Les noms comme `CON, COM1, LPT1, NUL` ne peuvent pas être utilisés pour des fichiers sous Windows. Cela peut provoquer des erreurs ou divulguer des informations.
* **Convention des noms courts (8.3)** : Utiliser des noms de fichiers courts (ex. `HAC~1.TXT`) pour contourner les restrictions ou écraser des fichiers sensibles (ex. `WEB~.CONF` pour écraser `web.conf`).

***

### <mark style="color:blue;">**4. Attaques avancées liées au téléversement de fichiers**</mark>

* Exploitation de traitements automatiques effectués sur les fichiers téléversés (ex. encodage vidéo, compression, renommage).
  * Exemples : Vulnérabilités dans des bibliothèques tierces comme ffmpeg.
  * Les failles dans du code personnalisé nécessitent des compétences avancées pour être détectées.

***

## <mark style="color:red;">Prévenir les Vulnérabilités Liées au Téléversement de Fichiers</mark>

Cette fiche résume les meilleures pratiques pour sécuriser les fonctions de téléversement de fichiers et éviter les vulnérabilités courantes.

***

### **1. Validation des Extensions**

#### **Problèmes Identifiés**

* Les serveurs et applications web utilisent les extensions pour déterminer comment traiter un fichier.
* Les attaquants peuvent contourner les validations faibles avec des noms comme `shell.php.jpg`.

#### **Bonnes Pratiques**

* **Liste blanche (whitelist) des extensions** : Autoriser uniquement les extensions sécurisées (ex. : `jpg`, `png`, `gif`).
* **Liste noire (blacklist) des extensions dangereuses** : Bloquer des extensions comme `php`, `exe`, `html`.

#### **Exemple en PHP**

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// Liste noire
if (preg_match('/^.+\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// Liste blanche
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

* Effectuer la validation **côté client et serveur**.

***

### **2. Validation du Contenu**

#### **Problèmes Identifiés**

* Les fichiers peuvent avoir une extension valide mais un contenu malveillant.
* L’extension et le contenu doivent correspondre.

#### **Bonnes Pratiques**

1. Vérifier l’extension via une liste blanche.
2. Contrôler le **type MIME** et la **signature du fichier**.

#### **Exemple en PHP**

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// Validation de l'extension
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// Validation du contenu
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only PNG images are allowed";
        die();
    }
}
```

***

### **3. Réduction des Risques de Divulgation**

#### **Problèmes Identifiés**

* Les attaquants peuvent accéder directement au répertoire des téléversements.

#### **Bonnes Pratiques**

1. **Masquer le répertoire des téléversements** : Empêcher l’accès direct (403 interdit).
2. **Utiliser une page de téléchargement** : Créer un script (ex. : `download.php`) pour gérer les téléchargements.
3. **Headers HTTP sécurisés** :
   * `Content-Disposition` pour forcer le téléchargement.
   * `nosniff` pour empêcher l'exécution de scripts malveillants.
4. **Noms aléatoires des fichiers** :
   * Stocker les noms originaux dans une base de données.
   * Utiliser un identifiant aléatoire comme nom de fichier.
5. **Serveur de stockage isolé** : Placer les fichiers dans un serveur ou conteneur distinct.

***

### **4. Sécurité Avancée**

#### **Configurations Critiques**

* **Désactiver les fonctions dangereuses en PHP** :
  * Exemple : `exec`, `shell_exec`, `system`, `passthru` dans `php.ini`.
* **Masquer les erreurs systèmes** : Afficher uniquement des messages d'erreur simples et non sensibles.

### **Autres Mesures**

1. Limiter la taille des fichiers téléversés.
2. Maintenir les bibliothèques à jour.
3. Scanner les fichiers téléversés pour repérer les logiciels malveillants.
4. Utiliser un **pare-feu pour applications web (WAF)**.

***
