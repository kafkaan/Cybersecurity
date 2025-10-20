# Protected File Transfers

***

### <mark style="color:red;">File Encryption on Windows</mark>

Many different methods can be used to encrypt files and information on Windows systems. One of the simplest methods is the [Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions/Invoke-AESEncryption.ps1) PowerShell script. This script is small and provides encryption of files and strings.

<mark style="color:orange;">**Invoke-AESEncryption.ps1**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell

.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text" 

Description
-----------
Encrypts the string "Secret Test" and outputs a Base64 encoded ciphertext.
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
 
Description
-----------
Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin
 
Description
-----------
Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Path file.bin.aes
 
Description
-----------
Decrypts the file "file.bin.aes" and outputs an encrypted file "file.bin"
#>
function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
```
{% endcode %}

<mark style="color:green;">**Import Module Invoke-AESEncryption.ps1**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> Import-Module .\Invoke-AESEncryption.ps1
```
{% endcode %}

<mark style="color:green;">**File Encryption Example**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
```
{% endcode %}

Using very `strong` and `unique` passwords for encryption for every company where a penetration test is performed is essential. This is to prevent sensitive files and information from being decrypted using one single password that may have been leaked and cracked by a third party.

***

### <mark style="color:red;">File Encryption on Linux</mark>

**Présence et utilisation**

* Fréquemment inclus dans les distributions Linux
* Utilisé par les administrateurs système pour générer des certificats de sécurité et autres tâches

**Capacités de transfert**

* Permet d'envoyer des fichiers "à la manière de netcat (nc)"
* Offre la possibilité de chiffrer les fichiers lors du transfert

**Options de chiffrement**

* Choix entre différents algorithmes de chiffrement (voir la page man d'OpenSSL)
* Exemple courant : `-aes256`

**Paramètres de sécurité avancés**

* `-iter 100000` : permet de modifier le nombre d'itérations par défaut
* `-pbkdf2` : utilise l'algorithme Password-Based Key Derivation Function 2 (dérivation de clé basée sur mot de passe)

<mark style="color:orange;">**Encrypting /etc/passwd with openssl**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc                           
```
{% endcode %}

Remember to use a strong and unique password to avoid brute-force cracking attacks should an unauthorized party obtain the file. To decrypt the file, we can use the following command:

<mark style="color:orange;">**Decrypt passwd.enc with openssl**</mark>

{% code overflow="wrap" fullWidth="true" %}
```sh
mrroboteLiot@htb[/htb]$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd                    
```
{% endcode %}
