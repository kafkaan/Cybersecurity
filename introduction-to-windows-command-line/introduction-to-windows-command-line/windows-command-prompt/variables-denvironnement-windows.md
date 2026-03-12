# Variables d'Environnement Windows

## <mark style="color:red;">Variables d'Environnement Windows</mark>

### <mark style="color:blue;">🎯 Qu'est-ce qu'une Variable d'Environnement ?</mark>

Les **variables d'environnement** sont des paramètres globaux du système accessibles par la plupart des utilisateurs et applications. Elles permettent de :

* Stocker des informations système importantes
* Accélérer l'exécution des applications
* Faciliter l'exécution de scripts
* Référencer des données communes

#### <mark style="color:$success;">📝 Syntaxe de Référence</mark>

```cmd
%NOM_VARIABLE%
```

#### <mark style="color:$success;">⚠️ Règles de Nommage</mark>

✅ **Autorisé** :

* Lettres majuscules/minuscules (non sensible à la casse)
* Espaces et chiffres dans le nom
* Underscores `_` pour séparer les mots

❌ **Interdit** :

* Commencer par un chiffre
* Utiliser le signe égal `=`

***

### <mark style="color:blue;">🔍 Les 3 Portées (Scopes) des Variables</mark>

<table data-full-width="true"><thead><tr><th>Portée</th><th>Description</th><th>Qui peut y accéder ?</th><th>Stockage Registre</th><th>Durée de vie</th></tr></thead><tbody><tr><td><strong>System (Machine)</strong></td><td>Variables globales du système d'exploitation, accessibles par TOUS les utilisateurs</td><td>Administrateur Local ou Domain</td><td><code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment</code></td><td>Permanente jusqu'à suppression</td></tr><tr><td><strong>User</strong></td><td>Variables spécifiques à l'utilisateur actif, invisibles aux autres users</td><td>Utilisateur actuel, Admin Local, Admin Domain</td><td><code>HKEY_CURRENT_USER\Environment</code></td><td>Permanente pour cet utilisateur</td></tr><tr><td><strong>Process</strong></td><td>Variables temporaires du processus en cours, héritées du parent</td><td>Processus actuel, processus parent, utilisateur actuel</td><td>Mémoire du processus (RAM)</td><td>Volatile - disparaît à la fermeture</td></tr></tbody></table>

#### <mark style="color:$success;">🌍 Global vs Local - Exemple Concret</mark>

**Scénario** : Alice et Bob connectés simultanément sur la même machine

**Variable Globale (`%WINDIR%`)**

```cmd
# Alice
C:\Users\alice> echo %WINDIR%
C:\Windows

# Bob
C:\Users\bob> echo %WINDIR%
C:\Windows
```

✅ Les deux voient la même chose → **Variable globale système**

**Variable Locale (créée par Alice)**

```cmd
# Alice crée sa variable
C:\Users\alice> set SECRET=HTB{5UP3r_53Cr37_V4r14813}
C:\Users\alice> echo %SECRET%
HTB{5UP3r_53Cr37_V4r14813}

# Bob tente d'y accéder
C:\Users\bob> echo %SECRET%
%SECRET%
C:\Users\bob> set %SECRET%
Environment variable %SECRET% not defined
```

❌ Bob ne peut pas voir → **Variable locale au processus d'Alice**

***

### <mark style="color:blue;">🛠️ Commandes de Gestion des Variables</mark>

#### <mark style="color:green;">📋 1. VISUALISER les Variables</mark>

**Commande `set`**

```cmd
# Afficher TOUTES les variables
C:\> set

# Afficher UNE variable spécifique
C:\> set SYSTEMROOT
SYSTEMROOT=C:\Windows

# Tenter d'afficher une valeur (ne fonctionne pas comme ça)
C:\> set %SYSTEMROOT%
Environment variable C:\Windows not defined
```

**Commande `echo`**

```cmd
# Afficher la VALEUR d'une variable
C:\> echo %PATH%
C:\Windows\system32;C:\Windows;...

C:\> echo %USERPROFILE%
C:\Users\htb
```

**💡 Différence** :

* `set` → Affiche le NOM et la VALEUR
* `echo` → Affiche uniquement la VALEUR

***

#### <mark style="color:green;">➕ 2. CRÉER des Variables</mark>

**Avec `set` (Temporaire - Portée Process)**

```cmd
C:\> set DCIP=172.16.5.2

# Vérification
C:\> echo %DCIP%
172.16.5.2
```

⚠️ **Temporaire** : Disparaît à la fermeture du CMD

**Avec `setx` (Permanente - Portée User/System)**

```cmd
C:\> setx DCIP 172.16.5.2
SUCCESS: Specified value was saved.

# Vérification (dans une NOUVELLE session CMD)
C:\> echo %DCIP%
172.16.5.2
```

✅ **Permanente** : Stockée dans le registre, persiste après redémarrage

**📌 Syntaxe** :

* `set` → `set VARIABLE=valeur`
* `setx` → `setx VARIABLE valeur`

***

#### <mark style="color:$success;">✏️ 3. MODIFIER des Variables</mark>

```cmd
# Modification avec setx (écrase l'ancienne valeur)
C:\> setx DCIP 172.16.5.5
SUCCESS: Specified value was saved.

# Vérification
C:\> echo %DCIP%
172.16.5.5
```

💡 **Astuce** : Modifier = Créer avec le même nom

***

#### <mark style="color:$success;">❌ 4. SUPPRIMER des Variables</mark>

```cmd
# Supprimer en définissant une valeur vide
C:\> setx DCIP ""
SUCCESS: Specified value was saved.

# Vérification
C:\> set DCIP
Environment variable DCIP not defined

C:\> echo %DCIP%
%DCIP%
```

⚠️ On ne **supprime pas** directement, on **vide** la valeur

***

### <mark style="color:blue;">🎯 set vs setx - Tableau Comparatif</mark>

| Critère                      | `set`                              | `setx`                                          |
| ---------------------------- | ---------------------------------- | ----------------------------------------------- |
| **Portée**                   | Process (temporaire)               | User ou System (permanente)                     |
| **Persistance**              | Disparaît à la fermeture           | Stockée dans le registre                        |
| **Syntaxe**                  | `set VAR=valeur`                   | `setx VAR valeur`                               |
| **Effet immédiat**           | Oui, dans la session actuelle      | Non, nécessite nouvelle session                 |
| **Fonctionnalités avancées** | Basique                            | Peut modifier sur machines distantes du domaine |
| **Usage typique**            | Tests rapides, scripts temporaires | Configuration permanente                        |

**🧠 Quand utiliser quoi ?**

* **`set`** → Tests rapides, modifications temporaires, ne pas laisser de traces
* **`setx`** → Configuration permanente, persistance nécessaire

***

### <mark style="color:blue;">🔐 Variables d'Environnement Critiques (Pentest)</mark>

<table data-full-width="true"><thead><tr><th>Variable</th><th>Valeur Typique</th><th>Description</th><th>Intérêt Pentest</th></tr></thead><tbody><tr><td><code>%PATH%</code></td><td><code>C:\Windows\system32;C:\Windows;...</code></td><td>Répertoires où sont cherchés les exécutables</td><td>Hijacking possible, trouver binaires</td></tr><tr><td><code>%OS%</code></td><td><code>Windows_NT</code></td><td>Système d'exploitation actuel</td><td>Identifier l'OS</td></tr><tr><td><code>%SYSTEMROOT%</code></td><td><code>C:\Windows</code></td><td>Dossier racine de Windows (lecture seule)</td><td>Localiser fichiers système critiques</td></tr><tr><td><code>%LOGONSERVER%</code></td><td><code>\\DC01</code> ou <code>\\MACHINE</code></td><td>Serveur de connexion de l'utilisateur</td><td>Déterminer si domaine ou workgroup</td></tr><tr><td><code>%USERPROFILE%</code></td><td><code>C:\Users\htb</code></td><td>Répertoire personnel de l'utilisateur actuel</td><td>Trouver fichiers utilisateur, AppData</td></tr><tr><td><code>%ProgramFiles%</code></td><td><code>C:\Program Files</code></td><td>Programmes installés (x64)</td><td>Énumérer applications installées</td></tr><tr><td><code>%ProgramFiles(x86)%</code></td><td><code>C:\Program Files (x86)</code></td><td>Programmes 32-bit sur système 64-bit</td><td>Identifier architecture (présence = x64)</td></tr><tr><td><code>%TEMP%</code> / <code>%TMP%</code></td><td><code>C:\Users\htb\AppData\Local\Temp</code></td><td>Dossier temporaire</td><td>Droits d'écriture garantis, exfiltration</td></tr><tr><td><code>%APPDATA%</code></td><td><code>C:\Users\htb\AppData\Roaming</code></td><td>Données d'application utilisateur</td><td>Trouver configs, credentials</td></tr><tr><td><code>%COMPUTERNAME%</code></td><td><code>MACHINE01</code></td><td>Nom de la machine</td><td>Identifier le système</td></tr><tr><td><code>%USERNAME%</code></td><td><code>htb</code></td><td>Nom de l'utilisateur actuel</td><td>Contexte d'exécution</td></tr><tr><td><code>%USERDOMAIN%</code></td><td><code>WORKGROUP</code> ou <code>CORP</code></td><td>Domaine de l'utilisateur</td><td>Vérifier appartenance domaine</td></tr></tbody></table>

***

### <mark style="color:blue;">🎓 Exemples Pratiques</mark>

#### <mark style="color:green;">🔎 Énumération Complète</mark>

```cmd
# Afficher toutes les variables
set

# Variables critiques
echo %COMPUTERNAME%
echo %USERNAME%
echo %USERDOMAIN%
echo %LOGONSERVER%
echo %OS%
echo %SYSTEMROOT%
echo %PATH%
```

#### <mark style="color:green;">🎯 Création Variable Custom</mark>

```cmd
# Temporaire (tests)
set TARGET=10.10.10.5

# Permanente (persistence)
setx C2_SERVER 192.168.1.100
```

#### <mark style="color:green;">🧹 Nettoyage</mark>

```cmd
# Supprimer trace
setx C2_SERVER ""
```

#### <mark style="color:green;">🔍 Vérification Domaine vs Workgroup</mark>

```cmd
C:\> echo %LOGONSERVER%
\\DC01            → Machine jointe au domaine

C:\> echo %LOGONSERVER%
\\MACHINE01       → Workgroup (serveur = machine locale)
```

#### <mark style="color:green;">🏗️ Identifier Architecture</mark>

```cmd
# Si cette variable existe → système x64
C:\> echo %ProgramFiles(x86)%
C:\Program Files (x86)

# Si vide/inexistante → système x86
C:\> echo %ProgramFiles(x86)%
%ProgramFiles(x86)%
```

***

### <mark style="color:blue;">📌 Résumé Clés</mark>

| Concept           | À Retenir                                                       |
| ----------------- | --------------------------------------------------------------- |
| **Portées**       | System (global) > User (par utilisateur) > Process (temporaire) |
| **Visualisation** | `set` pour lister, `echo %VAR%` pour afficher                   |
| **Création**      | `set VAR=val` (temp) ou `setx VAR val` (perm)                   |
| **Modification**  | Re-définir avec même nom                                        |
| **Suppression**   | Définir valeur vide `setx VAR ""`                               |
| **Pentest**       | `%LOGONSERVER%`, `%PATH%`, `%USERPROFILE%` très utiles          |

***

### <mark style="color:blue;">🎯 Commandes à Maîtriser</mark>

```cmd
# TOP 5 Commandes Essentielles

1. set                              # Lister toutes les variables
2. echo %VARIABLE%                  # Afficher une variable
3. set VAR=valeur                   # Créer temporaire
4. setx VAR valeur                  # Créer permanente
5. setx VAR ""                      # Supprimer variable
```

***

### <mark style="color:blue;">📚 Ressources Complémentaires</mark>

* [Liste complète variables Windows](https://docs.microsoft.com/en-us/windows/deployment/usmt/usmt-recognized-environment-variables)
* Registre : `regedit` → Naviguer vers les clés mentionnées
* PowerShell : `Get-ChildItem Env:` (équivalent de `set`)

***
