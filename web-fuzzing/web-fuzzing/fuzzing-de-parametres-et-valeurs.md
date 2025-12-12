# Fuzzing de Paramètres et Valeurs

### <mark style="color:blue;">Introduction</mark>

Les paramètres sont les messagers du web, transportant des informations vitales entre votre navigateur et le serveur qui héberge l'application web.&#x20;

* Ils sont comme des variables en programmation, contenant des valeurs spécifiques qui influencent le comportement de l'application.

***

### <mark style="color:blue;">Paramètres GET : Partage Ouvert d'Informations</mark>

Vous repérerez souvent les paramètres GET directement dans l'URL, après un point d'interrogation (?). Plusieurs paramètres sont reliés entre eux à l'aide d'esperluettes (&). Par exemple :

```http
https://example.com/search?query=fuzzing&category=security
```

Dans cette URL :

* `query` est un paramètre avec la valeur "fuzzing"
* `category` est un autre paramètre avec la valeur "security"

***

### <mark style="color:blue;">Paramètres POST : Communication en Coulisses</mark>

#### <mark style="color:green;">Processus de Soumission POST</mark>

Lorsque vous soumettez un formulaire ou interagissez avec une page web qui utilise des requêtes POST, voici ce qui se passe :

1. **Collecte de Données** : Les informations saisies dans les champs du formulaire sont rassemblées et préparées pour la transmission.
2. **Encodage** : Ces données sont encodées dans un format spécifique, généralement `application/x-www-form-urlencoded` ou `multipart/form-data` :
   * **application/x-www-form-urlencoded** : Ce format encode les données sous forme de paires clé-valeur séparées par des esperluettes (&), similaire aux paramètres GET mais placées dans le corps de la requête au lieu de l'URL.
   * **multipart/form-data** : Ce format est utilisé lors de la soumission de fichiers avec d'autres données. Il divise le corps de la requête en plusieurs parties, chacune contenant une donnée spécifique ou un fichier.
3. **Requête HTTP** : Les données encodées sont placées dans le corps d'une requête HTTP POST et envoyées au serveur web.
4. **Traitement Côté Serveur** : Le serveur reçoit la requête POST, décode les données et les traite selon la logique de l'application.

#### <mark style="color:green;">Exemple de Requête POST</mark>

Voici un exemple simplifié de ce à quoi pourrait ressembler une requête POST lors de la soumission d'un formulaire de connexion :

```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=your_username&password=your_password
```

* **POST** : Indique la méthode HTTP (POST).
* **/login** : Spécifie le chemin URL où les données du formulaire sont envoyées.
* **Content-Type** : Spécifie comment les données dans le corps de la requête sont encodées (application/x-www-form-urlencoded dans ce cas).
* **Corps de la Requête** : Contient les données du formulaire encodées sous forme de paires clé-valeur (username et password).

***

### <mark style="color:blue;">Utilisation de wenum</mark>

Pour suivre, démarrez le système cible via la section questions en bas de la page, en remplaçant les utilisations de `IP:PORT` par l'IP:PORT de votre instance créée. Nous utiliserons les listes de mots `/usr/share/seclists/Discovery/Web-Content/common.txt` pour ces tâches de fuzzing.

#### <mark style="color:green;">Installation de wenum</mark>

Préparons d'abord nos outils en installant wenum sur notre hôte d'attaque :

```bash
mrrobotEliot_1@htb[/htb]$ pipx install git+https://github.com/WebFuzzForge/wenum
mrrobotEliot_1@htb[/htb]$ pipx runpip wenum install setuptools
```

***

### <mark style="color:blue;">Fuzzing de Paramètres GET</mark>

#### <mark style="color:green;">Exploration Manuelle</mark>

```bash
mrrobotEliot_1@htb[/htb]$ curl http://IP:PORT/get.php
```

**Réponse :**

```
Invalid parameter value
x: 
```

La réponse nous indique que le paramètre `x` est manquant. Essayons d'ajouter une valeur :

```bash
mrrobotEliot_1@htb[/htb]$ curl http://IP:PORT/get.php?x=1
```

**Réponse :**

```
Invalid parameter value
x: 1
```

#### <mark style="color:green;">Fuzzing Automatisé avec wenum</mark>

Deviner manuellement les valeurs de paramètres serait fastidieux et chronophage. C'est là que wenum s'avère pratique. Il nous permet d'automatiser le processus de test de nombreuses valeurs potentielles, augmentant considérablement nos chances de trouver la bonne.

Utilisons wenum pour fuzzer la valeur du paramètre "x", en commençant par la liste de mots common.txt de SecLists :

{% code overflow="wrap" fullWidth="true" %}
```bash
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://IP:PORT/get.php?x=FUZZ"
```
{% endcode %}

**Sortie :**

```
...
 Code    Lines     Words        Size  Method   URL 
...
 200       1 L       1 W        25 B  GET      http://IP:PORT/get.php?x=OA... 
```

**Explication des options :**

* `-w` : Chemin vers votre liste de mots.
* `--hc 404` : Masque les réponses avec le code de statut 404 (Non Trouvé), car wenum enregistre par défaut chaque requête qu'il effectue.
* `http://IP:PORT/get.php?x=FUZZ` : C'est l'URL cible. wenum remplacera la valeur du paramètre FUZZ par des mots de la liste de mots.

#### <mark style="color:green;">Analyse des Résultats</mark>

En analysant les résultats, vous remarquerez que la plupart des requêtes renvoient le message "Invalid parameter value" et la valeur incorrecte que vous avez essayée. Cependant, une ligne se démarque :

```bash
200       1 L       1 W        25 B  GET      http://IP:PORT/get.php?x=OA...
```

Cela indique que lorsque le paramètre `x` était défini sur la valeur "OA...", le serveur a répondu avec un code de statut 200 OK, suggérant une entrée valide.

***

### <mark style="color:blue;">Fuzzing de Paramètres POST</mark>

#### <mark style="color:green;">Exploration Manuelle</mark>

```bash
curl -d "" http://IP:PORT/post.php
```

**Réponse :**

```
Invalid parameter value
y: 
```

#### <mark style="color:green;">Fuzzing Automatisé avec ffuf</mark>

Comme pour les paramètres GET, tester manuellement les valeurs des paramètres POST serait inefficace. Nous utiliserons ffuf pour automatiser ce processus :

{% code overflow="wrap" fullWidth="true" %}
```bash
ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
```
{% endcode %}

**Sortie :**

```shellscript
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://IP:PORT/post.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : y=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

[Status: 200, Size: 26, Words: 1, Lines: 2, Duration: 7ms]
| URL | http://IP:PORT/post.php
    * FUZZ: SU...

:: Progress: [4730/4730] :: Job [1/1] :: 5555 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

**Explication des options :**

* `-u` : URL cible
* `-X POST` : Méthode HTTP POST
* `-H` : En-tête HTTP personnalisé
* `-d` : Données POST (y=FUZZ)
* `-w` : Chemin vers la liste de mots
* `-mc 200` : Correspond uniquement aux codes de statut 200
* `-v` : Mode verbeux

La principale différence ici est l'utilisation du flag `-d`, qui indique à ffuf que la charge utile ("y=FUZZ") doit être envoyée dans le corps de la requête en tant que données POST.

***
