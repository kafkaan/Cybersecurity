# The Concept of Attacks

***

Pour comprendre efficacement les attaques sur les différents services, il est essentiel d’analyser comment ces services peuvent être ciblés. Un concept est une sorte de plan général qui peut être appliqué à plusieurs projets futurs.

**Exemple concret :**\
Imaginez la construction d’une maison. La plupart des maisons ont un sous-sol, quatre murs et un toit. Ce modèle général est utilisé dans le monde entier. Cependant, les détails comme les matériaux ou le design varient en fonction des besoins et des préférences individuelles. Cela montre qu’un concept repose sur des éléments généraux (sol, murs, toit) tout en laissant place à des ajustements spécifiques.

**Application aux services informatiques :**\
De la même manière, nous devons créer un concept pour les attaques sur différents services (SSH, FTP, SMB, HTTP). Il est utile de diviser ces services en catégories qui partagent des points communs, tout en gardant la flexibilité pour des méthodes d’attaques spécifiques à chaque service.

**Objectif :**\
L’objectif est de regrouper ces services et d’identifier ce qu’ils ont en commun. Ensuite, il faut établir une structure permettant de détecter les points d’attaque à travers un schéma unique, peu importe le service analysé.

**Processus évolutif :**\
Créer des modèles d’attaques basés sur des schémas communs n’est pas un produit fini. C’est un processus en constante évolution. À mesure que nous analysons de nouveaux cas, ces modèles deviennent plus complets et efficaces.

**Pourquoi ce modèle est important :**\
Ce modèle vous aide à mieux comprendre et expliquer les attaques en se basant sur des schémas reproductibles et évolutifs. Il facilite également l’enseignement et la transmission des connaissances autour des attaques sur différents services.

<mark style="color:green;">**The Concept of Attacks**</mark>

![](https://academy.hackthebox.com/storage/modules/116/attack_concept2.png)

{% hint style="warning" %}
Le concept repose sur **quatre catégories** qui s’appliquent à chaque vulnérabilité. Voici l’explication détaillée&#x20;

1\. **Source** :

* C’est l’origine de la requête ou de l’information.
* Par exemple, cela pourrait être un utilisateur, un script ou un programme qui envoie une commande ou une requête.

2\. **Processus** :

* C’est l’endroit où la vulnérabilité est déclenchée.
* Le processus prend la requête de la source et l’exécute. C’est là que des failles peuvent apparaître (par exemple, mauvaise gestion des entrées).

3\. **Privilèges** :

* Chaque processus s’exécute avec un ensemble de privilèges spécifiques.
* Ces privilèges déterminent **ce que le processus peut ou ne peut pas faire**. Une vulnérabilité est souvent exploitée pour élever ces privilèges (exploitation de type **escalade de privilèges**).

4\. **Destination** :

* C’est l’objectif final du processus.
* Cela peut être :
  * **Calculer de nouvelles données**
  * **Transférer des informations à un autre service**
  * **Stocker des résultats**
* La destination n’agit **pas toujours comme une nouvelle source**. Une fois la tâche accomplie, elle ne redémarre pas forcément un nouveau cycle.

***

**Pourquoi ce modèle est linéaire :**

* Chaque tâche suit une séquence logique : **Source → Processus → Destination**.
* Il n’y a **pas de boucle automatique** où la destination devient immédiatement une nouvelle source (sauf cas particuliers). Cela rend l’analyse plus simple et linéaire.

***

**Application du concept :**

* Pour qu’une tâche existe, il faut :
  1. Une idée ou des données à traiter (**Source**)
  2. Un plan pour exécuter cette tâche (**Processus**)
  3. Un objectif final à atteindre (**Destination**)
  4. Un contrôle de sécurité sur ce qui peut être fait (**Privilèges**)
{% endhint %}

***

### <mark style="color:blue;">Source</mark>

On peut généraliser **Source** comme étant une **source d'information utilisée pour une tâche spécifique** dans un processus. Il existe plusieurs façons de transmettre des informations à un processus.

Ainsi, la **source** représente le point d'entrée exploitable pour des vulnérabilités. Peu importe le protocole utilisé, car des attaques comme l’injection d’en-têtes HTTP ou les dépassements de mémoire tampon peuvent être manipulées manuellement.

Dans ce contexte, la source peut être classée comme **Code**. Examinons donc de plus près le modèle basé sur l'une des dernières vulnérabilités critiques dont beaucoup ont entendu parler.

<mark style="color:orange;">**Log4j**</mark>

Un excellent exemple est la vulnérabilité critique **Log4j** (CVE-2021-44228), publiée à la fin de l'année 2021. **Log4j** est un framework ou une bibliothèque utilisée pour enregistrer les messages des applications en **Java** et d'autres langages de programmation.

Cette bibliothèque contient des **classes** et des **fonctions** pouvant être intégrées à d'autres langages. Son objectif est de documenter des informations, à la manière d’un journal de bord (**logbook**). De plus, l’étendue de cette documentation est **hautement configurable**, ce qui a fait de Log4j un **standard** dans de nombreux logiciels **open source** et commerciaux.

Dans cet exemple, un attaquant peut **manipuler l'en-tête HTTP User-Agent** et y insérer une **requête JNDI**, exécutée comme une commande par la bibliothèque Log4j. Ainsi, au lieu de traiter l’en-tête **User-Agent classique** (exemple : _Mozilla 5.0_), c’est la requête **JNDI lookup** qui est interprétée, permettant une exploitation de la vulnérabilité.

***

### <mark style="color:blue;">Processes</mark>

Le processus consiste à traiter les informations transmises par la source. Celles-ci sont traitées selon la tâche prévue définie par le code du programme. Pour chaque tâche, le développeur spécifie comment les informations sont traitées. Cela peut se faire à l'aide de classes avec différentes fonctions, calculs et boucles. La variété des possibilités est aussi grande que le nombre de développeurs dans le monde. En conséquence, la plupart des vulnérabilités se trouvent dans le code du programme exécuté par le processus.

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Process Components</strong></td><td><strong>Description</strong></td></tr><tr><td><code>PID</code></td><td>The Process-ID (PID) identifies the process being started or is already running. Running processes have already assigned privileges, and new ones are started accordingly.</td></tr><tr><td><code>Input</code></td><td>This refers to the input of information that could be assigned by a user or as a result of a programmed function.</td></tr><tr><td><code>Data processing</code></td><td>The hard-coded functions of a program dictate how the information received is processed.</td></tr><tr><td><code>Variables</code></td><td>The variables are used as placeholders for information that different functions can further process during the task.</td></tr><tr><td><code>Logging</code></td><td>During logging, certain events are documented and, in most cases, stored in a register or a file. This means that certain information remains in the system.</td></tr></tbody></table>

<mark style="color:orange;">**Log4j**</mark>

Le processus de **Log4j** consiste à **enregistrer l’en-tête User-Agent** sous forme de chaîne de caractères à l’aide d’une fonction, puis à le stocker dans un emplacement prévu à cet effet.

🔹 **Où est la faille ?**\
Le problème vient du **mauvais traitement** de cette chaîne :

* Au lieu de simplement **enregistrer** la valeur du User-Agent dans les logs,
* Log4j **exécute une requête** si la chaîne contient une instruction spécifique (comme une requête JNDI).

C’est cette **erreur d’interprétation** qui **permet aux attaquants d’exécuter du code à distance (RCE)**.

🔹 **Pourquoi parle-t-on de privilèges ?**\
Avant d'explorer davantage cette fonction, il est important de **prendre en compte les privilèges** :

* Si le processus Log4j tourne avec **des privilèges élevés (admin/root)**, l’attaquant peut **prendre le contrôle total du système**.
* Avec des **droits limités**, l’impact est réduit, mais reste dangereux.

👉 **En résumé** : La faille vient du fait que Log4j **exécute du code au lieu de simplement l’enregistrer**, et son impact dépend des **droits** avec lesquels il fonctionne. 🚨

***

### <mark style="color:blue;">Privileges</mark>

Les **privilèges** sont présents dans tout système qui contrôle les processus. Ils servent de **permissions** permettant de déterminer quelles actions peuvent être effectuées sur le système.

En termes simples, on peut les comparer à un **ticket de bus** :

* Si nous avons un ticket valide pour une région spécifique, nous pouvons utiliser le bus.
* Sinon, l’accès nous est refusé.

De la même manière, ces **privilèges** (ou **tickets**, en comparaison) peuvent être utilisés pour différents **moyens de transport**, comme les **avions, trains, bateaux, etc.**

Dans les **systèmes informatiques**, ces privilèges permettent de **contrôler et segmenter** les actions en fonction des **autorisations nécessaires**, qui sont gérées par le système.

Ainsi, lorsque **un processus** doit exécuter une tâche, le système **vérifie ses droits** en fonction de cette catégorisation :

* **Si les privilèges sont suffisants**, l’action est **approuvée**.
* **Sinon, elle est refusée**.

Nous pouvons diviser ces **privilèges** en plusieurs **catégories**, que nous allons détailler ci-dessous. 🚀

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Privileges</strong></td><td><strong>Description</strong></td></tr><tr><td><code>System</code></td><td>These privileges are the highest privileges that can be obtained, which allow any system modification. In Windows, this type of privilege is called <code>SYSTEM</code>, and in Linux, it is called <code>root</code>.</td></tr><tr><td><code>User</code></td><td>User privileges are permissions that have been assigned to a specific user. For security reasons, separate users are often set up for particular services during the installation of Linux distributions.</td></tr><tr><td><code>Groups</code></td><td>Groups are a categorization of at least one user who has certain permissions to perform specific actions.</td></tr><tr><td><code>Policies</code></td><td>Policies determine the execution of application-specific commands, which can also apply to individual or grouped users and their actions.</td></tr><tr><td><code>Rules</code></td><td>Rules are the permissions to perform actions handled from within the applications themselves.</td></tr></tbody></table>

* **Policies** = **Règles globales** qui affectent l'exécution des commandes et l'accès à des actions spécifiques.
* **Rules** = **Permissions internes** aux applications qui contrôlent ce que l’utilisateur peut faire à l'intérieur de celles-ci.

<mark style="color:orange;">**Log4j**</mark>

What made the Log4j vulnerability so dangerous was the `Privileges` that the implementation brought. Logs are often considered sensitive because they can contain data about the service, the system itself, or even customers. Therefore, logs are usually stored in locations that no regular user should be able to access. Accordingly, most applications with the Log4j implementation were run with the privileges of an administrator. The process itself exploited the library by manipulating the User-Agent so that the process misinterpreted the source and led to the execution of user-supplied code.

***

### <mark style="color:blue;">Destination</mark>

Chaque tâche a **au moins un objectif** et un **but** qui doivent être atteints. Logiquement, si aucune modification des données n’était effectuée, stockée ou transmise quelque part, la tâche serait **inutile**.

Le **résultat** d’une telle tâche est soit **enregistré quelque part**, soit **transmis à un autre point de traitement**. C’est pourquoi on parle ici de la **Destination**, où les modifications seront appliquées.

Ces **points de traitement** peuvent être :

* **Locaux** (modification de fichiers ou enregistrement de données sur la machine).
* **Distants** (transmission des données à un autre service ou serveur).

Dans un environnement **local**, le processus peut modifier des fichiers locaux, **les transmettre à d’autres services**, ou **les réutiliser lui-même**.

Enfin, une fois que le processus a **stocké ou transmis** les données, le **cycle de la tâche est terminé**. ✅

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Destination</strong></td><td><strong>Description</strong></td></tr><tr><td><code>Local</code></td><td>The local area is the system's environment in which the process occurred. Therefore, the results and outcomes of a task are either processed further by a process that includes changes to data sets or storage of the data.</td></tr><tr><td><code>Network</code></td><td>The network area is mainly a matter of forwarding the results of a process to a remote interface. This can be an IP address and its services or even entire networks. The results of such processes can also influence the route under certain circumstances.</td></tr></tbody></table>

<mark style="color:orange;">**Log4j**</mark>

La **mauvaise interprétation** de l'en-tête **User-Agent** entraîne une requête **JNDI lookup**, qui est exécutée comme une **commande système avec des privilèges administrateur**. Cette commande interroge un **serveur distant contrôlé par l'attaquant**, qui représente ici la **Destination** dans notre concept d’attaques.

Cette requête récupère une **classe Java créée par l’attaquant**, spécialement manipulée pour servir ses propres objectifs. Le **code Java récupéré** à l’intérieur de cette classe est alors **exécuté dans le même processus**, ce qui entraîne une **vulnérabilité d'exécution de code à distance (RCE - Remote Code Execution).**

**GovCERT.ch** a réalisé une **excellente représentation graphique** de la faille **Log4j**, qui mérite d’être examinée en détail. 🚨

<figure><img src="../../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**Initiation of the Attack**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Step</strong></td><td><strong>Log4j</strong></td><td><strong>Concept of Attacks - Category</strong></td></tr><tr><td><code>1.</code></td><td>The attacker manipulates the user agent with a JNDI lookup command.</td><td><code>Source</code></td></tr><tr><td><code>2.</code></td><td>The process misinterprets the assigned user agent, leading to the execution of the command.</td><td><code>Process</code></td></tr><tr><td><code>3.</code></td><td>The JNDI lookup command is executed with administrator privileges due to logging permissions.</td><td><code>Privileges</code></td></tr><tr><td><code>4.</code></td><td>This JNDI lookup command points to the server created and prepared by the attacker, which contains a malicious Java class containing commands designed by the attacker.</td><td><code>Destination</code></td></tr></tbody></table>

This is when the cycle starts all over again, but this time to gain remote access to the target system.

<mark style="color:green;">**Trigger Remote Code Execution**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Step</strong></td><td><strong>Log4j</strong></td><td><strong>Concept of Attacks - Category</strong></td></tr><tr><td><code>5.</code></td><td>After the malicious Java class is retrieved from the attacker's server, it is used as a source for further actions in the following process.</td><td><code>Source</code></td></tr><tr><td><code>6.</code></td><td>Next, the malicious code of the Java class is read in, which in many cases has led to remote access to the system.</td><td><code>Process</code></td></tr><tr><td><code>7.</code></td><td>The malicious code is executed with administrator privileges due to logging permissions.</td><td><code>Privileges</code></td></tr><tr><td><code>8.</code></td><td>The code leads back over the network to the attacker with the functions that allow the attacker to control the system remotely.</td><td><code>Destination</code></td></tr></tbody></table>
