# Gestion des services

## <mark style="color:red;">📌 Gestion des services (Managing Services)</mark>

Surveiller et contrôler les **services Windows** sur une machine est une tâche essentielle pour un administrateur système.\
👉 **Du point de vue d’un attaquant**, c’est une capacité extrêmement recherchée, car elle permet :

* d’énumérer les services actifs,
* d’identifier des points d’accroche (hooks),
* d’activer, désactiver ou modifier des services,
* d’exploiter certains services pour de l’élévation de privilèges ou de la persistance.

Dans cette section, nous allons utiliser principalement l’outil **`sc`** (Service Controller), mais **avec une mentalité offensive**.

***

### <mark style="color:blue;">🎯 Objectifs de l’attaquant après compromission</mark>

Une fois connecté à une machine victime, nous cherchons à :

1. Déterminer quels services sont en cours d’exécution
2. Essayer de désactiver l’antivirus
3. Modifier des services existants

***

## <mark style="color:blue;">🛠️ Service Controller (SC)</mark>

**`sc.exe`** est un outil Windows en ligne de commande qui permet de :

* interroger les services,
* les démarrer / arrêter,
* les configurer,
* localement ou à distance.

Bien que d’autres outils existent (`WMIC`, `tasklist`, PowerShell), **`sc` est l’outil principal** dans cette section.

***

### <mark style="color:blue;">▶️</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`sc`</mark> <mark style="color:blue;"></mark><mark style="color:blue;">sans paramètres</mark>

```cmd
C:\htb> sc
```

#### Résultat

* Affiche l’aide intégrée
* Liste les commandes disponibles
* Fournit des exemples d’utilisation

#### Commandes principales

* `query` : interroger l’état d’un service
* `queryex` : version étendue
* `start` : démarrer un service
* `stop` : arrêter un service
* `config` : modifier un service

***

### <mark style="color:blue;">🔍 Interroger les services (Query Services)</mark>

Pouvoir récupérer :

* l’état d’un service,
* son PID,
* son type,

est **très précieux pour un attaquant**.

***

#### ⚠️ Important sur la syntaxe

La syntaxe est **très stricte** :

✅ Correct :

```cmd
sc query type= service
```

❌ Incorrect :

```cmd
sc query type=service
sc query type = service
```

***

### <mark style="color:blue;">📋 Lister tous les services actifs</mark>

```cmd
sc query type= service
```

Tu obtiens pour chaque service :

* `SERVICE_NAME`
* `DISPLAY_NAME`
* `STATE` (RUNNING / STOPPED)
* permissions (STOPPABLE, NOT\_PAUSABLE, etc.)

👉 Cela permet :

* d’identifier des services intéressants,
* de chercher des vecteurs d’attaque,
* de repérer des services détournables.

***

### <mark style="color:blue;">🛡️ Vérifier si Windows Defender est actif</mark>

```cmd
sc query windefend
```

#### Résultat

* Defender est **RUNNING**
* Il est **NOT\_STOPPABLE**
* Un utilisateur standard **ne peut pas l’arrêter**

***

### <mark style="color:blue;">❌ Tentative d’arrêt sans privilèges</mark>

```cmd
sc stop windefend
```

Résultat :

```
Access is denied.
```

➡️ **Normal** : utilisateur non administrateur.

***

### <mark style="color:blue;">❌ Même en tant qu’Administrateur</mark>

```cmd
sc stop windefend
```

Résultat :

```
Access is denied.
```

👉 Certaines protections (Defender) **ne peuvent être arrêtées que par SYSTEM**.

#### ⚠️ Leçon Red Team

* Tester à l’aveugle déclenche des logs
* Cela attire l’attention du blue team
* Il faut comprendre **les limites des privilèges**

***

## <mark style="color:blue;">🖨️ Exemple : Print Spooler (arrêtable)</mark>

#### Vérifier l’état

```cmd
sc query Spooler
```

#### Arrêter le service

```cmd
sc stop Spooler
```

#### Vérifier

```cmd
sc query Spooler
```

Résultat :

```
STATE : STOPPED
```

***

### <mark style="color:blue;">▶️ Démarrer un service</mark>

```cmd
sc start Spooler
```

États possibles :

* `START_PENDING`
* `RUNNING`

👉 Les services mettent souvent quelques secondes à démarrer.

***

## <mark style="color:blue;">✏️ Modifier des services (attaque avancée)</mark>

C’est ici que les attaquants **excellent** :

* désactiver des services,
* modifier leur binaire,
* créer de la persistance,
* empêcher les mises à jour.

⚠️ **Toute modification est persistante** (registre Windows).

{% hint style="info" %}
To configure services, we must use the [config](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config) parameter in `sc`. This will allow us to modify the values of existing services, regardless if they are currently running or not. All changes made with this command are reflected in the Windows registry as well as the database for Service Control Manager (`SCM`). Remember that all changes to existing services will only fully update after restarting the service.
{% endhint %}

***

### <mark style="color:blue;">❌ Désactiver Windows Update</mark>

Windows Update dépend de :

| Service  | Nom                                     |
| -------- | --------------------------------------- |
| wuauserv | Windows Update                          |
| bits     | Background Intelligent Transfer Service |

***

#### Vérifier leur état

```cmd
sc query wuauserv
sc query bits
```

***

#### Arrêter BITS

```cmd
sc stop bits
```

***

#### Désactiver les services

```cmd
sc config wuauserv start= disabled
sc config bits start= disabled
```

✔️ Succès confirmé

***

#### Vérification

```cmd
sc start wuauserv
sc start bits
```

Résultat :

```
FAILED 1058
The service cannot be started because it is disabled
```

👉 Windows **ne peut plus se mettre à jour**

***

### <mark style="color:blue;">🧠 Impact Attaquant</mark>

* Le système reste vulnérable
* Les correctifs de sécurité ne s’appliquent plus
* Mais : **action bruyante** → alertes possibles

***

## <mark style="color:$danger;">🔄 Autres moyens d’énumérer les services</mark>

***

### 🧾 `tasklist /svc`

```cmd
tasklist /svc
```

Affiche :

* les processus,
* leur PID,
* les services associés

👉 Très utile pour mapper **processus ↔ services**

***

### ⚡ `net start`

```cmd
net start
```

Liste **tous les services actifs**

Autres commandes :

* `net stop`
* `net pause`
* `net continue`

***

### 🧰 WMIC (déprécié)

```cmd
wmic service list brief
```

Affiche :

* Name
* ProcessID
* StartMode
* State
* Status

⚠️ **WMIC est déprécié** → éviter en production moderne

***
