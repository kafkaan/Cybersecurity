# WINDOWS COMMAND PROMPT

## &#x20;<mark style="color:red;">**GETTING HELP - WINDOWS COMMAND PROMPT**</mark>

***

### <mark style="color:blue;">**📋 I. SYSTÈME D'AIDE INTÉGRÉ**</mark>

#### <mark style="color:green;">**A. Commande**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`help`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**de Base**</mark>

**Syntaxe :**

```cmd
help
```

**Fonction :**

* Affiche la liste de **toutes les commandes intégrées** (built-in)
* Donne une **description courte** de chaque commande
* Point de départ pour découvrir les commandes disponibles

**Exemple de sortie :**

```cmd
C:\htb> help

For more information on a specific command, type HELP command-name
ASSOC          Displays or modifies file extension associations.
ATTRIB         Displays or changes file attributes.
BREAK          Sets or clears extended CTRL+C checking.
BCDEDIT        Sets properties in boot database to control boot loading.
CACLS          Displays or modifies access control lists (ACLs) of files.
CALL           Calls one batch program from another.
CD             Displays the name of or changes the current directory.
CHCP           Displays or sets the active code page number.
CHDIR          Displays the name of or changes the current directory.
CHKDSK         Checks a disk and displays a status report.
<snip>
```

***

#### <mark style="color:green;">**B. Aide Détaillée sur une Commande Spécifique**</mark>

**Syntaxe :**

```cmd
help <nom_commande>
```

**Exemple : Aide pour la commande `time`**

```cmd
C:\htb> help time

Displays or sets the system time.

TIME [/T | time]

Type TIME with no parameters to display the current time setting and a prompt
for a new one. Press ENTER to keep the same time.

If Command Extensions are enabled, the TIME command supports
the /T switch which tells the command to just output the
current time, without prompting for a new time.
```

**Informations fournies :**

* ✅ Description de la commande
* ✅ Syntaxe complète
* ✅ Paramètres disponibles
* ✅ Exemples d'utilisation
* ✅ Comportements spéciaux

***

#### <mark style="color:green;">**C. Modificateur**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`/?`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**- Alternative**</mark>

**Problème avec certaines commandes :** Toutes les commandes ne sont pas supportées par `help`

**Exemple :**

```cmd
C:\htb> help ipconfig

This command is not supported by the help utility. Try "ipconfig /?".
```

**Solution : Utiliser `/?`**

```cmd
C:\htb> ipconfig /?
```

**Règle générale :**

```
help <commande>     → Pour commandes built-in
<commande> /?       → Pour commandes externes et built-in
```

**Les deux syntaxes sont souvent interchangeables !**

***

### <mark style="color:blue;">**❓ II. POURQUOI UTILISER L'AIDE INTÉGRÉE ?**</mark>

#### <mark style="color:green;">**A. Scénario Réel**</mark>

**Situation :**

> Vous êtes en mission de pentest interne pour l'entreprise GreenHorn. Vous avez accès à un Command Prompt sur une machine du réseau interne. Règles d'engagement :
>
> * ❌ Pas d'appareils personnels
> * ❌ Firewall bloque tout trafic sortant
> * ❌ Pas d'accès Internet
> * ✅ Vous devez énumérer le système
> * ⚠️ Vous ne vous souvenez plus de la syntaxe exacte d'une commande

**Question : Où trouvez-vous l'information ?**

***

### <mark style="color:blue;">**🌐 III. RESSOURCES EXTERNES**</mark>

#### <mark style="color:green;">**A. Documentation Microsoft Officielle**</mark>

**URL :** [Microsoft Docs - Command-Line Reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)

**Contenu :**

* 📚 Liste complète des commandes CMD
* 📝 Descriptions détaillées
* 💡 Exemples d'utilisation
* 🔄 Mises à jour régulières

**Équivalent :** Version en ligne des Man Pages

***

#### <mark style="color:green;">**B. SS64.com**</mark>

**URL :** [ss64.com](https://ss64.com/)

**Avantages :**

* ⚡ Référence rapide
* 🖥️ Multi-plateformes :
  * Windows CMD
  * PowerShell
  * Bash (Linux)
  * MacOS
* 🎯 Exemples concrets
* 📋 Syntaxe claire

***

### <mark style="color:blue;">**🛠️ IV. TRUCS & ASTUCES ESSENTIELS**</mark>

#### <mark style="color:green;">**A. Nettoyer l'Écran -**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`cls`**</mark>

**Problème :**

* Écran surchargé de texte
* Difficulté à lire les sorties récentes
* Confusion entre anciennes et nouvelles commandes

**Solution :**

```cmd
cls
```

**Effet :**

* ✨ Efface tout le contenu visible
* 📄 Donne un écran vierge
* 🔄 Ne supprime PAS l'historique

**Utilisation :**

```cmd
C:\htb> ipconfig /all
[... beaucoup de sortie ...]
C:\htb> systeminfo
[... encore plus de sortie ...]
C:\htb> cls
[Écran maintenant vide]
C:\htb>
```

***

#### <mark style="color:green;">**B. Historique des Commandes**</mark>

**1. Qu'est-ce que l'Historique ?**

**Définition :**

* 💾 Mémoire des commandes exécutées dans la **session active**
* 🔄 Dynamique et temporaire
* ❌ **NON persistant** (perdu à la fermeture de CMD)

**Différence avec Linux/Bash :**

* Linux : Historique sauvegardé dans `~/.bash_history`
* CMD : Historique **seulement en mémoire** de la session

***

**2. Commande `doskey /history`**

**Syntaxe :**

```cmd
doskey /history
```

**Exemple de sortie :**

```cmd
C:\htb> doskey /history

systeminfo
ipconfig /all
cls
ipconfig /all
systeminfo
cls
help
doskey /history
ping 8.8.8.8
doskey /history
```

**Utilisation :**

* Voir toutes les commandes précédentes
* Retrouver une syntaxe utilisée plus tôt
* Documenter ses actions

***

**3. Sauvegarder l'Historique**

**Dans un fichier :**

```cmd
doskey /history > commands.txt
```

**Afficher et copier :**

```cmd
doskey /history
[Sélectionner et copier manuellement]
```

***

#### <mark style="color:green;">**C. Navigation dans l'Historique - Touches Clavier**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Touche/Commande</strong></td><td><strong>Fonction</strong></td></tr><tr><td><code>↑</code> (Flèche Haut)</td><td>Commande précédente (remonte dans l'historique)</td></tr><tr><td><code>↓</code> (Flèche Bas)</td><td>Commande suivante (descend dans l'historique)</td></tr><tr><td><code>Page Up</code></td><td><strong>Première</strong> commande de l'historique</td></tr><tr><td><code>Page Down</code></td><td><strong>Dernière</strong> commande de l'historique</td></tr><tr><td><code>→</code> (Flèche Droite)</td><td>Retape la commande précédente <strong>caractère par caractère</strong></td></tr><tr><td><code>←</code> (Flèche Gauche)</td><td>N/A (pas de fonction spéciale)</td></tr><tr><td><code>F3</code></td><td>Retape <strong>toute</strong> la commande précédente</td></tr><tr><td><code>F5</code></td><td>Cycle à travers les commandes précédentes</td></tr><tr><td><code>F7</code></td><td>Ouvre une <strong>liste interactive</strong> des commandes</td></tr><tr><td><code>F9</code></td><td>Entre une commande par son <strong>numéro</strong> dans l'historique</td></tr><tr><td><code>doskey /history</code></td><td>Affiche l'historique complet en texte</td></tr></tbody></table>

***

<mark style="color:orange;">**Exemples Pratiques**</mark>

**Scénario 1 : Réexécuter la dernière commande**

```cmd
C:\htb> ipconfig /all
[sortie...]
C:\htb> [Appuyer sur ↑]
C:\htb> ipconfig /all  [commande réapparaît]
```

**Scénario 2 : Liste interactive (F7)**

```cmd
[Appuyer sur F7]
┌─────────────────────────────┐
│ 1: systeminfo               │
│ 2: ipconfig /all            │
│ 3: cls                      │
│ 4: ping 8.8.8.8             │
└─────────────────────────────┘
[Utiliser ↑↓ pour sélectionner, Enter pour exécuter]
```

**Scénario 3 : Commande par numéro (F9)**

```cmd
[Appuyer sur F9]
Line number: 2
C:\htb> ipconfig /all  [commande #2 chargée]
```

***

#### <mark style="color:$success;">**D. Interrompre un Processus -**</mark><mark style="color:$success;">**&#x20;**</mark><mark style="color:$success;">**`Ctrl+C`**</mark>

**Situations**

**Quand utiliser `Ctrl+C` :**

* ⏸️ Commande qui prend trop de temps
* 🔄 Processus en boucle infinie
* ❌ Application qui ne répond plus
* ✅ Information déjà obtenue

**Exemple : Ping infini**

**Sans interruption :**

```cmd
C:\htb> ping 8.8.8.8

Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=22ms TTL=114
Reply from 8.8.8.8: bytes=32 time=25ms TTL=114
Reply from 8.8.8.8: bytes=32 time=23ms TTL=114
[Continue indéfiniment...]
```

**Avec interruption :**

```cmd
C:\htb> ping 8.8.8.8

Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=22ms TTL=114
Reply from 8.8.8.8: bytes=32 time=25ms TTL=114

Ping statistics for 8.8.8.8:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 22ms, Maximum = 25ms, Average = 23ms
^C
[Ctrl+C pressé - processus interrompu]

C:\htb>
```

**⚠️ Précautions**

**Risques de `Ctrl+C` :**

* ⚠️ Processus incomplet
* ⚠️ Données potentiellement corrompues
* ⚠️ Fermeture impropre d'applications
* ⚠️ Fichiers temporaires non nettoyés

**Conseil :** Toujours vérifier ce que vous interrompez avant d'appuyer sur `Ctrl+C`

***

### <mark style="color:blue;">**📊 V. TABLEAU RÉCAPITULATIF DES COMMANDES D'AIDE**</mark>

| **Commande**                 | **Fonction**                          | **Exemple**                 |
| ---------------------------- | ------------------------------------- | --------------------------- |
| `help`                       | Liste toutes les commandes built-in   | `help`                      |
| `help <cmd>`                 | Aide détaillée pour une commande      | `help time`                 |
| `<cmd> /?`                   | Aide pour commandes externes/built-in | `ipconfig /?`               |
| `cls`                        | Efface l'écran                        | `cls`                       |
| `doskey /history`            | Affiche l'historique                  | `doskey /history`           |
| `doskey /history > file.txt` | Sauvegarde l'historique               | `doskey /history > log.txt` |
| `Ctrl+C`                     | Interrompt le processus actuel        | `[Ctrl+C]`                  |

***
