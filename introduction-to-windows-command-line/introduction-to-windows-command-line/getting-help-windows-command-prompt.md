# GETTING HELP - WINDOWS COMMAND PROMPT

## &#x20;<mark style="color:red;">**GETTING HELP - WINDOWS COMMAND PROMPT**</mark>

***

### <mark style="color:blue;">**📋 I. SYSTÈME D'AIDE INTÉGRÉ**</mark>

#### **A. Commande `help` de Base**

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

#### **B. Aide Détaillée sur une Commande Spécifique**

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

#### **C. Modificateur `/?` - Alternative**

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

#### **A. Scénario Réel**

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

#### **B. Réponses aux Questions Fondamentales**

**1. Pourquoi l'utilitaire d'aide existe-t-il ?**

**Réponse :**

* 📖 **Manuel hors-ligne** pour CMD et commandes DOS/Windows
* 🔌 **Fonctionne sans réseau** (offline)
* 🐧 **Équivalent aux Man Pages** sur Linux

**Avantages :**

* Autonomie complète
* Pas de dépendance externe
* Disponibilité garantie

***

**2. Quelle utilité aujourd'hui avec Internet omniprésent ?**

**Situations où l'aide intégrée est cruciale :**

**A. Environnements restreints :**

* 🔒 Réseau isolé (air-gapped)
* 🚫 Firewall bloquant le trafic sortant
* 📡 Pas de connexion réseau disponible
* 🎯 Environnement de production critique

**B. Contextes de pentest/red team :**

* 🕵️ Éviter la détection (pas de requêtes DNS suspectes)
* ⚡ Rapidité (pas d'attente de chargement)
* 🎭 Discrétion (pas de logs de recherches web)

**C. Situations d'urgence :**

* 🔥 Panne réseau
* ⏱️ Temps de réponse critique
* 🛠️ Mode de récupération/réparation

***

### <mark style="color:blue;">**🌐 III. RESSOURCES EXTERNES**</mark>

#### **A. Documentation Microsoft Officielle**

**URL :** [Microsoft Docs - Command-Line Reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)

**Contenu :**

* 📚 Liste complète des commandes CMD
* 📝 Descriptions détaillées
* 💡 Exemples d'utilisation
* 🔄 Mises à jour régulières

**Équivalent :** Version en ligne des Man Pages

***

#### **B. SS64.com**

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

#### **C. Autres Ressources**

* Stack Overflow (questions/réponses)
* GitHub (scripts et exemples)
* Forums techniques Windows
* Blogs de cybersécurité

**⚠️ Important :** Ces ressources sont excellentes **SI** vous avez accès Internet

***

### <mark style="color:blue;">**🛠️ IV. TRUCS & ASTUCES ESSENTIELS**</mark>

#### **A. Nettoyer l'Écran - `cls`**

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

#### **B. Historique des Commandes**

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

#### **C. Navigation dans l'Historique - Touches Clavier**

| **Touche/Commande** | **Fonction**                                              |
| ------------------- | --------------------------------------------------------- |
| `↑` (Flèche Haut)   | Commande précédente (remonte dans l'historique)           |
| `↓` (Flèche Bas)    | Commande suivante (descend dans l'historique)             |
| `Page Up`           | **Première** commande de l'historique                     |
| `Page Down`         | **Dernière** commande de l'historique                     |
| `→` (Flèche Droite) | Retape la commande précédente **caractère par caractère** |
| `←` (Flèche Gauche) | N/A (pas de fonction spéciale)                            |
| `F3`                | Retape **toute** la commande précédente                   |
| `F5`                | Cycle à travers les commandes précédentes                 |
| `F7`                | Ouvre une **liste interactive** des commandes             |
| `F9`                | Entre une commande par son **numéro** dans l'historique   |
| `doskey /history`   | Affiche l'historique complet en texte                     |

***

**Exemples Pratiques**

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

#### **D. Interrompre un Processus - `Ctrl+C`**

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
