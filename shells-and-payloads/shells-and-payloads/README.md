---
description: https://medium.com/@ahmadallobani232/the-live-engagement-70c845bdb5ad
---

# Shells And Payloads

***

Chaque système d’exploitation possède un shell, et pour interagir avec lui, nous devons utiliser une application appelée émulateur de terminal. Voici quelques-uns des émulateurs de terminal les plus courants&#x20;

| **Terminal Emulator**                                          | **Operating System**     |
| -------------------------------------------------------------- | ------------------------ |
| [Windows Terminal](https://github.com/microsoft/terminal)      | Windows                  |
| [cmder](https://cmder.app)                                     | Windows                  |
| [PuTTY](https://www.putty.org)                                 | Windows                  |
| [kitty](https://sw.kovidgoyal.net/kitty/)                      | Windows, Linux and MacOS |
| [Alacritty](https://github.com/alacritty/alacritty)            | Windows, Linux and MacOS |
| [xterm](https://invisible-island.net/xterm/)                   | Linux                    |
| [GNOME Terminal](https://en.wikipedia.org/wiki/GNOME_Terminal) | Linux                    |
| [MATE Terminal](https://github.com/mate-desktop/mate-terminal) | Linux                    |
| [Konsole](https://konsole.kde.org)                             | Linux                    |
| [Terminal](https://en.wikipedia.org/wiki/Terminal_\(macOS\))   | MacOS                    |
| [iTerm2](https://iterm2.com)                                   | MacOS                    |

***

### <mark style="color:red;">Qu'est-ce qu'un interprète de langage de commande ?</mark>

Un interprète de langage de commande est un programme qui :

* Reçoit des instructions sous forme de texte (« commandes »).
* Traduire ces instructions pour le système d'exploitation.
* Demande au système d'exécuter ces instructions.

**Analogie :** C'est comme un interprète humain qui traduit entre deux langues. Ici, il traduit les commandes de l'utilisateur en un format compréhensible pour le système d'exploitation.

***

### <mark style="color:red;">Les trois éléments de l'interface en ligne de commande :</mark>

1. **Système d'exploitation** : L'entité qui gère les ressources matérielles et logicielles.
2. **Émulateur de terminal** : Un programme simulant un terminal physique.
3. **Interprète de commandes (shell)** : Traduit et exécute les commandes utilisateur.

#### Importance de connaître l'interprète utilisé

Chaque interprète (comme Bash, PowerShell, Zsh) a ses propres commandes et syntaxe. Identifier l'interprète permet de :

* Utiliser les commandes compatibles.
* Automatiser des tâches ou scripts de manière efficace.
* Exploiter des vulnérabilités potentielles lors d'audits sécurité.

***

### <mark style="color:red;">**Exploration pratique : Emulateurs et shells**</mark>

#### <mark style="color:green;">**Exemple pratique avec Parrot OS Pwnbox**</mark>

1. **Démarrage de l'émulateur de terminal :**
   * Cliquer sur l'icône verte pour ouvrir le terminal MATE.
2. **Prompt du shell :**
   * Un **`$`** indique que Bash ou un shell similaire est utilisé.
   * Si une commande inconnue est tapée, le shell renvoie une erreur, par exemple : « Command not found ».

#### **Validation de l'interprète en cours**

1.  **Commande `ps` :** Liste les processus actifs.

    ```bash
    mrroboteLiot@htb[/htb]$ ps

        PID TTY          TIME CMD
       4232 pts/1    00:00:00 bash
      11435 pts/1    00:00:00 ps
    ```

    Ici, **bash** est le shell actif.
2.  **Commande `env` :** Affiche les variables d'environnement.

    ```bash
    mrroboteLiot@htb[/htb]$ env

    SHELL=/bin/bash
    ```

    Variable **SHELL** confirmant que Bash est l'interprète de commandes.

***

### <mark style="color:red;">**Terminologie clé**</mark>

#### <mark style="color:green;">1.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Terminal**</mark>

* Une interface pour entrer et afficher des commandes.
* À l'origine, était un périphérique physique (clavier et écran).
* Aujourd'hui, c'est souvent un logiciel (émulateur de terminal).

<mark style="color:green;">**Exemples d'émulateurs de terminal :**</mark>

* **Linux** : GNOME Terminal, Konsole.
* **Windows** : cmd.exe (Invite de commandes), Windows Terminal, PowerShell.
* **macOS** : Terminal.

#### <mark style="color:green;">2.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Interprète de commandes (shell)**</mark>

Programme qui :

* Lit et interprète les commandes tapées dans le terminal.
* Exécute les commandes et affiche les résultats.

**Principaux shells :**

* **Bash (Bourne Again Shell)** : Standard pour Linux/macOS.
* **PowerShell** : Utilisé sous Windows pour l'administration et l'automatisation.
* **Zsh** : Amélioration de Bash avec plus de fonctions.
* **Cmd.exe** : Invite de commandes classique sous Windows.

***

### <mark style="color:red;">Comparaison :</mark> <mark style="color:red;"></mark><mark style="color:red;">**PowerShell vs Bash**</mark>

| Caractéristique | **Bash**                        | **PowerShell**                             |
| --------------- | ------------------------------- | ------------------------------------------ |
| **Plateforme**  | Linux/macOS (Windows via WSL)   | Windows (aussi disponible sur Linux/macOS) |
| **Syntaxe**     | Orientée texte                  | Basée sur des objets                       |
| **Usage**       | Scripts simples, administration | Automatisation avancée, DevOps             |
| **Prompt**      | `$`                             | `PS>`                                      |

***

