# Introduction to Windows Command Line

## <mark style="color:red;">**WINDOWS COMMAND LINE - CMD.EXE**</mark>

***

### <mark style="color:blue;">**📋 I. INTRODUCTION À CMD.EXE**</mark>

#### <mark style="color:green;">**Définition**</mark>

* **Nom complet** : Command Prompt (Invite de commandes)
* **Exécutable** : `cmd.exe`
* **Origine** : Basé sur `COMMAND.COM` de DOS
* **Fonction** : Interpréteur de ligne de commande par défaut de Windows

#### <mark style="color:green;">**Caractéristiques**</mark>

* Présent sur **toutes les versions de Windows**
* Permet d'exécuter des commandes directement interprétées par l'OS
* **Consomme moins de ressources** que les programmes graphiques
* Toujours pertinent malgré l'existence de PowerShell

#### <mark style="color:green;">**Avantages**</mark>

✅ Une seule commande peut accomplir des tâches complexes (changer un mot de passe, vérifier l'état du réseau)\
✅ Utilisation réduite du CPU et de la mémoire\
✅ Fonctionne même quand PowerShell est bloqué (AppLocker, restrictions)

***

### <mark style="color:blue;">**📍 II. ACCÈS À CMD**</mark>

#### <mark style="color:green;">**A. Accès Local (Physical Access)**</mark>

**Définition :** Accès physique direct à la machine (ou virtuel via VM)

**Méthodes d'ouverture :**

**1. Via la boîte de dialogue Exécuter**

```
Windows + R → Taper "cmd" → Entrée
```

**2. Via le chemin complet**

```
C:\Windows\System32\cmd.exe
```

**3. Via le menu Démarrer**

```
Rechercher "cmd" ou "Invite de commandes"
```

**Caractéristiques :**

* Ne nécessite **pas de connexion réseau**
* Accès direct via périphériques (clavier, souris, écran)
* Interaction directe avec la machine

***

#### <mark style="color:green;">**B. Accès à Distance (Remote Access)**</mark>

**Définition :** Accès via périphériques virtuels sur le réseau

**Protocoles disponibles :**

* **SSH** (Secure Shell) - Recommandé ✅
* **WinRM** (Windows Remote Management)
* **RDP** (Remote Desktop Protocol)
* **PsExec** (Sysinternals)
* **Telnet** (Non sécurisé ❌, déconseillé)

**Avantages :**

* Pas besoin d'accès physique
* Gestion centralisée des machines
* Gain de temps pour les administrateurs

**Risques de sécurité :** ⚠️ Si mal configuré : point d'entrée pour les attaquants\
⚠️ Accès large au réseau si compromis\
⚠️ Nécessite un équilibre entre disponibilité et sécurité

***

### <mark style="color:blue;">**🖥️ III. UTILISATION DE BASE**</mark>

#### <mark style="color:green;">**A. Interface de CMD**</mark>

**Apparence typique :**

```cmd
Microsoft Windows [Version 10.0.19044.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Users\htb>
```

**Éléments de l'interface :**

1. **Chemin actuel** : `C:\Users\htb` (working directory)
2. **Prompt** : `>` (invite de saisie)
3. **Zone de commande** : où on tape les commandes

***

#### <mark style="color:green;">**B. Navigation dans le Système de Fichiers**</mark>

**Analogie :** Se déplacer dans CMD = marcher dans un couloir avec des portes (répertoires)

**Commande `dir` - Lister le contenu d'un répertoire**

```cmd
C:\Users\htb\Desktop> dir
```

**Sortie exemple :**

```cmd
 Volume in drive C has no label.
 Volume Serial Number is DAE9-5896

 Directory of C:\Users\htb\Desktop

06/11/2021  11:59 PM    <DIR>          .
06/11/2021  11:59 PM    <DIR>          ..
06/11/2021  11:57 PM                 0 file1.txt
06/11/2021  11:57 PM                 0 file2.txt
06/11/2021  11:57 PM                 0 file3.txt
04/13/2021  11:24 AM             2,391 Microsoft Teams.lnk
06/11/2021  11:57 PM                 0 super-secret-sauce.txt
06/11/2021  11:59 PM                 0 write-secrets.ps1
               6 File(s)          2,391 bytes
               2 Dir(s)  35,102,117,888 bytes free
```

**Lecture de la sortie :**

* `<DIR>` : Répertoire
* Date et heure de modification
* Taille du fichier (en octets)
* Nom du fichier/dossier
* `.` : Répertoire actuel
* `..` : Répertoire parent

***

#### <mark style="color:green;">**C. Modèle Request-Response**</mark>

**Fonctionnement :**

```
1. Utilisateur → Commande → Système
2. Système → Traitement → Résultat
3. Affichage → Utilisateur
```

**Exemple :**

```
REQUEST:  dir
RESPONSE: Liste des fichiers et dossiers
```

***

### <mark style="color:blue;">**🔧 IV. CAS D'USAGE AVANCÉS**</mark>

#### <mark style="color:green;">**A. Windows Recovery Mode**</mark>

**Contexte :** En cas de verrouillage ou problème technique

**Accès :**

1. Démarrer depuis un disque d'installation Windows
2. Choisir "Mode réparation" (Repair Mode)
3. Accès à un **Command Prompt avec privilèges élevés**

**Utilisation légitime :**

* Dépannage du système
* Réparation de fichiers corrompus
* Restauration du système

***

#### <mark style="color:green;">**B. Exploitation de Sticky Keys (Exemple de risque de sécurité)**</mark>

**Technique (Windows 7 et antérieurs) :**

**Étape 1 : Remplacer sethc.exe**

```cmd
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```

**Étape 2 : Redémarrer la machine**

**Étape 3 : Sur l'écran de connexion Windows**

* Appuyer **5 fois sur Shift**
* Au lieu de Sticky Keys → CMD s'ouvre
* **Privilèges : NT AUTHORITY\SYSTEM** (super utilisateur)

**Résultat :** ✅ Contournement de l'authentification\
✅ Accès système complet\
✅ Aucun mot de passe requis

**⚠️ Impact sécurité :**

* Démontre l'importance de la sécurité physique
* Nécessité de chiffrer les disques (BitLocker)
* Contrôle d'accès au Recovery Mode

***
