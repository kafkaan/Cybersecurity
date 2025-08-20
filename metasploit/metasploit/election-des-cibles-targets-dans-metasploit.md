# Election des Cibles (Targets) dans Metasploit

## <mark style="color:red;">**Définition des cibles (Targets)**</mark>

Les **cibles** sont des identifiants uniques de systèmes d'exploitation qui sont tirés des versions spécifiques de ces systèmes, adaptées aux modules d'exploitations sélectionnés. Chaque module d'exploit dans Metasploit peut être configuré pour attaquer une version particulière d'un système d'exploitation.

La commande `show targets` affichera toutes les cibles vulnérables disponibles pour un module d'exploit spécifique. Si cette commande est exécutée en dehors d'un module d'exploit, elle indiquera qu'il faut d'abord sélectionner un module.

<mark style="color:green;">**Exemple de la commande**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`show targets`**</mark>

1.  **Lorsque aucun module n'est sélectionné** :

    ```bash
    Copy codemsf6 > show targets
    [-] No exploit module selected.
    ```
2.  **Après avoir sélectionné un module (par exemple `ms17_010_psexec`)** :

    ```bash
    msf6 exploit(windows/smb/ms17_010_psexec) > options
    Name                  Current Setting   Required  Description
    ----                  ---------------   --------  -----------
    DBGTRACE              false             yes       Show extra debug trace info
    RHOSTS                10.10.10.40       yes       The target host(s)
    RPORT                 445               yes       The Target port (TCP)
    ```

**Sélection d'une cible**

Lorsque vous choisissez un module d'exploitation, vous devez choisir la cible qui correspond à la version et aux caractéristiques du système que vous attaquez. Par exemple, dans le cas du module `ms12_063`, qui exploite une vulnérabilité d'Internet Explorer, les cibles peuvent être sélectionnées en fonction de la version de **Windows** et **Internet Explorer**.

<mark style="color:green;">**Exemple : Module MS12-063**</mark>

Pour exploiter la vulnérabilité **MS12-063**, il y a plusieurs cibles en fonction des versions d'Internet Explorer et de Windows :

```bash
msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets
Exploit targets:
   Id  Name
   --  ----
   0   Automatic
   1   IE 7 on Windows XP SP3
   2   IE 8 on Windows XP SP3
   3   IE 7 on Windows Vista
   4   IE 8 on Windows Vista
   5   IE 8 on Windows 7
   6   IE 9 on Windows 7
```

**Changer de cible**

Une fois que vous avez sélectionné un module, vous pouvez choisir une cible spécifique avec la commande `set target`. Par exemple :

```bash
msf6 exploit(windows/browser/ie_execcommand_uaf) > set target 6
target => 6
```

Cela sélectionne **IE 9 sur Windows 7** comme cible pour l'attaque.

<mark style="color:green;">**Types de cibles**</mark>

Les cibles peuvent varier considérablement selon plusieurs critères :

* Le **service pack** de l'OS
* La **version du système d'exploitation**
* La **version du logiciel**
* La **version linguistique** (les adresses de retour peuvent changer avec la langue)

Cela signifie qu'une même version d'Internet Explorer sur deux systèmes Windows différents peut avoir des comportements différents lors de l'exploitation.

***

## <mark style="color:red;">**Adresse de retour (Return Address)**</mark>

Les adresses de retour sont cruciales pour l'exploitation. Elles peuvent varier selon :

* La version du logiciel
* Le pack de langue installé
* Les **hooks** (modifications du fonctionnement interne du système)

Les adresses de retour sont généralement définies comme `jmp esp` (un saut vers un registre spécifique) ou `pop/pop/ret`. L'identification correcte de ces adresses est nécessaire pour ajuster l'exploit à la cible.

**Étapes pour identifier correctement une cible**

1. Obtenez une copie des binaires de la cible.
2. Utilisez des outils comme **msfpescan** pour localiser une adresse de retour appropriée.
3. Si nécessaire, effectuez des tests sur l'OS cible pour vérifier la bonne configuration du module.

**Bonnes pratiques**

Avant de commencer à exploiter une cible, il est conseillé d'utiliser la commande `info` pour obtenir plus d'informations sur le module d'exploitation, son fonctionnement et ses dépendances. Cela permet de mieux comprendre les spécificités de chaque exploit et de sécuriser l'environnement.

#### Commandes principales :

* **show targets** : Affiche les cibles disponibles pour le module d'exploit sélectionné.
* **set target \<index>** : Sélectionne une cible spécifique dans la liste.
* **info** : Fournit des informations détaillées sur un module d'exploit.
