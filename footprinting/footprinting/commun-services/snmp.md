---
cover: ../../../.gitbook/assets/SNMP_versions.png
coverY: -61.81993259508908
---

# SNMP

## <mark style="color:red;">**Présentation générale**</mark>

**SNMP** est un protocole conçu pour la <mark style="color:orange;">**surveillance et la gestion des appareils réseaux tels que les routeurs, commutateurs, serveurs, et appareils IoT.**</mark> Il permet également de gérer à distance des configurations et de modifier les paramètres des équipements.

* La version actuelle est **SNMPv3**, qui améliore la sécurité par rapport aux versions précédentes mais rend également l’utilisation plus complexe.

***

## <mark style="color:red;">**Fonctionnement**</mark>

#### <mark style="color:green;">**Ports utilisés**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

* **UDP 161** : pour l’échange d’informations et l’envoi de commandes de contrôle.
* **UDP 162** : pour l’envoi de « traps », des notifications envoyées par le serveur SNMP vers le client en cas d’événements spécifiques.

***

## <mark style="color:red;">**Architecture SNMP**</mark>

* **Client SNMP** : l'entité qui envoie des requêtes pour obtenir des informations ou envoyer des commandes.
* **Agent SNMP** : un logiciel qui fonctionne sur l’appareil réseau et qui répond aux requêtes du client en fournissant les informations demandées ou en exécutant les commandes.
* **MIB (Management Information Base)** : une base de données virtuelle contenant une collection hiérarchique d'objets SNMP. Chaque objet a un **OID (Object Identifier)** unique.

{% hint style="warning" %}
Pour garantir que l'accès SNMP fonctionne entre différents fabricants et avec diverses combinaisons client-serveur, la **Base d'Informations de Gestion (MIB - Management Information Base)** a été créée.

✅ **La MIB est un format indépendant** utilisé pour stocker des informations sur les appareils.\
✅ Il s'agit d'un **fichier texte** dans lequel **tous les objets SNMP interrogeables** d'un appareil sont répertoriés sous forme de hiérarchie standardisée en arbre.

📌 **Contenu d'une MIB**

Une MIB contient **au moins un** **Identifiant d'Objet (OID - Object Identifier)**, qui fournit :\
🔹 Une **adresse unique** et un **nom** pour chaque objet\
🔹 Des informations sur **le type de donnée**, **les droits d'accès** et une **description** de l'objet

📄 **Format des fichiers MIB**

* Écrits en **ASCII** sous une syntaxe normalisée appelée **ASN.1 (Abstract Syntax Notation One)**.
* Ils ne contiennent **pas les données elles-mêmes**, mais décrivent :
  * Où trouver certaines informations
  * À quoi ressemblent ces données
  * Quelles valeurs sont renvoyées pour un OID spécifique
  * Quel type de données est utilisé

🚀 En résumé : La **MIB** sert de **répertoire structuré** qui explique comment récupérer des informations SNMP depuis un appareil, peu importe le fabricant.
{% endhint %}

***

## <mark style="color:red;">**Versions SNMP**</mark>

1. <mark style="color:orange;">**SNMPv1**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark>
   * Version initiale.
   * Manque de mécanismes de sécurité : aucune authentification et absence de chiffrement, les données sont transmises en clair.
2. <mark style="color:orange;">**SNMPv2c**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark>
   * Version communautaire basée sur SNMPv2.
   * Ajout de nouvelles fonctionnalités mais toujours pas de chiffrement.
3. <mark style="color:orange;">**SNMPv3**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark>
   * **Sécurité renforcée** avec authentification (par nom d'utilisateur et mot de passe) et chiffrement des transmissions.
   * Complexité accrue due aux nombreuses options de configuration.

***

## <mark style="color:red;">**Concepts clés**</mark>

* <mark style="color:green;">**OID (Object Identifier)**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * Représente un nœud dans un espace de noms hiérarchique.
  * Chaque OID est une séquence de nombres qui identifie de manière unique chaque objet géré par SNMP.
* <mark style="color:green;">**Community Strings**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * Fonctionnent comme des mots de passe déterminant l’accès aux informations SNMP.
  * Le manque de chiffrement de SNMPv2 rend ces chaînes vulnérables.

{% hint style="warning" %}
Community strings can be seen as passwords that are used to determine whether the requested information can be viewed or not. It is important to note that many organizations are still using `SNMPv2`, as the transition to `SNMPv3` can be very complex, but the services still need to remain active. This causes many administrators a great deal of concern and creates some problems they are keen to avoid. The lack of knowledge about how the information can be obtained and how we as attackers use it makes the administrators' approach seem inexplicable. At the same time, the lack of encryption of the data sent is also a problem. Because every time the community strings are sent over the network, they can be intercepted and read.&#x20;
{% endhint %}

#### <mark style="color:green;">**Configuration**</mark>

*   **Fichier de configuration SNMP Daemon (snmpd.conf)** :

    * Définit les paramètres de base pour le service SNMP, y compris les adresses IP, les ports, les MIBs, les OIDs, l'authentification, et les community strings.
    * Il est possible de personnaliser ces paramètres en fonction des besoins spécifiques.

    ```shell-session
    cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
    ```

#### <mark style="color:green;">**Risques et Dangers**</mark>

* **Paramètres dangereux**&#x20;

| **Settings**                                     | **Description**                                                                       |
| ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `rwuser noauth`                                  | Provides access to the full OID tree without authentication.                          |
| `rwcommunity <community string> <IPv4 address>`  | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6.                  |

***

## <mark style="color:red;">**Footprinting SNMP**</mark>

Le **footprinting** (cartographie) du SNMP est une technique utilisée pour identifier et interroger les services SNMP d'un système. Le SNMP (Simple Network Management Protocol) est un protocole utilisé pour la gestion des réseaux. Il existe plusieurs outils pour réaliser le footprinting SNMP, dont **snmpwalk**, **onesixtyone**, et **braa**.

<mark style="color:green;">**Outils pour le Footprinting SNMP**</mark>

<mark style="color:green;">**1. Snmpwalk**</mark>

* **Fonctionnalité** : `snmpwalk` permet d'interroger les OID (Object Identifiers) pour obtenir des informations détaillées sur le système.
*   **Exemple d'utilisation** :

    ```bash
    mrroboteLiot@htb[/htb]$ snmpwalk -v2c -c public 10.129.14.128
    ```

    * **Résultat** :
      * Les informations retournées incluent des détails sur le système, tels que la version du noyau Linux, le nom d'hôte, et d'autres configurations système.
      *   **Exemples de retour** :

          ```plaintext
          iso.3.6.1.2.1.1.1.0 = STRING: "Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64"
          iso.3.6.1.2.1.1.4.0 = STRING: "mrb3n@inlanefreight.htb"
          iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
          iso.3.6.1.2.1.25.6.3.1.2.1243 = STRING: "python3_3.8.2-0ubuntu2_amd64"
          ```

<mark style="color:green;">**2. Onesixtyone**</mark>

* **Fonctionnalité** : `onesixtyone` est utilisé pour réaliser une attaque par force brute sur les noms des chaînes de communauté SNMP.
*   **Exemple d'utilisation** :

    {% code overflow="wrap" %}
    ```bash
    mrroboteLiot@htb[/htb]$ onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
    ```
    {% endcode %}

    * **Résultat** :
      * Cet outil tente de deviner la chaîne de communauté en utilisant des listes de mots (wordlists). Si une chaîne valide est trouvée, des informations sur le système seront affichées.
      *   **Exemple de retour** :

          {% code overflow="wrap" %}
          ```plaintext
          10.129.14.128 [public] Linux htb 5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021 x86_64
          ```
          {% endcode %}

<mark style="color:green;">**3. Braa**</mark>

* **Fonctionnalité** : `braa` est utilisé pour réaliser une attaque en force brute sur les OID individuels afin d'énumérer les informations associées.
*   **Exemple d'utilisation** :

    ```bash
    mrroboteLiot@htb[/htb]$ braa public@10.129.14.128:.1.3.6.*
    ```

    * **Résultat** :
      * L'outil retourne des informations sur le système en utilisant la chaîne de communauté trouvée.
      *   **Exemple de retour** :

          {% code overflow="wrap" %}
          ```plaintext
          10.129.14.128:20ms:.1.3.6.1.2.1.1.1.0:Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64
          ```
          {% endcode %}
