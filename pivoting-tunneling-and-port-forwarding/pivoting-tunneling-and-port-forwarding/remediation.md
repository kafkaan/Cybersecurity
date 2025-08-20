# REMEDIATION

**Détection et Prévention**

Tout au long de ce module, nous avons maîtrisé plusieurs techniques utilisables dans une perspective offensive. En tant que testeurs d'intrusion, nous devons également nous préoccuper des méthodes de mitigation et de détection permettant aux défenseurs de stopper ces types de TTP (Tactiques, Techniques et Procédures). Ceci est crucial car nous devons fournir à nos clients des solutions potentielles aux problèmes que nous découvrons et exploitons lors de nos évaluations. Certaines de ces solutions incluent :

* Changements matériels
* Modifications de l'infrastructure réseau
* Ajustements des configurations des hôtes

Cette section couvrira ces solutions et leur impact sur la défense du réseau.

***

### **Définition d'une ligne de base**

Comprendre ce qui se passe sur un réseau est essentiel. En tant que défenseurs, nous devons pouvoir identifier et analyser rapidement :

* Tout nouvel hôte apparaissant sur le réseau
* Tout nouvel outil ou application installé en dehors du catalogue autorisé
* Tout nouveau trafic réseau inhabituel

Un audit annuel, voire trimestriel, des éléments suivants est recommandé :

* Enregistrements DNS, sauvegardes des dispositifs réseau et configurations DHCP
* Inventaire complet des applications
* Liste des hôtes de l'entreprise et leur emplacement
* Liste des utilisateurs ayant des privilèges élevés
* Liste des hôtes ayant plusieurs interfaces réseau
* Schéma visuel du réseau

Des outils comme **Netbrain** permettent de créer un schéma interactif du réseau. Un outil gratuit comme **diagrams.net** peut aussi être utile pour documenter visuellement l'environnement.

***

### **Personnes, Processus et Technologies**

Le renforcement de la sécurité réseau se divise en trois catégories : **les personnes, les processus et la technologie**.

#### **1. Les Personnes**

Les utilisateurs sont souvent le maillon faible. Il est crucial de leur inculquer les bonnes pratiques de sécurité.

**BYOD et autres problèmes**

L'utilisation d'appareils personnels (BYOD) augmente le risque pour l'organisation. Exemple :

> _Nick, un gestionnaire logistique, utilise son ordinateur personnel pour travailler à domicile. Malheureusement, il télécharge illégalement des jeux, et son PC est infecté par un malware. En se connectant au WiFi de l'entreprise, l'attaquant obtient un accès au réseau interne._

**Solution** :

* Mise en place d'une **authentification multi-facteurs (MFA)**
* Restreindre l'accès des appareils personnels au réseau de l'entreprise
* Surveillance continue des activités suspectes avec un SOC (Security Operations Center)

#### **2. Processus**

Les politiques et procédures écrites sont indispensables :

* **Surveillance et gestion des actifs** : audits, étiquetage et inventaires réguliers
* **Contrôle d'accès** : provisioning/déprovisioning des comptes
* **Processus de déploiement et retrait des hôtes** : durcissement des configurations
* **Gestion des changements** : journalisation des modifications apportées au système

#### **3. Technologie**

Une veille constante est nécessaire pour :

* Détecter les **erreurs de configuration**
* Identifier les **nouvelles vulnérabilités**
* S'assurer que l'environnement évolue sans introduire de failles

***

### **De l'Extérieur vers l'Intérieur**

#### **Protection du Périmètre**

Questions à se poser :

* Quelles sont les ressources les plus précieuses à protéger ?
* Quels services sont accessibles depuis l'extérieur ?
* Comment détecter et prévenir une attaque en cours ?
* Qui est responsable de la surveillance des alertes de sécurité ?
* Dispose-t-on d'un plan de récupération après sinistre ?

Outils recommandés :

* Pare-feu nouvelle génération
* VPNs pour restreindre les accès distants
* Détection et réponse aux intrusions (IDS/IPS)

#### **Considérations internes**

Points clés :

* Les serveurs exposés à Internet sont-ils correctement sécurisés (DMZ) ?
* La segmentation réseau est-elle en place ?
* Qui a accès à l'infrastructure administrative ?
* Comment analysons-nous les journaux d'activités et les événements suspects ?

Un **SIEM** bien configuré permet de centraliser les journaux et détecter les anomalies avant qu'elles ne se transforment en incidents graves.

***

### **MITRE ATT\&CK et contre-mesures**

#### **Exemples de techniques et de prévention**

<table data-full-width="true"><thead><tr><th>TTP</th><th>MITRE Tag</th><th>Méthode de détection/prévention</th></tr></thead><tbody><tr><td><strong>Services distants</strong></td><td>T1021</td><td>MFA, restriction des accès, pare-feu</td></tr><tr><td><strong>Ports non standards</strong></td><td>T1571</td><td>IDS/IPS, contrôle des flux réseau</td></tr><tr><td><strong>Tunneling de protocole</strong></td><td>T1572</td><td>Filtrage DNS, analyse des schémas de communication</td></tr><tr><td><strong>Utilisation de proxy</strong></td><td>T1090</td><td>Surveillance du trafic sortant, liste d'adresses IP autorisées</td></tr><tr><td><strong>LOTL (Living Off The Land)</strong></td><td>N/A</td><td>Surveillance comportementale, solutions EDR</td></tr></tbody></table>

***

### **Conclusion**

Une bonne défense repose sur trois piliers :

1. **Les utilisateurs** doivent être formés et conscients des risques
2. **Les processus** doivent être clairement définis et appliqués
3. **Les technologies** doivent être bien configurées et surveillées

La visibilité et la réactivité sont essentielles pour détecter et empêcher les attaques avant qu'elles ne causent des dommages significatifs.
