---
description: https://faresbltagy.gitbook.io/footprintinglabs/footprinting-labs/lab-hard
cover: ../../.gitbook/assets/foot.jpg
coverY: 96.23430962343096
layout:
  width: default
  cover:
    visible: true
    size: full
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# Footprinting

## <mark style="color:red;">**Introduction**</mark>

La méthodologie d'énumération est une <mark style="color:orange;">**approche structurée utilisée par les testeurs de pénétration pour explorer et comprendre un système cible**</mark>.&#x20;

Elle est divisée en plusieurs couches, chacune représentant un <mark style="color:orange;">**niveau spécifique d'information à découvrir**</mark>.&#x20;

<table data-header-hidden data-full-width="true"><thead><tr><th width="324"></th><th width="353"></th><th></th></tr></thead><tbody><tr><td><code>Infrastructure-based enumeration</code></td><td><code>Host-based enumeration</code></td><td><code>OS-based enumeration</code></td></tr></tbody></table>

<figure><img src="../../.gitbook/assets/image (90).png" alt=""><figcaption><p>COUCHES</p></figcaption></figure>

***

### <mark style="color:blue;">Les Couches d'Énumération</mark>

1. <mark style="color:orange;">**Couche 1 : Présence Internet**</mark>
   * **Objectif :** Identifier la présence en ligne de l'entreprise.
   * **Ce que vous recherchez :** _<mark style="color:green;">**Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures**</mark>_
   * **Exemple :** Trouver `www.example.com`, `mail.example.com`, etc.
   * **Outils :** WHOIS, DNS enumeration tools, outils OSINT.
2. <mark style="color:orange;">**Couche 2 : Passerelle**</mark>
   * **Objectif :** Comprendre les mesures de sécurité mises en place pour protéger l'infrastructure.
   * **Ce que vous recherchez :** _<mark style="color:green;">**Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare**</mark>_
   * **Exemple :** Découvrir que l'accès à un sous-domaine est protégé par un VPN.
   * **Outils :** Scanners de ports, analyseurs de paquets, outils de sécurité réseau.
3. <mark style="color:orange;">**Couche 3 : Services Accessibles**</mark>
   * **Objectif :** Identifier les services et interfaces accessibles.
   * **Ce que vous recherchez :&#x20;**_<mark style="color:green;">**Service Type, Functionality, Configuration, Port, Version, Interface**</mark>_
   * **Exemple :** Trouver un serveur web sur le port 80 avec une version obsolète.
   * **Outils :** Nmap, Netcat, scanners de vulnérabilités.
4. <mark style="color:orange;">**Couche 4 : Processus**</mark>
   * **Objectif :** Identifier les processus internes et les interactions.
   * **Ce que vous recherchez :&#x20;**_<mark style="color:green;">**PID, Processed Data, Tasks, Source, Destination**</mark>_
   * **Exemple :** Analyser les tâches exécutées sur un serveur.
   * **Outils :** Outils de monitoring de processus, analyse de logs.
5. <mark style="color:orange;">**Couche 5 : Privilèges**</mark>
   * **Objectif :** Identifier les permissions et privilèges des utilisateurs.
   * **Ce que vous recherchez :** _<mark style="color:orange;">**Groups, Users, Permissions, Restrictions, Environment**</mark>_
   * **Exemple :** Trouver un utilisateur avec des privilèges administratifs excessifs.
   * **Outils :** Outils d'audit de privilèges, scripts de gestion des utilisateurs.
6. <mark style="color:orange;">**Couche 6 : Configuration du Système d'Exploitation**</mark>
   * **Objectif :** Collecter des informations sur le système d'exploitation et sa configuration.
   * **Ce que vous recherchez :** _<mark style="color:orange;">**Type de système d'exploitation, niveau de patch, fichiers de configuration.**</mark>_
   * **Exemple :** Découvrir que le système d'exploitation n'est pas à jour.
   * **Outils :** Scripts d'audit de configuration, outils de gestion de patchs.

***

### <mark style="color:blue;">**Exemple Pratique**</mark>

1. **Couche 1 : Présence Internet**
   * **Découverte :** Vous trouvez `dev.example.com` qui héberge une application web.
2. **Couche 3 : Services Accessibles**
   * **Découverte :** Vous trouvez une vulnérabilité d'injection SQL dans le formulaire de connexion.
   * **Exploitation :** Vous utilisez l'injection SQL pour accéder à l'application et trouvez des adresses e-mail internes.
3. **Retour à la Couche 1 : Présence Internet**
   * **Utilisation des informations :** Vous utilisez les adresses e-mail pour effectuer des recherches OSINT et trouvez de nouvelles cibles, comme `intranet.example.com`.
4. **Couche 2 : Passerelle**
   * **Découverte :** Vous découvrez que `intranet.example.com` est protégé par un VPN.
   * **Exploitation :** Vous tentez une connexion VPN avec des identifiants par défaut.
5. **Couche 3 : Services Accessibles (Interne)**
   * **Découverte :** Vous trouvez un serveur de fichiers interne mal sécurisé.
   * **Exploitation :** Vous accédez à des documents internes sensibles.
