---
description: >-
  Fingerprinting focuses on extracting technical details about the technologies
  powering a website or web application.
cover: ../../.gitbook/assets/finge.jpg
coverY: 0
---

# Fingerprinting

## <mark style="color:red;">**Introduction**</mark>

{% hint style="warning" %}
Le fingerprinting (ou identification) est une technique essentielle de reconnaissance web permettant de découvrir des informations critiques sur les infrastructures cibles, notamment les serveurs web, les systèmes d'exploitation et les composants logiciels. Cette connaissance permet aux attaquants d'adapter leurs attaques et d'exploiter les vulnérabilités spécifiques aux technologies identifiées.
{% endhint %}

***

## <mark style="color:red;">**Importance du Fingerprinting**</mark>

1. **Attaques Ciblées** : Identifier les technologies spécifiques en usage permet aux attaquants de se concentrer sur les vulnérabilités connues de ces systèmes, augmentant ainsi les chances de compromis réussi.
2. **Identification des Mauvaises Configurations** : Le fingerprinting peut révéler des logiciels mal configurés ou obsolètes, des paramètres par défaut ou d'autres faiblesses non apparentes via d'autres méthodes de reconnaissance.
3. **Priorisation des Cibles** : Lorsque plusieurs cibles potentielles sont présentes, le fingerprinting aide à prioriser les efforts en identifiant les systèmes les plus vulnérables ou les plus précieux.
4. **Construction d'un Profil Complet** : En combinant les données de fingerprinting avec d'autres résultats de reconnaissance, on obtient une vue holistique de l'infrastructure de la cible, facilitant la compréhension de sa posture de sécurité globale et des vecteurs d'attaque potentiels.

***

## <mark style="color:red;">**Techniques de Fingerprinting**</mark>

1. **Banner Grabbing** : Analyse des bannières présentées par les serveurs web et autres services, révélant souvent les logiciels de serveur, les numéros de version, etc.
2. **Analyse des En-têtes HTTP** : Les en-têtes HTTP contiennent des informations précieuses. L'en-tête "Server" indique souvent le logiciel de serveur web, tandis que "X-Powered-By" peut révéler des technologies supplémentaires comme des langages de script ou des frameworks.
3. **Probing pour Réponses Spécifiques** : En envoyant des requêtes spécialement conçues, on peut obtenir des réponses uniques révélant des technologies ou versions spécifiques (ex. messages d'erreur spécifiques à certains serveurs).
4. **Analyse du Contenu des Pages** : La structure, les scripts et autres éléments des pages web peuvent fournir des indices sur les technologies sous-jacentes (ex. en-têtes de copyright indiquant des logiciels spécifiques).

***

## <mark style="color:red;">**Outils de Fingerprinting**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Outil</strong></td><td><strong>Description</strong></td><td><strong>Fonctionnalités</strong></td></tr><tr><td><strong>Wappalyzer</strong></td><td>Extension de navigateur et service en ligne pour profiler les technologies des sites web.</td><td>Identifie une large gamme de technologies web, y compris CMS, frameworks, outils d'analyse, etc.</td></tr><tr><td><strong>BuiltWith</strong></td><td>Profiler technologique des sites web fournissant des rapports détaillés.</td><td>Offre des plans gratuits et payants avec différents niveaux de détail.</td></tr><tr><td><strong>WhatWeb</strong></td><td>Outil en ligne de commande pour le fingerprinting des sites web.</td><td>Utilise une vaste base de données de signatures pour identifier diverses technologies web.</td></tr><tr><td><strong>Nmap</strong></td><td>Scanner de réseau polyvalent pouvant être utilisé pour diverses tâches de reconnaissance, y compris le fingerprinting des services et des OS.</td><td>Peut être utilisé avec des scripts (NSE) pour un fingerprinting plus spécialisé.</td></tr><tr><td><strong>Netcraft</strong></td><td>Offre une gamme de services de sécurité web, y compris le fingerprinting des sites web et les rapports de sécurité.</td><td>Fournit des rapports détaillés sur la technologie, le fournisseur d'hébergement et la posture de sécurité d'un site web.</td></tr><tr><td><strong>wafw00f</strong></td><td>Outil en ligne de commande spécialement conçu pour identifier les pare-feux applicatifs web (WAF).</td><td>Aide à déterminer si un WAF est présent et, le cas échéant, son type et sa configuration.</td></tr></tbody></table>

<mark style="color:green;">**Cas Pratique : inlanefreight.com**</mark>

1.  **Commande :**

    ```sh
    curl -I inlanefreight.com
    ```

    **Résultat :**

    ```sh
    HTTP/1.1 301 Moved Permanently
    Date: Fri, 31 May 2024 12:07:44 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Location: https://inlanefreight.com/
    Content-Type: text/html; charset=iso-8859-1
    ```

    Révélation : Serveur Apache/2.4.41 sur Ubuntu.
2.  **Commande pour HTTPS :**

    ```sh
    curl -I https://inlanefreight.com
    ```

    **Résultat :**

    ```sh
    HTTP/1.1 301 Moved Permanently
    Date: Fri, 31 May 2024 12:12:12 GMT
    Server: Apache/2.4.41 (Ubuntu)
    X-Redirect-By: WordPress
    Location: https://www.inlanefreight.com/
    Content-Type: text/html; charset=UTF-8
    ```

    Révélation : Utilisation de WordPress pour la redirection.

***

## <mark style="color:red;">**Détection de**</mark> <mark style="color:red;"></mark><mark style="color:red;">WAF</mark> <mark style="color:red;"></mark><mark style="color:red;">**avec wafw00f**</mark>&#x20;

`Web Application Firewalls` (`WAFs`) are security solutions designed to protect web applications from various attacks.

1.  <mark style="color:green;">**Commande :**</mark>

    ```sh
    wafw00f inlanefreight.com
    ```

    **Résultat :**

    {% code title="WAF" overflow="wrap" %}
    ```sh
    [+] The site https://inlanefreight.com is behind Wordfence (Defiant) WAF.
    ```
    {% endcode %}

    Révélation : Présence de Wordfence WAF.

***

## <mark style="color:red;">**Scan avec Nikto :**</mark>

1.  <mark style="color:green;">**Installation et Commandes :**</mark>

    ```sh
    sudo apt update && sudo apt install -y perl
    git clone https://github.com/sullo/nikto
    cd nikto/program
    chmod +x ./nikto.pl
    nikto -h inlanefreight.com -Tuning b
    ```

    The `-h` flag specifies the target host. The `-Tuning b` flag tells `Nikto` to only run the Software Identification modules.
2.  <mark style="color:green;">**Résultat :**</mark>

    {% code overflow="wrap" %}
    ```sh
    + Server: Apache/2.4.41 (Ubuntu)
    + /: The site uses TLS and the Strict-Transport-Security HTTP header is not defined.
    + /: A Wordpress installation was found.
    ```
    {% endcode %}

    Révélation : Diverses informations sur le serveur et la configuration de sécurité.
