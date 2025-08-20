# Automatiser la Reconnaissance

***

**Définition :** Automatiser les tâches de reconnaissance web permet d'améliorer l'efficacité et la précision, permettant de recueillir des informations à grande échelle et d'identifier rapidement les vulnérabilités potentielles.

***

## <mark style="color:red;">**Pourquoi Automatiser la Reconnaissance ?**</mark>

1. **Efficacité :** Les outils automatisés effectuent des tâches répétitives beaucoup plus rapidement que les humains, libérant du temps précieux pour l'analyse et la prise de décision.
2. **Évolutivité :** L'automatisation permet d'étendre les efforts de reconnaissance à un grand nombre de cibles ou de domaines, découvrant ainsi un éventail plus large d'informations.
3. **Consistance :** Les outils automatisés suivent des règles et des procédures prédéfinies, garantissant des résultats cohérents et reproductibles et minimisant le risque d'erreur humaine.
4. **Couverture Complète :** L'automatisation peut être programmée pour effectuer une large gamme de tâches de reconnaissance, y compris l'énumération DNS, la découverte de sous-domaines, le crawling web, le scan de ports, et plus encore.
5. **Intégration :** De nombreux frameworks d'automatisation permettent une intégration facile avec d'autres outils et plateformes, créant un flux de travail homogène allant de la reconnaissance à l'évaluation des vulnérabilités et à l'exploitation.

***

## <mark style="color:red;">**Frameworks de Reconnaissance**</mark>

Ces frameworks fournissent une suite complète d'outils pour la reconnaissance web :

1. **FinalRecon :**
   * Outil de reconnaissance basé sur Python offrant une gamme de modules pour différentes tâches comme la vérification des certificats SSL, la collecte d'informations Whois, l'analyse des en-têtes et le crawling.
   * Structure modulaire permettant une personnalisation facile selon les besoins spécifiques.
2. **Recon-ng :**
   * Framework puissant écrit en Python offrant une structure modulaire avec divers modules pour différentes tâches de reconnaissance.
   * Peut effectuer l'énumération DNS, la découverte de sous-domaines, le scan de ports, le crawling web, et même exploiter les vulnérabilités connues.
3. **theHarvester :**
   * Conçu spécifiquement pour la collecte d'adresses email, de sous-domaines, d'hôtes, de noms d'employés, de ports ouverts, et de bannières à partir de différentes sources publiques comme les moteurs de recherche, les serveurs de clés PGP et la base de données SHODAN.
   * Outil en ligne de commande écrit en Python.
4. **SpiderFoot :**
   * Outil d'automatisation de l'intelligence open-source qui intègre diverses sources de données pour collecter des informations sur une cible, y compris les adresses IP, les noms de domaine, les adresses email et les profils de réseaux sociaux.
   * Peut effectuer des recherches DNS, le crawling web, le scan de ports, et plus encore.
5. **OSINT Framework :**
   * Collection de divers outils et ressources pour la collecte d'intelligence open-source.
   * Couvre une large gamme de sources d'informations, y compris les réseaux sociaux, les moteurs de recherche, les registres publics, et plus encore.

***

## <mark style="color:red;">**Détails de FinalRecon**</mark>

**FinalRecon** offre une mine d'informations de reconnaissance :

1. **Informations sur les En-têtes :** Révèle les détails du serveur, les technologies utilisées et les potentielles mauvaises configurations de sécurité.
2. **Whois Lookup :** Découvre les détails de l'enregistrement de domaine, y compris les informations sur le registrant et les coordonnées.
3. **Informations sur le Certificat SSL :** Examine le certificat SSL/TLS pour sa validité, l'émetteur, et d'autres détails pertinents.
4. **Crawler :**
   * Extrait des liens, des ressources, et des vulnérabilités potentielles à partir des fichiers HTML, CSS, et JavaScript.
   * Cartographie la structure du site web et identifie les connexions à d'autres domaines.
   * Rassemble des informations sur les images, le fichier robots.txt, et le sitemap.xml.
   * Découvre des liens cachés et des données historiques du site web via la Wayback Machine.
5. **Énumération DNS :** Interroge plus de 40 types d'enregistrements DNS, y compris les enregistrements DMARC pour l'évaluation de la sécurité des emails.
6. **Énumération de Sous-domaines :** Utilise plusieurs sources de données pour découvrir les sous-domaines.
7. **Énumération des Répertoires :** Prend en charge les listes de mots et les extensions de fichiers personnalisées pour découvrir les répertoires et fichiers cachés.
8. **Wayback Machine :** Récupère les URLs des cinq dernières années pour analyser les changements du site web et les vulnérabilités potentielles.

***

**Installation de FinalRecon**

**Étapes d'installation :**

1.  **Cloner le dépôt GitHub :**

    ```bash
    git clone https://github.com/thewhiteh4t/FinalRecon.git
    ```
2.  **Naviguer dans le répertoire créé :**

    ```bash
    cd FinalRecon
    ```
3.  **Installer les dépendances nécessaires :**

    ```bash
    pip3 install -r requirements.txt
    ```
4.  **Rendre le script principal exécutable :**

    ```bash
    chmod +x ./finalrecon.py
    ```
5.  **Vérifier l'installation et afficher les options disponibles :**

    ```bash
    ./finalrecon.py --help
    ```

***

## <mark style="color:red;">**Utilisation de FinalRecon**</mark>

**Exemple de commande pour recueillir des informations sur les en-têtes et effectuer une recherche Whois :**

```bash
/finalrecon.py --headers --whois --url http://inlanefreight.com
```

**Options disponibles :**

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Option</strong></td><td><strong>Argument</strong></td><td><strong>Description</strong></td></tr><tr><td>-h, --help</td><td></td><td>Afficher le message d'aide et quitter.</td></tr><tr><td>--url</td><td>URL</td><td>Spécifier l'URL cible.</td></tr><tr><td>--headers</td><td></td><td>Récupérer les informations sur les en-têtes pour l'URL cible.</td></tr><tr><td>--sslinfo</td><td></td><td>Obtenir les informations sur le certificat SSL pour l'URL cible.</td></tr><tr><td>--whois</td><td></td><td>Effectuer une recherche Whois pour le domaine cible.</td></tr><tr><td>--crawl</td><td></td><td>Crawler le site web cible.</td></tr><tr><td>--dns</td><td></td><td>Effectuer une énumération DNS sur le domaine cible.</td></tr><tr><td>--sub</td><td></td><td>Énumérer les sous-domaines pour le domaine cible.</td></tr><tr><td>--dir</td><td></td><td>Rechercher des répertoires sur le site web cible.</td></tr><tr><td>--wayback</td><td></td><td>Récupérer les URLs Wayback pour la cible.</td></tr><tr><td>--ps</td><td></td><td>Effectuer un scan de ports rapide sur la cible.</td></tr><tr><td>--full</td><td></td><td>Effectuer une analyse de reconnaissance complète sur la cible.</td></tr></tbody></table>

**Options supplémentaires :**

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Option</strong></td><td><strong>Description</strong></td></tr><tr><td>-nb</td><td>Masquer la bannière</td></tr><tr><td>-dt DT</td><td>Nombre de threads pour l'énumération des répertoires [Par défaut : 30]</td></tr><tr><td>-pt PT</td><td>Nombre de threads pour le scan de ports [Par défaut : 50]</td></tr><tr><td>-T T</td><td>Délai d'expiration des requêtes [Par défaut : 30.0]</td></tr><tr><td>-w W</td><td>Chemin vers la liste de mots [Par défaut : wordlists/dirb_common.txt]</td></tr><tr><td>-r</td><td>Autoriser les redirections [Par défaut : False]</td></tr><tr><td>-s</td><td>Activer/désactiver la vérification SSL [Par défaut : True]</td></tr><tr><td>-sp SP</td><td>Spécifier le port SSL [Par défaut : 443]</td></tr><tr><td>-d D</td><td>Serveurs DNS personnalisés [Par défaut : 1.1.1.1]</td></tr><tr><td>-e E</td><td>Extensions de fichiers [Exemple : txt, xml, php]</td></tr><tr><td>-o O</td><td>Format d'exportation [Par défaut : txt]</td></tr><tr><td>-cd CD</td><td>Changer le répertoire d'exportation [Par défaut : ~/.local/share/finalrecon]</td></tr><tr><td>-k K</td><td>Ajouter une clé API [Exemple : shodan@key]</td></tr></tbody></table>
