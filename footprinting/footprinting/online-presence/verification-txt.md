# Verification TXT

Les enregistrements TXT (Text) sont un <mark style="color:orange;">**type de ressource DNS qui permet aux administrateurs de stocker des informations textuelles dans le système de noms de domaine (DNS)**</mark>. Ces enregistrements sont souvent utilisés pour diverses fonctions de sécurité et de vérification, notamment les mécanismes de sécurité des emails tels que <mark style="color:orange;">**SPF, DKIM, et DMARC**</mark>. Voyons en détail comment chacun de ces mécanismes fonctionne et leur rôle dans la vérification des emails.

***

## <mark style="color:red;">Enregistrements TXT et Mécanismes de Sécurité des Emails</mark>

***

#### <mark style="color:green;">**1. SPF (Sender Policy Framework)**</mark>

* **Objectif** : L'enregistrement SPF est utilisé pour <mark style="color:orange;">**spécifier les adresses IP autorisées à envoyer des email**</mark> au nom de votre domaine.
* **Fonctionnement** : Lorsqu'un serveur de réception reçoit un email, il vérifie l'adresse IP de l'expéditeur contre l'enregistrement SPF du domaine de l'expéditeur. Si l'IP est autorisée, le mail passe cette vérification.
*   **Exemple d'enregistrement SPF** :

    ```makefile
    v=spf1 include:_spf.google.com ~all
    ```

    * `v=spf1` : Indique la version SPF.
    * `include:_spf.google.com` : Autorise les serveurs de Google à envoyer des emails pour ce domaine.
    * `~all` : Permet à tous les autres serveurs d'envoyer des emails, mais les marque comme soft fail.

#### <mark style="color:green;">**2. DKIM (DomainKeys Identified Mail)**</mark>

* **Objectif** : DKIM ajoute une signature numérique aux en-têtes des emails, permettant aux destinataires de vérifier que les emails n'ont pas été altérés et proviennent bien du domaine déclaré.
* **Fonctionnement** : Lorsqu'un email est envoyé, le serveur de l'expéditeur signe l'email avec une clé privée. Le destinataire peut vérifier cette signature en utilisant la clé publique stockée dans un enregistrement TXT du DNS.
*   **Exemple d'enregistrement DKIM** :

    ```arduino
    google._domainkey.example.com IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD...QAB"
    ```

    * `google._domainkey` : Sélecteur DKIM spécifique.
    * `v=DKIM1` : Version DKIM.
    * `k=rsa` : Type de cryptographie.
    * `p=MIGfMA0GCSq...QAB` : Clé publique.

#### <mark style="color:green;">**3. DMARC (Domain-based Message Authentication, Reporting, and Conformance)**</mark>

* **Objectif** : DMARC permet aux propriétaires de domaine de publier une politique sur la manière de gérer les emails qui échouent aux vérifications SPF et DKIM. Il fournit également des rapports sur l'activité des emails.
* **Fonctionnement** : Les serveurs de réception vérifient si l'email passe les contrôles SPF et DKIM. Si l'email échoue, le serveur applique la politique DMARC (par exemple, rejeter ou mettre en quarantaine le mail).
*   **Exemple d'enregistrement DMARC** :

    {% code overflow="wrap" fullWidth="true" %}
    ```perl
    _dmarc.example.com IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-failures@example.com"
    ```
    {% endcode %}

    * `v=DMARC1` : Version DMARC.
    * `p=reject` : Politique de rejet des emails qui échouent aux vérifications.
    * `rua` : Adresse email pour les rapports agrégés.
    * `ruf` : Adresse email pour les rapports d'échec.

***
