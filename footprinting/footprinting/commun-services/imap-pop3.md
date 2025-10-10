---
description: https://www.mailenable.com/kb/content/article.asp?ID=ME020711
cover: ../../../.gitbook/assets/pop-imap2.png
coverY: 107.33333333333333
layout:
  width: default
  cover:
    visible: true
    size: hero
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

# IMAP / POP3

## <mark style="color:red;">**1. Introduction**</mark>

* <mark style="color:orange;">**IMAP (Internet Message Access Protocol)**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark> Permet l'accès et la gestion des e-mails directement sur le serveur. Il offre des fonctionnalités étendues pour la gestion des courriels en ligne, y compris la possibilité de gérer des structures de dossiers et de synchroniser les e-mails entre plusieurs clients.
* <mark style="color:orange;">**POP3 (Post Office Protocol)**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark> Permet de récupérer les e-mails du serveur vers un client local. Moins sophistiqué qu'IMAP, il gère uniquement le téléchargement et la suppression des e-mails sans support pour la gestion avancée des dossiers.

***

## <mark style="color:red;">**2. Fonctionnalités**</mark>

* <mark style="color:green;">**IMAP :**</mark>
  * **Gestion en ligne** : Les e-mails restent sur le serveur, permettant une gestion centralisée et une synchronisation entre différents clients.
  * **Structures de dossiers** : Supporte la création et la gestion de dossiers sur le serveur.
  * **Synchronisation** : Permet la synchronisation des e-mails et des dossiers entre plusieurs clients (par exemple, webmail et clients de messagerie locaux).
  * **Mode hors ligne** : Certains clients peuvent offrir un mode hors ligne en téléchargeant une copie locale des e-mails, avec synchronisation ultérieure des modifications.
  * **Sécurité** : Fonctionne souvent avec SSL/TLS pour sécuriser les communications. Utilise les ports 143 (non sécurisé ou avec STARTTLS) et 993 (sécurisé par SSL/TLS).
* <mark style="color:green;">**POP3 :**</mark>
  * **Téléchargement des e-mails** : Les e-mails sont généralement téléchargés du serveur vers le client et supprimés du serveur.
  * **Pas de gestion des dossiers** : Ne supporte pas la gestion des structures de dossiers sur le serveur.
  * **Synchronisation limitée** : La synchronisation entre plusieurs clients est compliquée car les e-mails sont souvent supprimés du serveur après téléchargement.
  * **Mode hors ligne** : Les e-mails sont stockés localement après téléchargement.
  * **Sécurité** : Peut utiliser SSL/TLS pour sécuriser les communications. Utilise les ports 110 (non sécurisé) et 995 (sécurisé par SSL/TLS).

***

## <mark style="color:red;">**3. Commandes**</mark>

* <mark style="color:green;">**IMAP :**</mark>
  * `LOGIN username password` : Authentifie l'utilisateur.
  * `LIST "" *` : Liste tous les répertoires.
  * `CREATE "INBOX"` : Crée une boîte aux lettres avec le nom spécifié.
  * `DELETE "INBOX"` : Supprime une boîte aux lettres.
  * `RENAME "ToRead" "Important"` : Renomme une boîte aux lettres.
  * `LSUB "" *` : Liste les boîtes aux lettres abonnées.
  * `SELECT INBOX` : Sélectionne une boîte aux lettres pour accéder aux messages.
  * `UNSELECT INBOX` : Désélectionne une boîte aux lettres.
  * `FETCH <ID> all` : Récupère les données associées à un message.
  * `CLOSE` : Supprime tous les messages marqués comme supprimés.
  * `LOGOUT` : Ferme la connexion avec le serveur IMAP.
* <mark style="color:green;">**POP3 :**</mark>
  * `USER username` : Identifie l'utilisateur.
  * `PASS password` : Authentifie l'utilisateur avec le mot de passe.
  * `STAT` : Demande le nombre de messages stockés.
  * `LIST` : Demande le nombre et la taille de tous les messages.
  * `RETR id` : Demande la livraison d'un message par ID.
  * `DELE id` : Supprime un message par ID.
  * `CAPA` : Affiche les capacités du serveur.
  * `RSET` : Réinitialise les informations transmises.
  * `QUIT` : Ferme la connexion avec le serveur POP3.

***

## <mark style="color:red;">**4. Sécurité**</mark>

* <mark style="color:green;">**IMAP**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * **Chiffrement** : SSL/TLS est souvent utilisé pour sécuriser les communications. Le port 993 est couramment utilisé pour les connexions sécurisées.
  * **Configuration** : Les paramètres de sécurité peuvent inclure le chiffrement des données, la vérification des certificats, et la protection contre les connexions non sécurisées.
* <mark style="color:green;">**POP3**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * **Chiffrement** : SSL/TLS est également utilisé pour sécuriser les communications, généralement sur le port 995.
  * **Configuration** : Comme IMAP, le chiffrement est essentiel pour la sécurité des données. Les communications non sécurisées doivent être évitées.

***

## <mark style="color:red;">**5. Configuration et Tests**</mark>

* <mark style="color:green;">**Configuration par défaut**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * IMAP et POP3 peuvent être configurés de nombreuses manières. Pour une configuration détaillée, il est recommandé de créer une VM et d'installer des serveurs de messagerie comme Dovecot pour expérimenter les configurations.
* <mark style="color:green;">**Tests avec Nmap**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * Utilisez Nmap pour scanner les ports 110, 143, 993, et 995 pour identifier les services POP3 et IMAP sur un serveur, ainsi que leurs capacités et certificats SSL.
* <mark style="color:green;">**Tests avec cURL et OpenSSL**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * Utilisez `curl` et `openssl` pour interagir avec les serveurs IMAP et POP3, tester les connexions sécurisées, et vérifier les détails des certificats SSL.

***

## <mark style="color:red;">**6. Paramètres Dangereux**</mark>

#### <mark style="color:green;">**Configuration risquée**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

* `auth_debug` : Active les journaux de débogage d'authentification.
* `auth_debug_passwords` : Enregistre les mots de passe et schémas utilisés.
* `auth_verbose` : Journalise les tentatives d'authentification échouées.
* `auth_verbose_passwords` : Les mots de passe d'authentification sont enregistrés.
* `auth_anonymous_username` : Spécifie le nom d'utilisateur pour la connexion anonyme.

***

## <mark style="color:red;">Footprinting the Service</mark>

By default, ports `110` and `995` are used for POP3, and ports `143` and `993` are used for IMAP. The higher ports (`993` and `995`) use TLS/SSL to encrypt the communication between the client and server. Using Nmap, we can scan the server for these ports. The scan will return the corresponding information (as seen below) if the server uses an embdedded certificate.

<mark style="color:green;">**Nmap**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

***

<mark style="color:green;">**cURL**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd

* LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." INBOX
```

If we also use the `verbose` (`-v`) option, we will see how the connection is made. From this, we can see the version of TLS used for encryption, further details of the SSL certificate, and even the banner, which will often contain the version of the mail server.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v


> A003 LIST "" *
< * LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." Important
< * LIST (\HasNoChildren) "." INBOX
* LIST (\HasNoChildren) "." INBOX
< A003 OK List completed (0.001 + 0.000 secs).
* Connection #0 to host 10.129.14.128 left intact
```
{% endcode %}

To interact with the IMAP or POP3 server over SSL, we can use `openssl`, as well as `ncat`. The commands for this would look like this:

#### <mark style="color:green;">**OpenSSL - TLS Encrypted Interaction POP3**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ openssl s_client -connect 10.129.14.128:pop3s
```
{% endcode %}

#### <mark style="color:green;">**OpenSSL - TLS Encrypted Interaction IMAP**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ openssl s_client -connect 10.129.14.128:imaps
```
{% endcode %}
