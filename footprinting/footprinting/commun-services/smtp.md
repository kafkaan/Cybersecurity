---
cover: ../../../.gitbook/assets/smtp-jpg.webp
coverY: 0
---

# SMTP

## <mark style="color:red;">Protocole SMTP (Simple Mail Transfer Protocol)</mark>

### <mark style="color:blue;">**1. Introduction au SMTP**</mark>

* **Définition** : SMTP est un protocole <mark style="color:orange;">**utilisé pour l'envoi d'e-mails à travers un réseau IP**</mark>. Il est utilisé entre un client de messagerie et un serveur de messagerie sortant, ou entre deux serveurs SMTP.
* SMTP is often combined with the IMAP or POP3 protocols
* <mark style="color:orange;">**Port par défaut**</mark> : 25

{% hint style="warning" %}
SMTP servers also use other ports such as TCP port `587`. This port is used to receive mail from authenticated users/servers, usually using the STARTTLS command to switch the existing plaintext connection to an encrypted connection.
{% endhint %}

* **Ports alternatifs** : 587 (pour l'envoi d'e-mails authentifiés avec <mark style="color:orange;">**STARTTLS**</mark>), 465 (pour une connexion chiffrée <mark style="color:orange;">**SSL/TLS**</mark>).

***

### <mark style="color:blue;">**2. Fonctionnement du SMTP**</mark>

{% hint style="info" %}
Une fonction essentielle d'un serveur SMTP est de prévenir le spam en utilisant des mécanismes d'authentification qui permettent seulement aux utilisateurs autorisés d'envoyer des e-mails. À cette fin, la plupart des serveurs SMTP modernes supportent l'extension du protocole <mark style="color:orange;">**ESMTP avec SMTP-Auth**</mark>.&#x20;

Après avoir envoyé son e-mail, le client SMTP, également connu sous le nom d'Agent **Utilisateur de Messagerie (MUA)**, le convertit en un en-tête et un corps de message et télécharge les deux sur le serveur SMTP. Ce dernier dispose d'un **Agent de Transfert de Mail (MTA)**, la base logicielle pour l'envoi et la réception des e-mails. Le MTA vérifie la taille et le spam de l'e-mail, puis le stocke. Pour soulager le MTA, il est parfois précédé par un **Agent de Soumission de Mail (MSA)**, qui vérifie la validité, c'est-à-dire l'origine de l'e-mail. Ce MSA est également appelé serveur de relais (Relay server). Ceux-ci sont très importants plus tard, car une attaque appelée "Open Relay Attack" peut être réalisée sur de nombreux serveurs SMTP en raison d'une mauvaise configuration. Nous discuterons de cette attaque et de la manière d'identifier le point faible un peu plus tard. Le MTA recherche ensuite dans le DNS l'adresse IP du serveur de messagerie du destinataire.
{% endhint %}

1. **Client (MUA)** : Envoyer un e-mail en spécifiant l'expéditeur, le destinataire, le contenu, etc.
2. **Agent de Soumission de Mail (MSA)** : Vérifie la validité de l'e-mail avant qu'il ne soit passé au MTA.
3. **Agent de Transfert de Mail (MTA)** : Transmet l'e-mail à travers les serveurs SMTP jusqu'au serveur SMTP destinataire.
4. **Agent de Livraison de Mail (MDA)** : Reçoit l'e-mail du MTA et le place dans la boîte aux lettres du destinataire.
5. **Boîte aux lettres** : Accédée via POP3 ou IMAP.

**Schéma** : Client (MUA) ➞ Agent de Soumission de Mail (MSA) ➞ Agent de Transfert de Mail (MTA) ➞ Agent de Livraison de Mail (MDA) ➞ Boîte aux lettres (POP3/IMAP)

{% hint style="warning" %}
<mark style="color:orange;">**Le SMTP présente deux inconvénients inhérents**</mark> <mark style="color:orange;">**au protocole réseau :**</mark>

1. **Confirmation de livraison** :
   * Lors de l'envoi d'un e-mail via SMTP, il n'y a pas de confirmation de livraison utilisable.
   * Bien que les spécifications du protocole prévoient ce type de notification, leur formatage n'est pas défini par défaut.
   * En conséquence, seuls des messages d'erreur en anglais, incluant l'en-tête du message non délivré, sont généralement renvoyés.
2. **Authentification des utilisateurs** :
   * Les utilisateurs ne sont pas authentifiés lors de l'établissement de la connexion.
   * Par conséquent, l'expéditeur d'un e-mail est peu fiable.
   * Les relais SMTP ouverts sont souvent détournés pour envoyer des spams en masse, les auteurs utilisant des adresses d'expéditeur fausses pour ne pas être tracés (usurpation d'adresse e-mail).

Pour prévenir ces abus, diverses techniques de sécurité sont employées, comme :

* <mark style="color:orange;">**Le rejet des e-mails suspects ou leur déplacement en quarantaine (dossier spam).**</mark>
* <mark style="color:orange;">**Des protocoles comme DomainKeys (DKIM) et Sender Policy Framework (SPF) aident à identifier les expéditeurs fiables.**</mark>

Une extension appelée **Extended SMTP (ESMTP)** a été développée pour améliorer SMTP :

* ESMTP utilise **TLS** pour sécuriser la connexion après la commande **EHLO**, en envoyant **STARTTLS**.
* Cela initialise une connexion SMTP protégée par SSL, rendant la connexion plus sécurisée.
* L'extension **AUTH PLAIN** pour l'authentification peut alors être utilisée en toute sécurité.
{% endhint %}

***

### <mark style="color:blue;">**3. Commandes SMTP Principales**</mark>

* **HELO/EHLO** : Débute la session SMTP. EHLO fournit plus d'options que HELO.
* **MAIL FROM** : Spécifie l'adresse de l'expéditeur.
* **RCPT TO** : Spécifie l'adresse du destinataire.
* **DATA** : Débute la transmission du contenu de l'e-mail.
* **RSET** : Réinitialise la connexion mais garde la connexion ouverte.
* **VRFY** : Vérifie si une adresse de boîte aux lettres existe.
* **NOOP** : Demande une réponse pour éviter une déconnexion.
* **QUIT** : Termine la session SMTP.

***

### <mark style="color:blue;">**4. Sécurité et Chiffrement**</mark>

* **Chiffrement SSL/TLS** : Utilisé pour sécuriser les connexions SMTP afin d'éviter que les données ne soient envoyées en texte clair.
* **STARTTLS** : Commande pour initier une connexion chiffrée sur une connexion SMTP existante.
* **ESMTP** : Extension de SMTP qui supporte STARTTLS et AUTH PLAIN pour une authentification sécurisée.

***

### <mark style="color:blue;">**5. Configuration par Défaut**</mark>

Exemple de configuration dans le fichier `/etc/postfix/main.cf` :

```sh
smtpd_banner = ESMTP Server
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
myhostname = mail1.inlanefreight.htb
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
smtp_generic_maps = hash:/etc/postfix/generic
mydestination = $myhostname, localhost
masquerade_domains = $myhostname
mynetworks = 127.0.0.0/8 10.129.0.0/16
mailbox_size_limit = 0
recipient_delimiter = +
smtp_bind_address = 0.0.0.0
inet_protocols = ipv4
smtpd_helo_restrictions = reject_invalid_hostname
home_mailbox = /home/postfix
```

***

### <mark style="color:blue;">**6. Exemples de Commandes avec Telnet**</mark>

* **Telnet** 10.129.14.128 25
*   <mark style="color:green;">**Envoi d'un e-mail**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

    ```sh
    EHLO mail1
    MAIL FROM: <cry0l1t3@inlanefreight.htb>
    RCPT TO: <mrb3n@inlanefreight.htb>
    DATA
    From: <cry0l1t3@inlanefreight.htb>
    To: <mrb3n@inlanefreight.htb>
    Subject: DB
    Date: Tue, 28 Sept 2021 16:32:51 +0200
    Hey man, I am trying to access our XY-DB but the creds don't work.
    Did you make any changes there?
    .
    ```

***

### <mark style="color:blue;">**7. Problèmes de Sécurité et Attaques**</mark>

{% hint style="danger" %}
<mark style="color:green;">**1. Utilisation d'un serveur de relais (relay server) pour éviter les filtres anti-spam :**</mark>

* **Serveur de relais** : C'est un serveur SMTP que le destinataire considère comme digne de confiance et qui est vérifié par d'autres serveurs.
* **Authentification** : En règle générale, l'expéditeur doit s'authentifier auprès du serveur de relais pour pouvoir l'utiliser. Cela permet de garantir que seuls les utilisateurs autorisés peuvent envoyer des e-mails via ce serveur.
* **Objectif** : En utilisant un serveur de relais, l'expéditeur essaie de s'assurer que ses e-mails ne seront pas filtrés par les filtres anti-spam et atteindront bien le destinataire.

<mark style="color:green;">**2. Problème de la mauvaise configuration des serveurs SMTP :**</mark>

* **Manque de visibilité des administrateurs** : Les administrateurs réseau peuvent ne pas avoir une vue d'ensemble des plages d'adresses IP qu'ils doivent autoriser sur leur serveur SMTP.
* **Résultat** : Pour éviter les erreurs et ne pas perturber la communication, ils peuvent finir par permettre l'accès à **toutes les adresses IP**. C'est une configuration dangereuse car elle ouvre la porte à des abus.

<mark style="color:green;">**3. Configuration d'un relais ouvert (Open Relay) :**</mark>

* **Open Relay** : Un serveur SMTP est dit "open relay" lorsqu'il permet à n'importe quel utilisateur, sans restrictions d'IP, d'envoyer des e-mails via ce serveur, même s'ils ne sont pas authentifiés ou ne font pas partie du réseau de confiance.
*   **Exemple de configuration** :

    ```bash
    mynetworks = 0.0.0.0/0
    ```

    * **mynetworks = 0.0.0.0/0** : Cette configuration signifie que le serveur SMTP acceptera des connexions de n'importe quelle adresse IP. Autrement dit, il n'y a aucune restriction sur les adresses IP autorisées à utiliser ce serveur pour envoyer des e-mails.

<mark style="color:green;">**4. Risques associés :**</mark>

* **Envoi de faux e-mails** : Avec une telle configuration, un attaquant peut utiliser le serveur pour envoyer des e-mails frauduleux en se faisant passer pour une autre personne ou entité
{% endhint %}

* **Relay Open** : Une mauvaise configuration peut permettre à un serveur SMTP de fonctionner comme relais ouvert, permettant à des tiers d’envoyer des e-mails non autorisés.
* **Mail Spoofing** : Les attaquants peuvent falsifier l'adresse de l'expéditeur pour tromper les destinataires.
* **Vérification de Relais Ouvert** : Utilisation d'outils comme Nmap pour détecter les relais ouverts&#x20;

***

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo nmap 10.129.14.128 -sC -sV -p25

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
MAC Address: 00:00:00:00:00:00 (VMware)

```
{% endcode %}

```bash
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```

```sh
smtp-user-enum -M VRFY -U wordlist.txt -t 10.x.x.x -w 15 -v
```

***

### <mark style="color:blue;">**8. Réponses SMTP**</mark>

* **250** : Succès.
* **354** : Début des données.
* **421** : Service non disponible.
* **450** : Demande échouée, essayer plus tard.
* **451** : Erreur temporaire.
* **550** : Commande non reconnue ou mail rejeté.
* **552** : Taille du message excédée.
* **553** : Nom de commande ou d’adresse invalide.

***

### <mark style="color:blue;">**9. En-têtes des E-mails**</mark>

* **Structure** : Défini par RFC 5322. Inclut des informations sur l'expéditeur, le destinataire, le sujet, la date, et le chemin parcouru par l’e-mail.

***
