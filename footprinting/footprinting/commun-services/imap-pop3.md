---
description: https://www.mailenable.com/kb/content/article.asp?ID=ME020711
---

# IMAP / POP3

## <mark style="color:red;">**1. Introduction**</mark>

* <mark style="color:orange;">**IMAP (Internet Message Access Protocol)**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark> Permet l'accès et la gestion des e-mails directement sur le serveur. Il offre des fonctionnalités étendues pour la gestion des courriels en ligne, y compris la possibilité de gérer des structures de dossiers et de synchroniser les e-mails entre plusieurs clients.
* <mark style="color:orange;">**POP3 (Post Office Protocol)**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark> Permet de récupérer les e-mails du serveur vers un client local. Moins sophistiqué qu'IMAP, il gère uniquement le téléchargement et la suppression des e-mails sans support pour la gestion avancée des dossiers.

***

## <mark style="color:red;">**2. Fonctionnalités**</mark>

* <mark style="color:orange;">**IMAP :**</mark>
  * **Gestion en ligne** : Les e-mails restent sur le serveur, permettant une gestion centralisée et une synchronisation entre différents clients.
  * **Structures de dossiers** : Supporte la création et la gestion de dossiers sur le serveur.
  * **Synchronisation** : Permet la synchronisation des e-mails et des dossiers entre plusieurs clients (par exemple, webmail et clients de messagerie locaux).
  * **Mode hors ligne** : Certains clients peuvent offrir un mode hors ligne en téléchargeant une copie locale des e-mails, avec synchronisation ultérieure des modifications.
  * **Sécurité** : Fonctionne souvent avec SSL/TLS pour sécuriser les communications. Utilise les ports 143 (non sécurisé ou avec STARTTLS) et 993 (sécurisé par SSL/TLS).
* <mark style="color:orange;">**POP3 :**</mark>
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

* **Configuration par défaut** :
  * IMAP et POP3 peuvent être configurés de nombreuses manières. Pour une configuration détaillée, il est recommandé de créer une VM et d'installer des serveurs de messagerie comme Dovecot pour expérimenter les configurations.
* **Tests avec Nmap** :
  * Utilisez Nmap pour scanner les ports 110, 143, 993, et 995 pour identifier les services POP3 et IMAP sur un serveur, ainsi que leurs capacités et certificats SSL.
* **Tests avec cURL et OpenSSL** :
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

*   Trying 10.129.14.128:993...
* TCP_NODELAY set
* Connected to 10.129.14.128 (10.129.14.128) port 993 (#0)
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* Server certificate:
*  subject: C=US; ST=California; L=Sacramento; O=Inlanefreight; OU=Customer Support; CN=mail1.inlanefreight.htb; emailAddress=cry0l1t3@inlanefreight.htb
*  start date: Sep 19 19:44:58 2021 GMT
*  expire date: Jul  4 19:44:58 2295 GMT
*  issuer: C=US; ST=California; L=Sacramento; O=Inlanefreight; OU=Customer Support; CN=mail1.inlanefreight.htb; emailAddress=cry0l1t3@inlanefreight.htb
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
< * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB-Academy IMAP4 v.0.21.4
> A001 CAPABILITY
< * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN
< A001 OK Pre-login capabilities listed, post-login capabilities have more.
> A002 AUTHENTICATE PLAIN AGNyeTBsMXQzADEyMzQ=
< * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE
< A002 OK Logged in
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

CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb

...SNIP...

---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 3CC39A7F2928B252EF2FFA5462140B1A0A74B29D4708AA8DE1515BB4033D92C2
    Session-ID-ctx:
    Resumption PSK: 68419D933B5FEBD878FF1BA399A926813BEA3652555E05F0EC75D65819A263AA25FA672F8974C37F6446446BB7EA83F9
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - d7 86 ac 7e f3 f4 95 35-88 40 a5 b5 d6 a6 41 e4   ...~...5.@....A.
    0010 - 96 6c e6 12 4f 50 ce 72-36 25 df e1 72 d9 23 94   .l..OP.r6%..r.#.
    0020 - cc 29 90 08 58 1b 57 ab-db a8 6b f7 8f 31 5b ad   .)..X.W...k..1[.
    0030 - 47 94 f4 67 58 1f 96 d9-ca ca 56 f9 7a 12 f6 6d   G..gX.....V.z..m
    0040 - 43 b9 b6 68 de db b2 47-4f 9f 48 14 40 45 8f 89   C..h...GO.H.@E..
    0050 - fa 19 35 9c 6d 3c a1 46-5c a2 65 ab 87 a4 fd 5e   ..5.m<.F\.e....^
    0060 - a2 95 25 d4 43 b8 71 70-40 6c fe 6f 0e d1 a0 38   ..%.C.qp@l.o...8
    0070 - 6e bd 73 91 ed 05 89 83-f5 3e d9 2a e0 2e 96 f8   n.s......>.*....
    0080 - 99 f0 50 15 e0 1b 66 db-7c 9f 10 80 4a a1 8b 24   ..P...f.|...J..$
    0090 - bb 00 03 d4 93 2b d9 95-64 44 5b c2 6b 2e 01 b5   .....+..dD[.k...
    00a0 - e8 1b f4 a4 98 a7 7a 7d-0a 80 cc 0a ad fe 6e b3   ......z}......n.
    00b0 - 0a d6 50 5d fd 9a b4 5c-28 a4 c9 36 e4 7d 2a 1e   ..P]...\(..6.}*.

    Start Time: 1632081313
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
+OK HTB-Academy POP3 Server
```
{% endcode %}

#### <mark style="color:green;">**OpenSSL - TLS Encrypted Interaction IMAP**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ openssl s_client -connect 10.129.14.128:imaps

CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb

...SNIP...

---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 2B7148CD1B7B92BA123E06E22831FCD3B365A5EA06B2CDEF1A5F397177130699
    Session-ID-ctx:
    Resumption PSK: 4D9F082C6660646C39135F9996DDA2C199C4F7E75D65FA5303F4A0B274D78CC5BD3416C8AF50B31A34EC022B619CC633
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 68 3b b6 68 ff 85 95 7c-8a 8a 16 b2 97 1c 72 24   h;.h...|......r$
    0010 - 62 a7 84 ff c3 24 ab 99-de 45 60 26 e7 04 4a 7d   b....$...E`&..J}
    0020 - bc 6e 06 a0 ff f7 d7 41-b5 1b 49 9c 9f 36 40 8d   .n.....A..I..6@.
    0030 - 93 35 ed d9 eb 1f 14 d7-a5 f6 3f c8 52 fb 9f 29   .5........?.R..)
    0040 - 89 8d de e6 46 95 b3 32-48 80 19 bc 46 36 cb eb   ....F..2H...F6..
    0050 - 35 79 54 4c 57 f8 ee 55-06 e3 59 7f 5e 64 85 b0   5yTLW..U..Y.^d..
    0060 - f3 a4 8c a6 b6 47 e4 59-ee c9 ab 54 a4 ab 8c 01   .....G.Y...T....
    0070 - 56 bb b9 bb 3b f6 96 74-16 c9 66 e2 6c 28 c6 12   V...;..t..f.l(..
    0080 - 34 c7 63 6b ff 71 16 7f-91 69 dc 38 7a 47 46 ec   4.ck.q...i.8zGF.
    0090 - 67 b7 a2 90 8b 31 58 a0-4f 57 30 6a b6 2e 3a 21   g....1X.OW0j..:!
    00a0 - 54 c7 ba f0 a9 74 13 11-d5 d1 ec cc ea f9 54 7d   T....t........T}
    00b0 - 46 a6 33 ed 5d 24 ed b0-20 63 43 d8 8f 14 4d 62   F.3.]$.. cC...Mb

    Start Time: 1632081604
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB-A
```
{% endcode %}
