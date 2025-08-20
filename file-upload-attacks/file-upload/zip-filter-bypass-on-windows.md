# Zip Filter Bypass on Windows

***

### <mark style="color:red;">🎯</mark> <mark style="color:red;"></mark><mark style="color:red;">**Concaténation ZIP Évasive : Un Cheval de Troie cible les utilisateurs Windows**</mark>

***

#### <mark style="color:green;">🧠 Les attaquants innovent sans cesse pour échapper à la détection.</mark>

La concaténation de fichiers ZIP est devenue une tactique efficace.\
En exploitant les différences entre les lecteurs ZIP et les gestionnaires d’archives, les attaquants intègrent des malwares visant les utilisateurs de certains outils spécifiques.

Cette méthode leur permet :

* D’échapper aux solutions de sécurité,
* Et de piéger les chercheurs en sécurité selon l’outil qu’ils utilisent.

***

#### <mark style="color:green;">📦 Structure du format ZIP (essentielle pour comprendre l’évasion)</mark>

Le format ZIP est largement utilisé pour :

* compresser,
* et regrouper plusieurs fichiers dans un seul,
* pour faciliter les transferts.

Mais sa **flexibilité structurelle** en fait aussi une **surface d’attaque**.

**🧱 Composants clés d’un fichier ZIP :**

* **Entrées de fichiers** : fichiers réels avec nom, taille, date.
* **Répertoire central** : situé à la fin, liste toutes les entrées avec leurs offsets.
* **EOCD (End of Central Directory)** : marque la fin de l’archive, contient :
  * nombre total d’entrées,
  * position du répertoire central.

🧩 Ces structures sont exploitées pour contourner les contrôles de sécurité.\
Les techniques d’évasion abusent des **variations dans l’interprétation** de ces composants entre outils ZIP.

***

#### <mark style="color:green;">🛠️ Les 3 lecteurs ZIP les plus courants :</mark>

| Outil                | Points forts                                      | Cas d’usage                                     |
| -------------------- | ------------------------------------------------- | ----------------------------------------------- |
| **7zip**             | Open-source, multi-formats, interface CLI avancée | Dévs, chercheurs sécurité, utilisateurs experts |
| **WinRAR**           | Stable, multi-formats, récupération d’erreurs     | Utilisateurs classiques et pros                 |
| **Windows Explorer** | Intégré à Windows, très simple                    | Utilisation de base                             |

Les tests utilisent :

* 7zip v22.01,
* WinRAR v7.01,
* Windows 23H2 (22631.4317)

***

### <mark style="color:red;">🔗</mark> <mark style="color:red;"></mark><mark style="color:red;">**Concaténation de fichiers ZIP : Exploitation de la flexibilité du format**</mark>

#### 🧨 Technique :

Les attaquants **ajoutent plusieurs archives ZIP dans un seul fichier**.

📌 Chaque archive contient son propre répertoire central.\
Mais tous les outils ne lisent **qu’un seul répertoire**, donc certains contenus sont **masqués** selon l’outil utilisé.

**💡 Exemple pratique :**

```bash
echo "fichier inoffensif" > premier.txt
echo "ceci est un malware" > second.txt
7zz a pt1.zip premier.txt
7zz a pt2.zip second.txt
cat pt1.zip pt2.zip > archive_finale.zip
```

👉 Certains outils ne verront que `premier.txt`, d’autres que `second.txt`.

***

#### 🧪 Comportement des lecteurs ZIP avec une archive concaténée :

**📂 7zip :**

* Affiche uniquement `pt1.zip` → montre `premier.txt`
* Message d’avertissement : "des données après la fin de l'archive"
* ⚠️ souvent **ignoré par l’utilisateur**

**📂 WinRAR :**

* Lit **le 2ᵉ répertoire central**
* Affiche `second.txt` (le fichier **malicieux**)
* ✔️ Bon pour les chercheurs qui veulent voir les payloads cachés

**📂 Windows Explorer :**

* Peut échouer à ouvrir l’archive concaténée
* Ou peut afficher uniquement `second.txt` **si renommé en `.rar`**
* ❌ Très peu fiable pour la sécurité

***

### <mark style="color:red;">🧨 Pourquoi cette technique fonctionne</mark>

* Les **outils de sécurité** utilisent souvent :
  * Windows Explorer,
  * 7zip en ligne de commande,
* Ces outils **n’analysent pas tous les répertoires concaténés**.

➡️ Les attaquants cachent donc leur malware dans **le deuxième ZIP**.

***

### <mark style="color:red;">☠️ Exemple d’attaque réelle :</mark>

**Trojan via une archive concaténée**

📧 Phishing email imitant une société de transport, contenant :

* Fichier attaché : `SHIPPING_INV_PL_BL_pdf.rar`
* L’utilisateur est incité à "vérifier les documents"

Mais :

* Le fichier est **un ZIP concaténé**, pas un vrai `.rar`
* Contient deux parties :
  * un `.pdf` **inoffensif**
  * un `.exe` **malveillant** : `SHIPPING_INV_PL_BL_pdf.exe`

***

#### 📤 Comportement des outils sur cette attaque :

* **7zip** : ne voit que `x.pdf` → rien de suspect.
* **WinRAR** / **Windows Explorer** : révèlent `SHIPPING_INV_PL_BL_pdf.exe` → **Trojan détecté**

Ce `.exe` utilise **AutoIt** pour :

* automatiser l’exécution,
* télécharger d’autres payloads,
* déployer ransomware ou trojan bancaire.

***

#### 🛠️ Réponse des chercheurs de Perception Point

* Ils ont **signalé le comportement à 7zip**.
* Réponse : ce n’est **pas un bug**, mais **fonctionnalité volontaire**.
* ⚠️ Donc : **ce ne sera pas corrigé** → les attaques par concaténation ZIP vont continuer.

***

### 🔐 Contre-mesure : Le “Recursive Unpacker” de Perception Point

* **Détection anti-évasion propriétaire**
* Détection automatique d’archives concaténées
* **Extraction récursive de tous les fichiers** (même ceux profondément cachés)
* Analyse dynamique post-extraction : révèle les trojans et loaders cachés

***

#### 🧭 Résumé de la chaîne d’attaque (ex. SmokeLoader)

1. Email phishing avec fichier ZIP concaténé
2. Archive contient un `.pdf` légitime + `.exe` malveillant
3. Outils classiques ne voient que le `.pdf`
4. Le `.exe` est exécuté si utilisateur naïf ou mauvaise inspection
5. Charge utile téléchargée + autres malwares déclenchés

***

### <mark style="color:red;">📦 Comment fonctionne réellement un fichier ZIP (structure interne)</mark>

Un fichier `.zip` est composé de plusieurs parties dans cet ordre logique :

```
+------------------------+
| Fichier compressé #1   |  <- données
+------------------------+
| Fichier compressé #2   |  <- données
+------------------------+
| Fichier compressé #n   |
+------------------------+
| Répertoire central     |  <- INDEX des fichiers, stocké à la fin
+------------------------+
| EOCD (End of Central Directory) <- MARQUE FIN DU ZIP
+------------------------+
```

***

### <mark style="color:red;">🗃️ 1. Répertoire Central (</mark><mark style="color:red;">`Central Directory`</mark><mark style="color:red;">)</mark>

* **C’est une sorte d’index** :
  * Il contient la **liste de tous les fichiers** dans le ZIP,
  * Et pour chaque fichier : son **nom**, sa **taille**, et surtout **où le trouver** dans le fichier ZIP (offset).
* Il est **stocké à la fin du fichier ZIP** pour des raisons de performance (pas besoin de scanner tout le fichier à chaque fois).

➡️ Quand tu ouvres un ZIP, le lecteur lit **le répertoire central** pour savoir **ce qu’il y a dedans**.

***

### <mark style="color:red;">🔚 2. EOCD (End of Central Directory)</mark>

Le **EOCD est la "balise de fin"** du ZIP. Il contient :

* Le **nombre total de fichiers**,
* L’**emplacement du répertoire central**,
* Une signature magique `0x06054b50`.

➡️ Quand un outil ZIP ouvre une archive, **il commence par chercher le EOCD** à la fin du fichier. C’est **à partir de cette position** qu’il lit ensuite **le répertoire central**.

***

### <mark style="color:red;">🚨 3. Où vient la faille ? (⚠️ Point de vulnérabilité)</mark>

#### 💥 Le ZIP est "interprété" selon **l’index déclaré dans le EOCD**, pas ce qu’il y a réellement dans le fichier.

Donc :

* Si tu concatènes **deux ZIPs**, tu peux avoir **deux EOCDs** et **deux répertoires centraux** !
* ➜ Le **premier lecteur ZIP** s’arrête au **premier EOCD**, et ignore tout ce qu’il y a après.
* ➜ Un **autre outil ZIP** peut continuer plus loin et lire le **deuxième index**, révélant **d’autres fichiers cachés**.

***

### <mark style="color:red;">🧪 Illustration ASCII de ZIP Concatenation</mark>

```
pt1.zip :
[ DATA1 ][ CENTRAL_DIR1 ][ EOCD1 ]

pt2.zip :
[ DATA2 ][ CENTRAL_DIR2 ][ EOCD2 ]

ZIP CONCATENÉ :
[ DATA1 ][ CENTRAL_DIR1 ][ EOCD1 ][ DATA2 ][ CENTRAL_DIR2 ][ EOCD2 ]
```

* 🧩 **7zip** lit EOCD1 → voit `DATA1`
* 🧩 **WinRAR** lit EOCD2 → voit `DATA2` **et ignore l'ancien index**
* 🧩 **Explorateur Windows** bugue souvent ou affiche selon l'extension

***

### <mark style="color:red;">🤯 Ce que ça permet :</mark>

* Tu peux créer une archive **qui semble contenir uniquement un fichier bénin** (`x.pdf`)
* Mais en fait contient **un payload malveillant caché** (`malware.exe`)
* Et ça passe les contrôles basés sur :
  * Nom des fichiers visibles,
  * Signature MIME de la 1ʳᵉ archive,
  * Analyse du contenu faite par un outil qui ne lit **que le premier EOCD**.

***

### <mark style="color:red;">🎯 Résumé du problème :</mark>

| Élément             | Fonction                                   | Exploitable ? |
| ------------------- | ------------------------------------------ | ------------- |
| Central Directory   | Index des fichiers (noms, emplacements)    | ✅ oui         |
| EOCD                | Indique où est le Central Directory        | ✅ oui         |
| ZIP concaténé       | Contient plusieurs Central Dir + EOCD      | ✅ oui         |
| ZIP Reader (7zip)   | Ne lit que le 1er EOCD → payload invisible | ✅ oui         |
| ZIP Reader (WinRAR) | Lit jusqu’au 2e EOCD → payload révélé      | ⚠️ dépendant  |

***
