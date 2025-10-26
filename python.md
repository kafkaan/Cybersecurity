---
icon: python
---

# PYTHON

***

### <mark style="color:red;">1. Programmation Asynchrone</mark>

#### <mark style="color:green;">**`async/await`**</mark>

```python
import asyncio

async def tache():
    await asyncio.sleep(1)
    return "Terminé"

# Exécuter
asyncio.run(tache())
```

**Usage cyber :** Port scanning rapide, fuzzing parallèle, requêtes HTTP massives

#### <mark style="color:green;">**`asyncio.gather()`**</mark>

```python
# Exécute plusieurs tâches en parallèle
results = await asyncio.gather(
    scan_port(80),
    scan_port(443),
    scan_port(8080)
)
```

**Usage cyber :** Scanner de ports, brute-force distribué

#### <mark style="color:green;">`asyncio.Semaphore()`</mark>

```python
semaphore = asyncio.Semaphore(10)  # Max 10 tâches simultanées

async with semaphore:
    # Code limité en concurrence
    pass
```

**Usage cyber :** Rate limiting pour éviter les bans, contrôle de charge

#### <mark style="color:green;">**`asyncio.Queue()`**</mark>

```python
queue = asyncio.Queue()
await queue.put(item)
item = await queue.get()
```

**Usage cyber :** Pipeline de traitement (scan → exploit → post-exploit)

#### <mark style="color:green;">`asyncio.create_task()`</mark>

```python
task = asyncio.create_task(fonction())
await task
```

**Usage cyber :** Lancer des tâches en arrière-plan

***

### <mark style="color:red;">2. Structures de Données</mark>

#### <mark style="color:green;">`collections.deque`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Double-ended queue)</mark>

```python
from collections import deque

queue = deque([1, 2, 3])
queue.append(4)      # Ajoute à droite
queue.appendleft(0)  # Ajoute à gauche
queue.pop()          # Retire à droite
queue.popleft()      # Retire à gauche (O(1) !)
```

**Usage cyber :** BFS, file d'attente de requêtes, buffer circulaire

#### <mark style="color:green;">**`collections.defaultdict`**</mark>

```python
from collections import defaultdict

# Dict avec valeur par défaut
ports = defaultdict(list)
ports['http'].append(80)  # Pas besoin de vérifier si la clé existe
```

**Usage cyber :** Grouper des résultats de scan, compter des occurrences

#### <mark style="color:green;">`collections.Counter`</mark>

```python
from collections import Counter

words = ['admin', 'admin', 'user', 'root', 'admin']
count = Counter(words)
# Counter({'admin': 3, 'user': 1, 'root': 1})

most_common = count.most_common(2)  # Top 2
```

**Usage cyber :** Analyse de fréquence, détection de patterns

#### <mark style="color:green;">`set et opérations`</mark> <mark style="color:green;"></mark><mark style="color:green;">d'ensemble</mark>

```python
ports_open = {80, 443, 8080}
ports_filtered = {443, 8080, 3306}

common = ports_open & ports_filtered      # Intersection
all_ports = ports_open | ports_filtered   # Union
unique = ports_open - ports_filtered      # Différence
symmetric = ports_open ^ ports_filtered   # Différence symétrique
```

**Usage cyber :** Comparaison de résultats, déduplication

#### <mark style="color:green;">`heapq`</mark> <mark style="color:green;"></mark><mark style="color:green;">(Priority Queue)</mark>

```python
import heapq

heap = []
heapq.heappush(heap, (priority, item))
priority, item = heapq.heappop(heap)  # Plus petite priorité
```

**Usage cyber :** Algorithmes de pathfinding, ordonnancement de tâches

***

### <mark style="color:red;">3. Algorithmes de Recherche</mark>

#### <mark style="color:green;">BFS (Breadth-First Search)</mark>

```python
from collections import deque

def bfs(graph, start):
    visited = set()
    queue = deque([start])
    
    while queue:
        node = queue.popleft()
        if node not in visited:
            visited.add(node)
            queue.extend(graph[node])
    
    return visited
```

**Usage cyber :** Énumération de usernames, exploration de directories, graph traversal

#### <mark style="color:green;">DFS (Depth-First Search)</mark>

```python
def dfs(graph, node, visited=None):
    if visited is None:
        visited = set()
    
    visited.add(node)
    for neighbor in graph[node]:
        if neighbor not in visited:
            dfs(graph, neighbor, visited)
    
    return visited
```

**Usage cyber :** Path traversal, exploration récursive

#### <mark style="color:green;">Binary Search</mark>

```python
def binary_search(arr, target):
    left, right = 0, len(arr) - 1
    
    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    
    return -1
```

**Usage cyber :** Recherche dans des listes triées (wordlists)

#### <mark style="color:green;">Dijkstra (Shortest Path)</mark>

```python
import heapq

def dijkstra(graph, start):
    distances = {node: float('inf') for node in graph}
    distances[start] = 0
    pq = [(0, start)]
    
    while pq:
        current_dist, current = heapq.heappop(pq)
        
        if current_dist > distances[current]:
            continue
        
        for neighbor, weight in graph[current]:
            distance = current_dist + weight
            if distance < distances[neighbor]:
                distances[neighbor] = distance
                heapq.heappush(pq, (distance, neighbor))
    
    return distances
```

**Usage cyber :** Pivot dans un réseau, optimisation de routes d'attaque

***

### <mark style="color:red;">4. Manipulation de Bytes et Encodage</mark>

#### <mark style="color:green;">Bytes vs String</mark>

```python
# String → Bytes
text = "Hello"
bytes_data = text.encode('utf-8')  # b'Hello'

# Bytes → String
text = bytes_data.decode('utf-8')  # "Hello"

# Accès direct
byte_value = bytes_data[0]  # 72 (valeur ASCII de 'H')
```

#### <mark style="color:green;">`struct`</mark> <mark style="color:green;"></mark><mark style="color:green;">- Packing/Unpacking binaire</mark>

```python
import struct

# Pack (Python → bytes)
data = struct.pack('<I', 0x41424344)  # Little-endian, unsigned int
# b'DCBA'

# Unpack (bytes → Python)
value = struct.unpack('<I', b'DCBA')[0]  # 0x41424344

# Formats communs
# < : little-endian, > : big-endian
# B : unsigned char (1 byte)
# H : unsigned short (2 bytes)
# I : unsigned int (4 bytes)
# Q : unsigned long long (8 bytes)
```

**Usage cyber :** Exploitation binaire, shellcode, protocoles réseau

#### <mark style="color:green;">Encodages multiples</mark>

```python
# Base64
import base64
encoded = base64.b64encode(b'data')
decoded = base64.b64decode(encoded)

# Hex
hex_str = b'data'.hex()  # '64617461'
bytes_data = bytes.fromhex('64617461')

# URL encoding
from urllib.parse import quote, unquote
encoded = quote("admin*")  # 'admin%2A'
decoded = unquote(encoded)
```

**Usage cyber :** Obfuscation, bypass WAF, décodage de payloads

#### <mark style="color:green;">`bytearray`</mark> <mark style="color:green;"></mark><mark style="color:green;">(mutable bytes)</mark>

```python
data = bytearray(b'Hello')
data[0] = 0x68  # Modification en place
# bytearray(b'hello')
```

**Usage cyber :** Modification de binaires, patching

***

### <mark style="color:red;">5. Sockets et Réseaux</mark>

#### <mark style="color:green;">Socket basique</mark>

```python
import socket

# Client TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('example.com', 80))
sock.send(b'GET / HTTP/1.1\r\n\r\n')
response = sock.recv(4096)
sock.close()

# Serveur TCP
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 8080))
server.listen(5)
client, addr = server.accept()
data = client.recv(1024)
client.send(b'Response')
client.close()
```

#### <mark style="color:green;">Socket UDP</mark>

```python
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b'data', ('example.com', 53))
data, addr = sock.recvfrom(1024)
```

#### <mark style="color:green;">Socket non-bloquant</mark>

```python
sock.setblocking(False)
sock.settimeout(5)  # Timeout de 5 secondes
```

#### <mark style="color:green;">`select`</mark> <mark style="color:green;"></mark><mark style="color:green;">- Multiplexing I/O</mark>

```python
import select

readable, writable, errors = select.select(
    [sock1, sock2],  # Sockets à lire
    [sock3],          # Sockets à écrire
    [],               # Sockets en erreur
    timeout=5
)
```

**Usage cyber :** Reverse shell, bind shell, port scanner, C2 server

***

### <mark style="color:red;">6. Expressions Régulières (Regex)</mark>

#### <mark style="color:green;">Patterns de base</mark>

```python
import re

# Recherche
match = re.search(r'password=(\w+)', text)
if match:
    password = match.group(1)

# Trouver toutes les occurrences
emails = re.findall(r'[\w.-]+@[\w.-]+\.\w+', text)

# Remplacer
clean = re.sub(r'<script>.*?</script>', '', html)

# Split
parts = re.split(r'[,;]', "a,b;c")

# Compilation (plus rapide si réutilisé)
pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
ips = pattern.findall(text)
```

#### <mark style="color:green;">Patterns utiles en cyber</mark>

```python
# IP v4
r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# Email
r'[\w.-]+@[\w.-]+\.\w+'

# URL
r'https?://[^\s<>"]+|www\.[^\s<>"]+'

# Hash MD5
r'\b[a-f0-9]{32}\b'

# Hash SHA256
r'\b[a-f0-9]{64}\b'

# JWT Token
r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'

# API Key patterns
r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']?([a-z0-9]{32,})'

# Base64
r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
```

#### <mark style="color:green;">Groupes et lookahead/lookbehind</mark>

```python
# Groupes nommés
match = re.search(r'(?P<user>\w+):(?P<pass>\w+)', 'admin:password')
user = match.group('user')

# Positive lookahead (?=...)
# Trouve "admin" seulement si suivi de "@"
re.search(r'admin(?=@)', 'admin@example.com')

# Negative lookahead (?!...)
# Trouve "admin" seulement si PAS suivi de "istrator"
re.search(r'admin(?!istrator)', 'admin')

# Positive lookbehind (?<=...)
# Trouve les chiffres après "password="
re.search(r'(?<=password=)\d+', 'password=12345')
```

**Usage cyber :** Extraction de credentials, parsing de logs, détection de patterns

***

### <mark style="color:red;">7. Cryptographie</mark>

#### <mark style="color:green;">Hashing</mark>

```python
import hashlib

# MD5 (faible, ne pas utiliser en prod)
md5 = hashlib.md5(b'password').hexdigest()

# SHA256
sha256 = hashlib.sha256(b'password').hexdigest()

# SHA512
sha512 = hashlib.sha512(b'password').hexdigest()

# HMAC (Hash-based Message Authentication Code)
import hmac
signature = hmac.new(b'secret_key', b'message', hashlib.sha256).hexdigest()
```

#### <mark style="color:green;">Chiffrement symétrique (AES)</mark>

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Encryption
key = get_random_bytes(16)  # 128 bits
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(b'Secret message', AES.block_size))
iv = cipher.iv

# Decryption
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
```

#### <mark style="color:green;">Chiffrement asymétrique (RSA)</mark>

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Génération de clés
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Encryption
cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
ciphertext = cipher.encrypt(b'Secret')

# Decryption
cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
plaintext = cipher.decrypt(ciphertext)
```

#### <mark style="color:green;">XOR</mark>

```python
def xor_bytes(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Exemple
encrypted = xor_bytes(b'Hello', b'K')
decrypted = xor_bytes(encrypted, b'K')  # Retourne b'Hello'
```

**Usage cyber :** Cracking de hashs, analyse de malware, crypto challenges

***

### <mark style="color:red;">8. Web Scraping et Parsing</mark>

#### <mark style="color:green;">`requests`</mark> <mark style="color:green;"></mark><mark style="color:green;">- HTTP client</mark>

```python
import requests

# GET
response = requests.get('https://example.com')
print(response.text)
print(response.status_code)
print(response.headers)
print(response.cookies)

# POST
data = {'username': 'admin', 'password': 'test'}
response = requests.post('https://example.com/login', data=data)

# Headers personnalisés
headers = {'User-Agent': 'Custom'}
response = requests.get(url, headers=headers)

# Session (garde les cookies)
session = requests.Session()
session.get('https://example.com/login')
session.post('https://example.com/dashboard')

# Proxy
proxies = {'http': 'http://127.0.0.1:8080'}
requests.get(url, proxies=proxies, verify=False)
```

#### <mark style="color:green;">`BeautifulSoup`</mark> <mark style="color:green;"></mark><mark style="color:green;">- HTML/XML parsing</mark>

```python
from bs4 import BeautifulSoup

html = requests.get(url).text
soup = BeautifulSoup(html, 'html.parser')

# Sélecteurs
soup.find('div', {'class': 'content'})
soup.find_all('a')
soup.select('div.content > p')  # CSS selector

# Extraction
links = [a['href'] for a in soup.find_all('a', href=True)]
forms = soup.find_all('form')
inputs = form.find_all('input')

# Attributs
element = soup.find('input', {'name': 'token'})
token = element.get('value')
```

#### <mark style="color:green;">`lxml`</mark> <mark style="color:green;"></mark><mark style="color:green;">- Fast XML/HTML parsing</mark>

```python
from lxml import etree

tree = etree.fromstring(html_bytes)
elements = tree.xpath('//div[@class="content"]')
```

#### <mark style="color:green;">JSON</mark>

```python
import json

# Parse
data = json.loads('{"key": "value"}')

# Serialize
json_str = json.dumps({'key': 'value'}, indent=2)

# Fichiers
with open('data.json', 'r') as f:
    data = json.load(f)
```

**Usage cyber :** Web exploitation, API testing, data extraction

***

### <mark style="color:red;">9. Gestion de Fichiers et Formats</mark>

#### <mark style="color:green;">Context manager (</mark><mark style="color:green;">`with`</mark><mark style="color:green;">)</mark>

```python
# Automatiquement ferme le fichier
with open('file.txt', 'r') as f:
    content = f.read()

# Modes
# 'r'  : lecture
# 'w'  : écriture (écrase)
# 'a'  : append
# 'rb' : lecture binaire
# 'wb' : écriture binaire
```

#### <mark style="color:green;">`pathlib`</mark> <mark style="color:green;"></mark><mark style="color:green;">- Manipulation de chemins</mark>

```python
from pathlib import Path

path = Path('/tmp/file.txt')
path.exists()
path.is_file()
path.is_dir()
path.read_text()
path.write_text('data')
path.parent  # /tmp
path.name    # file.txt
path.suffix  # .txt

# Iteration
for file in Path('.').glob('*.py'):
    print(file)
```

#### <mark style="color:green;">`zipfile`</mark> <mark style="color:green;"></mark><mark style="color:green;">et</mark> <mark style="color:green;"></mark><mark style="color:green;">`tarfile`</mark>

```python
import zipfile
import tarfile

# ZIP
with zipfile.ZipFile('archive.zip', 'r') as z:
    z.extractall('/tmp')
    z.extract('file.txt')
    names = z.namelist()

# TAR
with tarfile.open('archive.tar.gz', 'r:gz') as tar:
    tar.extractall('/tmp')
```

#### <mark style="color:green;">CSV et Excel</mark>

```python
import csv

# Lecture CSV
with open('data.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(row['username'])

# Écriture CSV
with open('output.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=['user', 'pass'])
    writer.writeheader()
    writer.writerow({'user': 'admin', 'pass': '123'})
```

**Usage cyber :** Traitement de logs, extraction de data, backup/restore

***

### <mark style="color:red;">10. Concepts Avancés Python</mark>

#### <mark style="color:green;">Decorators</mark>

```python
def timer(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        print(f"{func.__name__} took {time.time() - start}s")
        return result
    return wrapper

@timer
def scan_port(port):
    # code
    pass
```

#### <mark style="color:green;">Generators</mark>

```python
def generate_passwords():
    for i in range(10000):
        yield f"pass{i:04d}"

# Usage
for password in generate_passwords():
    # Génère à la demande, économise la RAM
    test_login(password)
```

#### <mark style="color:green;">List/Dict/Set Comprehensions</mark>

```python
# List
squares = [x**2 for x in range(10)]
evens = [x for x in range(10) if x % 2 == 0]

# Dict
ports = {port: scan(port) for port in range(1, 1024)}

# Set
unique_ips = {ip for ip in ip_list}

# Generator (lazy)
gen = (x**2 for x in range(1000000))  # Ne calcule pas tout de suite
```

#### <mark style="color:green;">`*args`</mark> <mark style="color:green;"></mark><mark style="color:green;">et</mark> <mark style="color:green;"></mark><mark style="color:green;">`**kwargs`</mark>

```python
def fonction(*args, **kwargs):
    # args = tuple des arguments positionnels
    # kwargs = dict des arguments nommés
    pass

fonction(1, 2, 3, key='value')
# args = (1, 2, 3)
# kwargs = {'key': 'value'}

# Unpacking
liste = [1, 2, 3]
fonction(*liste)  # Équivaut à fonction(1, 2, 3)

dico = {'key': 'value'}
fonction(**dico)  # Équivaut à fonction(key='value')
```

#### <mark style="color:green;">Lambda functions</mark>

```python
# Fonction anonyme
square = lambda x: x**2

# Avec map/filter/sorted
numbers = [1, 2, 3, 4]
squares = list(map(lambda x: x**2, numbers))
evens = list(filter(lambda x: x % 2 == 0, numbers))
sorted_ports = sorted(ports, key=lambda x: x['priority'])
```

#### <mark style="color:green;">Context Managers personnalisés</mark>

```python
from contextlib import contextmanager

@contextmanager
def network_connection(host, port):
    sock = socket.connect((host, port))
    try:
        yield sock
    finally:
        sock.close()

# Usage
with network_connection('example.com', 80) as sock:
    sock.send(b'data')
```

#### <mark style="color:green;">Exception handling avancé</mark>

```python
try:
    risky_operation()
except ValueError as e:
    handle_value_error(e)
except (TypeError, KeyError) as e:
    handle_multiple(e)
except Exception as e:
    handle_generic(e)
else:
    # Exécuté si aucune exception
    pass
finally:
    # Toujours exécuté
    cleanup()

# Lever une exception
raise ValueError("Invalid input")

# Exceptions personnalisées
class ExploitFailedException(Exception):
    pass
```

#### <mark style="color:green;">`functools`</mark> <mark style="color:green;"></mark><mark style="color:green;">- Outils fonctionnels</mark>

```python
from functools import lru_cache, partial

# Cache LRU (mémoization)
@lru_cache(maxsize=128)
def fibonacci(n):
    if n < 2:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

# Partial application
def exploit(target, port, payload):
    pass

exploit_80 = partial(exploit, port=80)
exploit_80('192.168.1.1', payload='test')
```

#### <mark style="color:green;">`itertools`</mark> <mark style="color:green;"></mark><mark style="color:green;">- Itération avancée</mark>

```python
from itertools import *

# Produit cartésien
for combo in product(['a','b'], [1,2]):
    # ('a',1), ('a',2), ('b',1), ('b',2)
    pass

# Permutations
for perm in permutations([1,2,3], 2):
    # (1,2), (1,3), (2,1), (2,3), (3,1), (3,2)
    pass

# Combinaisons
for combo in combinations([1,2,3], 2):
    # (1,2), (1,3), (2,3)
    pass

# Chaînage
for item in chain([1,2], [3,4]):
    # 1, 2, 3, 4
    pass

# Groupement
data = [('a',1), ('a',2), ('b',3)]
for key, group in groupby(data, key=lambda x: x[0]):
    print(key, list(group))
```

**Usage cyber :** Password generation, bruteforce combinations

***

### <mark style="color:red;">11. Manipulation de Protocoles</mark>

#### <mark style="color:green;">HTTP avancé avec</mark> <mark style="color:green;"></mark><mark style="color:green;">`urllib`</mark>

```python
from urllib.parse import urlparse, parse_qs, urlencode, quote

# Parse URL
url = 'https://example.com/page?user=admin&id=5'
parsed = urlparse(url)
# scheme='https', netloc='example.com', path='/page', query='user=admin&id=5'

params = parse_qs(parsed.query)
# {'user': ['admin'], 'id': ['5']}

# Construire URL
new_params = urlencode({'user': 'admin', 'pass': 'test'})
# 'user=admin&pass=test'
```

#### <mark style="color:green;">DNS lookup</mark>

```python
import socket

ip = socket.gethostbyname('example.com')
hostname = socket.gethostbyaddr('93.184.216.34')

# DNS avec dnspython
import dns.resolver
answers = dns.resolver.resolve('example.com', 'A')
for rdata in answers:
    print(rdata.address)
```

#### <mark style="color:green;">Raw packets avec</mark> <mark style="color:green;"></mark><mark style="color:green;">`scapy`</mark>

```python
from scapy.all import *

# Créer un paquet
packet = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")

# Envoyer
send(packet)

# Envoyer et recevoir
response = sr1(packet, timeout=2)

# Sniffer
packets = sniff(count=10, filter="tcp port 80")
```

#### <mark style="color:green;">Subprocess (exécuter des commandes)</mark>

```python
import subprocess

# Simple
result = subprocess.run(['ls', '-la'], capture_output=True, text=True)
print(result.stdout)

# Avec input
result = subprocess.run(['cat'], input='hello', text=True, capture_output=True)

# Shell (attention: injection!)
result = subprocess.run('ls | grep txt', shell=True, capture_output=True)
```

**Usage cyber :** Network scanning, packet crafting, protocol fuzzing

***

### <mark style="color:red;">12. Optimisation et Performance</mark>

#### <mark style="color:green;">`multiprocessing`</mark> <mark style="color:green;"></mark><mark style="color:green;">- Parallélisme CPU</mark>

```python
from multiprocessing import Pool

def hash_crack(password):
    return hashlib.md5(password.encode()).hexdigest()

# Pool de 4 processus
with Pool(4) as p:
    results = p.map(hash_crack, passwords)
```

#### <mark style="color:green;">`threading`</mark> <mark style="color:green;"></mark><mark style="color:green;">- Concurrence I/O</mark>

```python
import threading

def scan_port(port):
    # I/O bound task
    pass

threads = []
for port in range(1, 1000):
    t = threading.Thread(target=scan_port, args=(port,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()
```

#### <mark style="color:green;">`queue.Queue`</mark> <mark style="color:green;"></mark><mark style="color:green;">- Thread-safe queue</mark>

```python
from queue import Queue
import threading

q = Queue()

def worker():
    while True:
        item = q.get()
        process(item)
        q.task_done()

# Start workers
for i in range(4):
    t = threading.Thread(target=worker, daemon=True)
    t.start()

# Add work
for item in items:
    q.put(item)

q.join()  # Attend que tout soit traité
```

#### <mark style="color:green;">Profiling</mark>

```python
import cProfile
import timeit

# Profile
cProfile.run('function()')

# Timeit
time = timeit.timeit('function()', number=1000)

# Context timer
import time
start = time.time()
function()
print(f"Took {time.time() - start}s")
```

#### <mark style="color:green;">Memoization / Caching</mark>

```python
from functools import lru_cache

@lru_cache(maxsize=None)
def expensive_computation(n):
    # Calcul coûteux
    return result
```

***

### 🎓 Ressources pour approfondir

1. **Python Docs** : https://docs.python.org/3/
2. **Real Python** : https://realpython.com/
3. **Awesome Python** : https://awesome-python.com/
4. **Python Security** : https://bandit.readthedocs.io/
5. **Asyncio Docs** : https://docs.python.org/3/library/asyncio.html
