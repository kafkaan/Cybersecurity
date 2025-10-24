# Antak Webshell

***

### <mark style="color:red;">ASPX and a Quick Learning Tip</mark>

One great resource to use in learning is `IPPSEC's` blog site [ippsec.rocks](https://ippsec.rocks/?). The site is a powerful learning tool. Take, for example, the concept of web shells. We can use his site to type in the concept we want to learn, like aspx.

![IPPSEC Rocks](https://academy.hackthebox.com/storage/modules/115/ippsecrocks.png)

***

### <mark style="color:red;">ASPX Explained</mark>

* **ASPX = extension ASP.NET** : fichiers serveur écrits pour le framework **ASP.NET** de Microsoft.
* **Fonctionnement** : la page ASPX reçoit des entrées utilisateur côté serveur, les traite et génère du **HTML** envoyé au navigateur.
* **Capacités serveur** : côté serveur, une page ASPX peut appeler des APIs .NET et interagir avec le système d’exploitation (fichiers, processus, réseau).
* **Webshell ASPX** : une webshell écrite en ASPX permet, si elle est uploadée/exécutée, d’exécuter des actions sur le serveur Windows via la couche .NET.
* **Risque** : une webshell donne potentiellement un contrôle important sur la machine hébergeant l’application — c’est une vulnérabilité critique si déposée sans autorisation.
* **Exemple cité** : l’**Antak Webshell** est un exemple d’implémentation ASPX utilisée pour illustrer ce type d’accès (ne pas l’utiliser sur des cibles non autorisées).

***

### <mark style="color:red;">Antak Webshell</mark>

* **Antak** est une **webshell ASP.NET** incluse dans le projet **Nishang**.
* **Nishang** = trousse d’outils offensifs basée sur **PowerShell** pour faciliter diverses phases d’un pentest.
* **Antak** utilise PowerShell côté serveur pour interagir avec l’hôte Windows, ce qui en fait un moyen efficace d’obtenir une webshell sur un serveur ASP.NET.
* L’interface d’Antak est même thématisée façon **PowerShell**, ce qui facilite l’utilisation pour manipuler objets et commandes .NET/PowerShell.
* Utilité pédagogique : pratique utile pour comprendre l’impact d’une webshell et tester des rétroactions côté serveur **dans un lab autorisé**.

***

### <mark style="color:red;">Working with Antak</mark>

The Antak files can be found in the `/usr/share/nishang/Antak-WebShell` directory.

```shell-session
mrroboteLiot@htb[/htb]$ ls /usr/share/nishang/Antak-WebShell

antak.aspx  Readme.md
```

* **Fonctionne comme une console PowerShell** : interface et logique similaires à PowerShell côté serveur.
* **Exécution par processus** : chaque commande envoyée est lancée comme **un nouveau processus** (pas une session interactive persistante).
* **Exécution en mémoire possible** : peut charger et exécuter des scripts directement en mémoire (sans écrire forcément sur le disque).
* **Encodage des commandes** : permet d’encoder/obfusquer les commandes envoyées, rendant l’analyse ou la détection plus difficile.
* **Outil puissant** : offre beaucoup de fonctionnalités pour manipuler le système via le web (fichiers, processus, exécution de commandes)

***

### <mark style="color:red;">Antak Demonstration</mark>

<mark style="color:green;">**Move a Copy for Modification**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```
{% endcode %}

Make sure you set credentials for access to the web shell. Modify `line 14`, adding a user (green arrow) and password (orange arrow). This comes into play when you browse to your web shell, much like Laudanum. This can help make your operations more secure by ensuring random people can't just stumble into using the shell. It can be prudent to remove the ASCII art and comments from the file. These items in a payload are often signatured on and can alert the defenders/AV to what you are doing.

<mark style="color:green;">**Modify the Shell for Use**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/antak-changes.png)

<mark style="color:green;">**Shell Success**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/antak-creds-prompt.png)

As seen in the following image, we will be granted access if our credentials are entered properly.

![image](https://academy.hackthebox.com/storage/modules/115/antak-success.png)

<mark style="color:green;">**Issuing Commands**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/antak-commands.png)
