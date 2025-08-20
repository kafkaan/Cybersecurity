# Hybrid Attacks

***

Many organizations implement policies requiring users to change their passwords periodically to enhance security. However, these policies can inadvertently breed predictable password patterns if users are not adequately educated on proper password hygiene.

![](https://academy.hackthebox.com/storage/modules/57/2n.png)

## <mark style="color:red;">Hybrid Attacks in Action</mark> :bridge\_at\_night:

Let's illustrate this with a practical example. Consider an attacker targeting an organization known to enforce regular password changes.

![](https://academy.hackthebox.com/storage/modules/57/3n.png)

***

## <mark style="color:red;">The Power of Hybrid Attacks</mark>

The effectiveness of hybrid attacks lies in their adaptability and efficiency. They leverage the strengths of both dictionary and brute-force techniques, maximizing the chances of cracking passwords, especially in scenarios where users fall into predictable patterns.

It's important to note that hybrid attacks are not limited to the password change scenario described above. They can be tailored to exploit any observed or suspected password patterns within a target organization. Let's consider a scenario where you have access to a common passwords wordlist, and you're targeting an organization with the following password policy:

* Minimum length: 8 characters
* Must include:
  * At least one uppercase letter
  * At least one lowercase letter
  * At least one number

To extract only the passwords that adhere to this policy, we can leverage the powerful command-line tools available on most Linux/Unix-based systems by default, specifically `grep` paired with regex. We are going to use the [darkweb2017-top10000.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/darkweb2017-top10000.txt) password list for this. First, download the wordlist

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/darkweb2017-top10000.txt
```
{% endcode %}

Next, we need to start matching that wordlist to the password policy.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ grep -E '^.{8,}$' darkweb2017-top10000.txt > darkweb2017-minlength.txt
```
{% endcode %}

This initial `grep` command targets the core policy requirement of a minimum password length of 8 characters. The regular expression `^.{8,}$` acts as a filter, ensuring that only passwords containing at least 8 characters are passed through and saved in a temporary file named `darkweb2017-minlength.txt`.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt
```
{% endcode %}

Building upon the previous filter, this `grep` command enforces the policy's demand for at least one uppercase letter. The regular expression `[A-Z]` ensures that any password lacking an uppercase letter is discarded, further refining the list saved in `darkweb2017-uppercase.txt`.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt
```
{% endcode %}

Maintaining the filtering chain, this `grep` command ensures compliance with the policy's requirement for at least one lowercase letter. The regular expression `[a-z]` serves as the filter, keeping only passwords that include at least one lowercase letter and storing them in `darkweb2017-lowercase.txt`.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt
```
{% endcode %}

This last `grep` command tackles the policy's numerical requirement. The regular expression `[0-9]` acts as a filter, ensuring that passwords containing at least one numerical digit are preserved in `darkweb2017-number.txt`.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ wc -l darkweb2017-number.txt

89 darkweb2017-number.txT
```
{% endcode %}

***

## <mark style="color:red;">Credential Stuffing: Leveraging Stolen Data for Unauthorized Access</mark>

![](https://academy.hackthebox.com/storage/modules/57/5n.png)

Les attaques par **credential stuffing** exploitent la tendance généralisée des utilisateurs à réutiliser leurs mots de passe sur plusieurs comptes en ligne. Cette pratique, motivée par la recherche de commodité et la difficulté de gérer de nombreux mots de passe uniques, offre aux attaquants un terrain fertile.

**Étapes des Attaques**

1. **Acquisition des Identifiants Compromis :**\
   Les attaquants obtiennent des listes de noms d’utilisateurs et mots de passe compromis via :
   * Des violations de données à grande échelle.
   * Des campagnes de phishing ou des logiciels malveillants.
   * Des listes publiques comme _rockyou_ ou _SecLists_ contenant des mots de passe courants.
2. **Identification des Cibles :**\
   Les attaquants visent des services en ligne susceptibles d’être utilisés par les victimes : réseaux sociaux, fournisseurs de messagerie, banques en ligne et sites d’e-commerce.
3. **Automatisation des Tests :**\
   À l’aide de scripts ou d’outils, les attaquants testent les identifiants volés de manière automatisée et discrète, en imitant un comportement utilisateur normal pour éviter les systèmes de détection.
4. **Accès Non Autorisé :**\
   Lorsqu’un identifiant correspond, les attaquants accèdent aux comptes, leur permettant :
   * Vol de données.
   * Fraudes financières.
   * Diffusion de logiciels malveillants ou attaques supplémentaires.

**Le Problème de la Réutilisation des Mots de Passe**

Le principal facteur du succès du **credential stuffing** est la réutilisation des mots de passe. Une violation sur un service peut entraîner une cascade de compromissions sur d’autres comptes utilisant des identifiants similaires.

**Solutions Proposées**

* Utiliser des mots de passe forts et uniques pour chaque service.
* Activer l’authentification à deux facteurs (2FA) pour une sécurité renforcée.
