# Detection

***

* La détection des injections de commandes OS se fait comme l’exploitation.
* On tente d’ajouter des commandes via différentes méthodes d’injection.
* Si la sortie de la commande change par rapport au résultat attendu, la vulnérabilité est confirmée et exploitée.

***

### <mark style="color:red;">Command Injection Detection</mark>

&#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_exercise_1.jpg" alt=""><figcaption></figcaption></figure>

<figure><img src="https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_exercise_2.jpg" alt=""><figcaption></figcaption></figure>

Although we do not have access to the source code of the web application, we can confidently guess that the IP we entered is going into a `ping` command since the output we receive suggests that. As the result shows a single packet transmitted in the ping command, the command used may be as follows:

```bash
ping -c 1 OUR_INPUT
```

* Si les entrées utilisateur ne sont pas filtrées ou échappées avant d’être utilisées avec la commande `ping`, il est possible d’injecter une commande arbitraire.
* Il est donc nécessaire de tester si l’application web est vulnérable à une injection de commandes OS.

***

### <mark style="color:red;">Command Injection Methods</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Injection Operator</strong></td><td><strong>Injection Character</strong></td><td><strong>URL-Encoded Character</strong></td><td><strong>Executed Command</strong></td></tr><tr><td>Semicolon</td><td><code>;</code></td><td><code>%3b</code></td><td>Both</td></tr><tr><td>New Line</td><td></td><td><code>%0a</code></td><td>Both</td></tr><tr><td>Background</td><td><code>&#x26;</code></td><td><code>%26</code></td><td>Both (second output generally shown first)</td></tr><tr><td>Pipe</td><td><code>|</code></td><td><code>%7c</code></td><td>Both (only second output is shown)</td></tr><tr><td>AND</td><td><code>&#x26;&#x26;</code></td><td><code>%26%26</code></td><td>Both (only if first succeeds)</td></tr><tr><td>OR</td><td><code>||</code></td><td><code>%7c%7c</code></td><td>Second (only if first fails)</td></tr><tr><td>Sub-Shell</td><td><code>``</code></td><td><code>%60%60</code></td><td>Both (Linux-only)</td></tr><tr><td>Sub-Shell</td><td><code>$()</code></td><td><code>%24%28%29</code></td><td>Both (Linux-only)</td></tr></tbody></table>

* Certains opérateurs sont spécifiques à Unix (Linux/macOS) et ne fonctionneront pas sur Windows, par exemple :
  * Double backticks (\`\`)
  * Sub-shell operator ($())
* En général, pour une injection de commandes basique, la plupart des opérateurs fonctionnent indépendamment du langage web, du framework ou du serveur back-end.
* Par conséquent, une injection sur :
  * Une application PHP sur Linux,
  * Une application .Net sur Windows,
  * Une application NodeJS sur macOS,\
    devrait fonctionner de manière similaire.

{% hint style="warning" %}
Note: The only exception may be the semi-colon `;`, which will not work if the command was being executed with `Windows Command Line (CMD)`, but would still work if it was being executed with `Windows PowerShell`.
{% endhint %}
