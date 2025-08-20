# DOM XSS

<mark style="color:orange;">**DOM-based XSS**</mark>, un type non persistant. Contrairement au **Reflected XSS** qui envoie les données au serveur, le **DOM XSS** est traité entièrement côté client via JavaScript. Il se produit lorsque JavaScript modifie la source de la page via le **Document Object Model (DOM)**.

Dans cet exemple, en ajoutant un élément de test, on constate qu'aucune requête HTTP n'est envoyée et que l'élément est traité uniquement côté client. Le paramètre d'entrée dans l'URL utilise un **hashtag (#)**, ce qui montre que le traitement se fait côté navigateur et n'atteint pas le serveur. De plus, le code JavaScript met à jour la page après son chargement, donc la source de la page ne montre pas notre entrée, et elle ne persiste pas après un rafraîchissement.

<figure><img src="../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

However, if we open the `Network` tab in the Firefox Developer Tools, and re-add the `test` item, we would notice that no HTTP requests are being made:

&#x20; &#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/103/xss_dom_network.jpg" alt=""><figcaption></figcaption></figure>

&#x20; &#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/103/xss_dom_inspector.jpg" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Source & Sink</mark>

Pour mieux comprendre la nature de la vulnérabilité **DOM-based XSS**, il est important de saisir les concepts de **Source** et de **Sink** des objets affichés sur la page. La **Source** est l'objet JavaScript qui prend l'entrée de l'utilisateur, et cela peut être n'importe quel paramètre d'entrée, comme un paramètre d'URL ou un champ de saisie, comme nous l'avons vu précédemment.

D'autre part, le **Sink** est la fonction qui écrit l'entrée de l'utilisateur dans un objet DOM sur la page. Si la fonction Sink ne nettoie pas correctement l'entrée de l'utilisateur, elle sera vulnérable à une attaque XSS. Certaines des fonctions JavaScript couramment utilisées pour écrire dans les objets DOM sont :

* `document.write()`
* `DOM.innerHTML`
* `DOM.outerHTML`

De plus, certaines fonctions de la bibliothèque jQuery qui écrivent dans les objets DOM sont :

* `add()`
* `after()`
* `append()`

Si une fonction Sink écrit l'entrée exacte sans aucune sanitation (comme les fonctions mentionnées ci-dessus), et qu'aucune autre méthode de sanitation n'est utilisée, cela signifie que la page est vulnérable à une attaque XSS.

Nous pouvons regarder le code source de l'application web To-Do, examiner `script.js`, et nous verrons que la Source est prise depuis le paramètre `task=`.

{% code fullWidth="true" %}
```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```
{% endcode %}

Right below these lines, we see that the page uses the `innerHTML` function to write the `task` variable in the `todo` DOM:

{% code overflow="wrap" fullWidth="true" %}
```javascript
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```
{% endcode %}

So, we can see that we can control the input, and the output is not being sanitized, so this page should be vulnerable to DOM XSS.

***

### <mark style="color:red;">DOM Attacks</mark>

Si nous essayons la charge utile XSS que nous avons utilisée précédemment, nous verrons qu'elle ne s'exécutera pas. Cela est dû au fait que la fonction `innerHTML` n'autorise pas l'utilisation des balises `<script>` pour des raisons de sécurité. Cependant, il existe de nombreuses autres charges utiles XSS qui ne contiennent pas de balises `<script>`, comme celle-ci :

```html
<img src="" onerror=alert(window.origin)>
```

Cette ligne crée un nouvel objet image HTML, qui possède un attribut `onerror` capable d'exécuter du code JavaScript lorsque l'image n'est pas trouvée. En fournissant un lien d'image vide (`""`), notre code s'exécutera toujours sans avoir besoin d'utiliser des balises `<script>`.

{% hint style="warning" %}
Pour cibler un utilisateur avec cette vulnérabilité DOM XSS, nous pouvons une fois de plus copier l'URL du navigateur et la partager avec l'utilisateur. Lorsqu'il visitera cette URL, le code JavaScript devrait s'exécuter. Ces charges utiles font partie des plus basiques en XSS, mais selon la sécurité de l'application web et du navigateur, il peut être nécessaire d'utiliser différentes charges utiles, ce que nous verrons dans la section suivante.
{% endhint %}

![](https://academy.hackthebox.com/storage/modules/103/xss_dom_alert.jpg)
