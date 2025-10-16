# Les Journaux de Transparence des Certificats

## <mark style="color:red;">**Qu'est-ce que les Journaux de Transparence des Certificats ?**</mark>

Les journaux de **Transparence des Certificats (CT)** sont des registres publics, uniquement ajoutables, qui enregistrent la délivrance des certificats SSL/TLS. Chaque fois qu'une Autorité de Certification (CA) délivre un nouveau certificat, elle doit le soumettre à plusieurs journaux CT. Ces journaux sont maintenus par des organisations indépendantes et sont ouverts à l'inspection publique.

Considérez les journaux CT comme un registre mondial des certificats. Ils fournissent un enregistrement transparent et vérifiable de chaque certificat SSL/TLS émis pour un site web. Cette transparence a plusieurs objectifs cruciaux :

* **Détection Précoce des Certificats Frauduleux** : En surveillant les journaux CT, les chercheurs en sécurité et les propriétaires de sites web peuvent rapidement identifier des certificats suspects ou mal émis. Un certificat frauduleux est un certificat numérique non autorisé ou frauduleux émis par une autorité de certification de confiance. La détection précoce permet de révoquer rapidement les certificats avant qu'ils ne puissent être utilisés à des fins malveillantes.
* **Responsabilité des Autorités de Certification** : Les journaux CT tiennent les CA responsables de leurs pratiques de délivrance. Si une CA émet un certificat qui enfreint les règles ou les normes, cela sera publiquement visible dans les journaux, ce qui peut entraîner des sanctions ou une perte de confiance.
* **Renforcement de la PKI Web (Infrastructure à Clé Publique)** : La PKI Web est le système de confiance sous-jacent à la communication sécurisée en ligne. Les journaux CT aident à renforcer la sécurité et l'intégrité de la PKI Web en fournissant un mécanisme de supervision publique et de vérification des certificats.

***

## <mark style="color:red;">**Fonctionnement des Journaux CT**</mark>

### <mark style="color:blue;">**Journaux CT et Reconnaissance Web**</mark>

Les journaux de transparence des certificats (CT) permettent d'énumérer des sous-domaines de manière fiable et efficace en fournissant un enregistrement complet des certificats émis pour un domaine, y compris les sous-domaines. Contrairement aux méthodes de force brute ou aux listes de mots, qui reposent sur des suppositions, les journaux CT révèlent des sous-domaines historiques, même ceux liés à des certificats expirés ou inactifs. Cela permet de découvrir des sous-domaines autrement indétectables, offrant une meilleure reconnaissance et potentiellement des opportunités d'exploitation.

### <mark style="color:blue;">**Recherche dans les Journaux CT**</mark>

Il existe deux options populaires pour rechercher dans les journaux CT :

<table data-full-width="true"><thead><tr><th>Outil</th><th>Fonctionnalités Clés</th><th>Cas d'Utilisation</th><th>Avantages</th><th>Inconvénients</th></tr></thead><tbody><tr><td><strong>crt.sh</strong></td><td>Interface web conviviale, recherche simple par domaine, affichage des détails des certificats, entrées SAN.</td><td>Recherches rapides et faciles, identification des sous-domaines, vérification de l'historique des certificats.</td><td>Gratuit, facile à utiliser, pas d'inscription requise.</td><td>Options de filtrage et d'analyse limitées.</td></tr><tr><td><strong>Censys</strong></td><td>Moteur de recherche puissant pour les dispositifs connectés à Internet, filtrage avancé par domaine, IP, attributs de certificat.</td><td>Analyse approfondie des certificats, identification des erreurs de configuration, découverte de certificats et d'hôtes associés.</td><td>Données étendues et options de filtrage, accès API.</td><td>Inscription requise (niveau gratuit disponible).</td></tr></tbody></table>

<mark style="color:orange;">**Recherche avec crt.sh**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```
{% endcode %}

{% hint style="warning" %}
&#x20;select(.name\_value | contains("dev")) | .name\_value'\`

* **`|`** : C'est un pipe, il passe la sortie de la commande précédente (les données JSON obtenues par `curl`) comme entrée à la commande suivante (ici `jq`).
* **`jq`** : Un outil de ligne de commande pour le traitement de données JSON.
* **`-r`** : L'option `-r` (ou `--raw-output`) indique à `jq` de produire des sorties brutes (non échappées), ce qui est utile pour obtenir des chaînes de caractères simples.



<mark style="color:red;">**'.\[] | select(.name\_value | contains("dev")) | .name\_value'**</mark> : C'est une expression `jq` qui effectue les opérations suivantes :

* **`.[ ]`** : Cela itère à travers chaque élément de l'array JSON renvoyé par `crt.sh`.
* **`select(.name_value | contains("dev"))`** : Cela filtre les éléments pour ne garder que ceux où le champ `name_value` (qui contient le domaine ou sous-domaine) inclut la chaîne `"dev"`.
* **`.name_value`** : Cela extrait la valeur du champ `name_value` pour chaque élément filtré.

**Ce que fait cette étape :** Elle filtre les résultats JSON pour ne conserver que les sous-domaines de `facebook.com` contenant `"dev"` dans leur nom.
{% endhint %}

* `sort -u` : Cette commande trie les résultats par ordre alphabétique et supprime les doublons.
