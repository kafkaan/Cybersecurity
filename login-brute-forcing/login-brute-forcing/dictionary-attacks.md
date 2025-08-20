# Dictionary Attacks

***

## <mark style="color:red;">**Définition**</mark> :identification\_card:

> Une **dictionary attack** (attaque par dictionnaire) est une méthode utilisée pour deviner des mots de passe en testant une liste prédéfinie de mots ou phrases probables, appelés "wordlists". Cette méthode repose sur l'idée que les utilisateurs choisissent souvent des mots de passe basés sur des mots courants, des phrases simples ou des modèles prévisibles.

***

## <mark style="color:red;">**Principe**</mark> :map:

* Contrairement aux attaques par brute force qui testent **toutes les combinaisons possibles**, les attaques par dictionnaire se concentrent sur des mots **plus probables**.
* Exploitent la tendance humaine à choisir des mots de passe faciles à mémoriser.
* Le succès dépend fortement de la **qualité et de la pertinence** de la wordlist utilisée.

***

<mark style="color:green;">**Avantages et Limites**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Caractéristique</strong></td><td><strong>Dictionary Attack</strong></td><td><strong>Brute Force Attack</strong></td></tr><tr><td><strong>Efficacité</strong></td><td>Plus rapide et moins gourmande en ressources.</td><td>Très lente pour les mots de passe longs ou complexes.</td></tr><tr><td><strong>Ciblage</strong></td><td>Peut être adaptée à une cible spécifique.</td><td>Ne peut pas s'adapter : teste toutes les combinaisons.</td></tr><tr><td><strong>Limites</strong></td><td>Inefficace contre des mots de passe aléatoires.</td><td>Inefficace pour des mots de passe longs ou complexes.</td></tr><tr><td><strong>Succès</strong></td><td>Très efficace contre des mots de passe communs.</td><td>Garantit le succès, mais peut nécessiter beaucoup de temps.</td></tr></tbody></table>

***

<mark style="color:green;">**Exemple de Wordlists**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Wordlist</strong></td><td><strong>Description</strong></td><td><strong>Utilisation</strong></td><td><strong>Source</strong></td></tr><tr><td><code>rockyou.txt</code></td><td>Mots de passe courants issus de la fuite RockYou.</td><td>Attaques par dictionnaire.</td><td>RockYou Breach.</td></tr><tr><td><code>top-usernames-shortlist.txt</code></td><td>Liste des noms d'utilisateur les plus courants.</td><td>Brute force des noms d'utilisateur.</td><td>SecLists.</td></tr><tr><td><code>2023-200_most_used_passwords.txt</code></td><td>200 mots de passe les plus utilisés en 2023.</td><td>Ciblage des mots de passe communs.</td><td>SecLists.</td></tr><tr><td><code>default-passwords.txt</code></td><td>Identifiants par défaut pour routeurs, etc.</td><td>Périphériques mal sécurisés.</td><td>SecLists.</td></tr></tbody></table>

***

### <mark style="color:blue;">**Comparaison : Brute Force vs Dictionary Attack**</mark> :vs:

1. <mark style="color:green;">**Brute Force**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
   * Teste **toutes** les combinaisons possibles.
   * **Long et gourmand** en ressources.
   * Réussi contre tous les mots de passe, mais nécessite un temps considérable.
2. <mark style="color:green;">**Dictionary Attack**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
   * Teste uniquement les mots présents dans une **liste prédéfinie**.
   * **Rapide** si le mot de passe se trouve dans la liste.
   * Échoue contre des mots de passe complexes ou aléatoires.

***

## <mark style="color:red;">**Stratégies pour Renforcer une Dictionary Attack**</mark> :straight\_ruler:

1. <mark style="color:green;">**Wordlists adaptées**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
   * Ajouter des mots spécifiques au contexte cible (par exemple, jargon d'entreprise, noms d'employés).
2. <mark style="color:green;">**Données contextuelles**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
   * Exploiter des informations sur la cible : hobbies, industries, etc.
3. <mark style="color:green;">**Combinaisons personnalisées**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
   * Construire des variations des mots communs (ajouter des chiffres, des majuscules).

***

<mark style="color:orange;">**Exemple : Script Python pour une Dictionary Attack**</mark>

Ce script utilise une wordlist pour tester un mot de passe sur un système cible.

{% code overflow="wrap" fullWidth="true" %}
```python
import requests

ip = "127.0.0.1"  # Adresse IP de la cible
port = 1234       # Port de la cible

# Télécharger une wordlist
passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt").text.splitlines()

# Tester chaque mot de passe
for password in passwords:
    print(f"Attempted password: {password}")
    
    response = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})

    # Vérifier si le mot de passe est correct
    if response.ok and 'flag' in response.json():
        print(f"Correct password found: {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```
{% endcode %}

***

**Exemple de Sortie**

```
Attempted password: 123456
Attempted password: password
Attempted password: letmein
Correct password found: letmein
Flag: HTB{example_flag}
```

***
