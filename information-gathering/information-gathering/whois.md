# WHOIS

## <mark style="color:red;">**Définition**</mark>

* **WHOIS** : Protocole de requête-réponse permettant d'accéder à des bases de données sur les ressources Internet enregistrées (noms de domaine, adresses IP, systèmes autonomes).
* **Fonction** : Permet de rechercher les informations sur la propriété et la gestion des actifs en ligne.

***

## <mark style="color:red;">**Commande de Base**</mark>

```bash
whois nom_de_domaine
```

## <mark style="color:red;">**Informations Typiquement Rencontrées**</mark>

* **Domain Name** : Nom de domaine (ex. : example.com)
* **Registrar** : Société d'enregistrement (ex. : GoDaddy, Namecheap)
* **Registrant Contact** : Personne ou organisation ayant enregistré le domaine.
* **Administrative Contact** : Personne responsable de la gestion administrative du domaine.
* **Technical Contact** : Personne responsable des aspects techniques du domaine.
* **Creation Date** : Date de création du domaine.
* **Expiration Date** : Date d'expiration du domaine.
* **Name Servers** : Serveurs qui traduisent le nom de domaine en adresse IP.

***

## <mark style="color:red;">**Histoire de WHOIS**</mark>

* **Création** : Années 1970 par Elizabeth Feinler et son équipe au Stanford Research Institute's Network Information Center (NIC).
* **But Initial** : Suivre et gérer les ressources réseau sur l'ARPANET.

***

## <mark style="color:red;">**Utilisation en Sécurité Informatique**</mark>

* **Reconnaissance** : Utilisé par les pentesters pour obtenir des informations sur la cible.
* **Identification des Personnes Clés** : Noms, e-mails et téléphones pour le social engineering ou le phishing.
* **Découverte de l'Infrastructure** : Serveurs de noms, adresses IP pour identifier des points d'entrée ou des configurations.
* **Analyse Historique** : Suivre les changements de propriété et de contact à travers le temps.

## <mark style="color:red;">**Exemple de Sortie WHOIS**</mark>

```yaml
Domain Name: example.com
Registry Domain ID: 123456789_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.example
Registrar URL: https://registrar.example
Updated Date: 2023-07-03T01:11:15Z
Creation Date: 2019-08-05T22:43:09Z
Expiration Date: 2024-08-05T22:43:09Z
Registrant Contact: John Doe, john.doe@example.com
Administrative Contact: Jane Doe, jane.doe@example.com
Technical Contact: Tech Support, tech@example.com
Name Servers: ns1.example.com, ns2.example.com
```
