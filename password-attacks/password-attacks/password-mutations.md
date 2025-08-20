# Password Mutations

***

`OSINT` information gathering can be very helpful for finding out more about a user's preferences and may assist with password guessing.&#x20;

Commonly, users use the following additions for their password to fit the most common password policies:

| **Description**                        | **Password Syntax** |
| -------------------------------------- | ------------------- |
| First letter is uppercase.             | `Password`          |
| Adding numbers.                        | `Password123`       |
| Adding year.                           | `Password2022`      |
| Adding month.                          | `Password02`        |
| Last character is an exclamation mark. | `Password2022!`     |
| Adding special characters.             | `P@ssw0rd2022!`     |

Étant donné que de nombreuses personnes souhaitent garder leurs mots de passe aussi simples que possible malgré les politiques de sécurité, nous pouvons créer des règles pour générer des mots de passe faibles.&#x20;

***

D'après les statistiques fournies par WPengine, la plupart des mots de passe ne dépassent pas dix caractères. Ce que nous pouvons faire, c'est choisir des termes d'au moins cinq caractères de long qui semblent les plus familiers pour les utilisateurs, tels que les noms de leurs animaux de compagnie, leurs loisirs, leurs préférences et autres centres d'intérêt.&#x20;

Si l'utilisateur choisit un mot unique (comme le mois en cours), ajoute l'année en cours, suivie d'un caractère spécial à la fin de son mot de passe, on obtiendrait ainsi un mot de passe de dix caractères. Étant donné que la plupart des entreprises exigent des changements réguliers de mot de passe, un utilisateur peut modifier son mot de passe en changeant simplement le nom d'un mois ou un seul chiffre, etc. Prenons un exemple simple pour créer une liste de mots de passe avec une seule entrée.

***

### <mark style="color:blue;">**Password List**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ cat password.list

password
```

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Function</strong></td><td><strong>Description</strong></td></tr><tr><td><code>:</code></td><td>Do nothing.</td></tr><tr><td><code>l</code></td><td>Lowercase all letters.</td></tr><tr><td><code>u</code></td><td>Uppercase all letters.</td></tr><tr><td><code>c</code></td><td>Capitalize the first letter and lowercase others.</td></tr><tr><td><code>sXY</code></td><td>Replace all instances of X with Y.</td></tr><tr><td><code>$!</code></td><td>Add the exclamation character at the end.</td></tr></tbody></table>

Each rule is written on a new line which determines how the word should be mutated. If we write the functions shown above into a file and consider the aspects mentioned, this file can then look like this:

***

## <mark style="color:blue;">**Hashcat Rule File**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

Hashcat will apply the rules of `custom.rule` for each word in `password.list` and store the mutated version in our `mut_password.list` accordingly. Thus, one word will result in fifteen mutated words in this case.

<mark style="color:green;">**Generating Rule-based Wordlist**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
mrroboteLiot@htb[/htb]$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```
{% endcode %}

`Hashcat` and `John` come with pre-built rule lists that we can use for our password generating and cracking purposes. One of the most used rules is `best64.rule`

***

## <mark style="color:blue;">**Hashcat Existing Rules**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ ls /usr/share/hashcat/rules/

best64.rule                  specific.rule
combinator.rule              T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
d3ad0ne.rule                 T0XlC-insert_space_and_special_0_F.rule
dive.rule                    T0XlC-insert_top_100_passwords_1_G.rule
generated2.rule              T0XlC.rule
generated.rule               T0XlCv1.rule
hybrid                       toggles1.rule
Incisive-leetspeak.rule      toggles2.rule
InsidePro-HashManager.rule   toggles3.rule
InsidePro-PasswordsPro.rule  toggles4.rule
leetspeak.rule               toggles5.rule
oscommerce.rule              unix-ninja-leetspeak.rule
rockyou-30000.rule
```
{% endcode %}

We can now use another tool called [CeWL](https://github.com/digininja/CeWL) to scan potential words from the company's website and save them in a separate list. We can then combine this list with the desired rules and create a customized password list that has a higher probability of guessing a correct password. We specify some parameters, like the depth to spider (`-d`), the minimum length of the word (`-m`), the storage of the found words in lowercase (`--lowercase`), as well as the file where we want to store the results (`-w`).

***

## <mark style="color:blue;">**Generating Wordlists Using CeWL**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
mrroboteLiot@htb[/htb]$ wc -l inlane.wordlist

```
{% endcode %}
