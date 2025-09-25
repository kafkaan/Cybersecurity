# Union Injection

***

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_cn.png" alt=""><figcaption></figcaption></figure>

We see a potential SQL injection in the search parameters. We apply the SQLi Discovery steps by injecting a single quote (`'`), and we do get an error:

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_quote.png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Detect number of columns</mark>

Before going ahead and exploiting Union-based queries, we need to find the number of columns selected by the server. There are two methods of detecting the number of columns:

* Using `ORDER BY`
* Using `UNION`

<mark style="color:green;">**Using ORDER BY**</mark>

* Pour **détecter le nombre de colonnes**, on peut utiliser `ORDER BY`.
* Injecter `ORDER BY 1`, `ORDER BY 2`, etc., jusqu’à obtenir une **erreur** → le dernier numéro valide = nombre de colonnes.
* Exemple : si `ORDER BY 4` échoue, la table a **3 colonnes**.

```sql
' order by 1-- -
```

Reminder: We are adding an extra dash (-) at the end, to show you that there is a space after (--).

As we see, we get a normal result:

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_cn.png" alt=""><figcaption></figcaption></figure>

Next, let us try to sort by the second column, with the following payload:

```sql
' order by 2-- -
```

We still get the results. We notice that they are sorted differently, as expected:

<figure><img src="https://academy.hackthebox.com/storage/modules/33/order_by_2.jpg" alt=""><figcaption></figcaption></figure>

We do the same for column `3` and `4` and get the results back. However, when we try to `ORDER BY` column 5, we get the following error:

<figure><img src="https://academy.hackthebox.com/storage/modules/33/order_by_5.jpg" alt=""><figcaption></figcaption></figure>

This means that this table has exactly 4 columns .

***

<mark style="color:green;">**Using UNION**</mark>

* Une autre méthode : tester une **injection UNION** avec différents nombres de colonnes jusqu’à obtenir un résultat valide.
* Contrairement à `ORDER BY`, ici on obtient **une erreur jusqu’au succès**.
* Exemple : commencer par un `UNION` à 3 colonnes.

```sql
cn' UNION select 1,2,3-- -
```

We get an error saying that the number of columns don’t match:

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_columns_diff.png" alt=""><figcaption></figcaption></figure>

So, let’s try four columns and see the response

```sql
cn' UNION select 1,2,3,4-- -
```

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_columns_correct.png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Location of Injection</mark>

* Même si une requête renvoie plusieurs colonnes, la **page web n’en affiche que certaines**.
* Il faut identifier quelles colonnes sont affichées pour **placer correctement l’injection**.
* Exemple : injection renvoie `1, 2, 3, 4`, mais seulement `2, 3, 4` apparaissent à l’écran.

<figure><img src="https://academy.hackthebox.com/storage/modules/33/ports_columns_correct.png" alt=""><figcaption></figcaption></figure>

* Souvent, certaines colonnes comme `ID` ne sont pas affichées à l’utilisateur.
* Les colonnes visibles (`2, 3, 4`) sont **celles où placer l’injection**.
* Utiliser des **nombres comme données factices** aide à identifier quelles colonnes s’affichent.
* Exemple : remplacer un chiffre par `@@version` dans la colonne visible pour tester l’extraction réelle de données.

```sql
cn' UNION select 1,@@version,3,4-- -
```

<figure><img src="https://academy.hackthebox.com/storage/modules/33/db_version_1.jpg" alt=""><figcaption></figcaption></figure>
