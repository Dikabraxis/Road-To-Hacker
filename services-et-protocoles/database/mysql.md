# MySQL

### **Database SQL (MySQL) : Guide Complet pour les Requêtes de Base**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

### **Introduction**

Ce guide décrit l'utilisation des commandes SQL fondamentales pour manipuler et interagir avec les bases de données MySQL. Il inclut des exemples pratiques et détaillés pour exploiter efficacement les données.

***

### **1. SELECT : Lecture des Données**

**Afficher toutes les données d'une table**

Pour récupérer toutes les lignes et colonnes d'une table, utilise la commande :

```sql
SELECT * FROM users;
```

**Exemple de sortie :**

| id | username | password  |
| -- | -------- | --------- |
| 1  | jon      | pass123   |
| 2  | admin    | p4ssword  |
| 3  | martin   | secret123 |

**Combiner les résultats de deux tables**

La commande `UNION` permet de combiner les résultats de deux requêtes en un ensemble unique.

```sql
SELECT name, address, city, postcode 
FROM customers 
UNION 
SELECT company, address, city, postcode 
FROM suppliers;
```

**Exemple de sortie :**

| name             | address                   | city       | postcode |
| ---------------- | ------------------------- | ---------- | -------- |
| Mr John Smith    | 123 Fake Street           | Manchester | M2 3FJ   |
| Mrs Jenny Palmer | 99 Green Road             | Birmingham | B2 4KL   |
| Miss Sarah Lewis | 15 Fore Street            | London     | NW12 3GH |
| Widgets Ltd      | Unit 1a, Newby Estate     | Bristol    | BS19 4RT |
| The Tool Company | 75 Industrial Road        | Norwich    | N22 3DR  |
| Axe Makers Ltd   | 2b Makers Unit, Market Rd | London     | SE9 1KK  |

***

### **2. INSERT : Ajout de Nouvelles Données**

L'instruction `INSERT` ajoute de nouvelles lignes à une table.

**Ajouter une nouvelle ligne**

```sql
INSERT INTO users (username, password) 
VALUES ('bob', 'password123');
```

**Nouvelle table :**

| id | username | password    |
| -- | -------- | ----------- |
| 1  | jon      | pass123     |
| 2  | admin    | p4ssword    |
| 3  | martin   | secret123   |
| 4  | bob      | password123 |

***

### **3. UPDATE : Modifier des Données Existantes**

L'instruction `UPDATE` permet de modifier des valeurs dans une table.

**Modifier une ligne spécifique**

```sql
UPDATE users 
SET username = 'root', password = 'pass123' 
WHERE username = 'admin';
```

**Nouvelle table :**

| id | username | password    |
| -- | -------- | ----------- |
| 1  | jon      | pass123     |
| 2  | root     | pass123     |
| 3  | martin   | secret123   |
| 4  | bob      | password123 |

***

### **4. DELETE : Supprimer des Données**

L'instruction `DELETE` supprime des lignes spécifiques ou toutes les lignes d'une table.

**Supprimer une ligne spécifique**

```sql
DELETE FROM users 
WHERE username = 'martin';
```

**Nouvelle table :**

| id | username | password    |
| -- | -------- | ----------- |
| 1  | jon      | pass123     |
| 2  | root     | pass123     |
| 4  | bob      | password123 |

**Supprimer toutes les lignes**

```sql
DELETE FROM users;
```

**Table vide :**

***

### **5. Requêtes Complémentaires et Bonnes Pratiques**

**Lister les Bases de Données**

Afficher toutes les bases de données disponibles :

```sql
SHOW DATABASES;
```

**Changer de Base de Données**

Sélectionner une base de données spécifique pour exécuter les requêtes :

```sql
USE database_name;
```

**Lister les Tables dans une Base de Données**

Afficher toutes les tables de la base sélectionnée :

```sql
SHOW TABLES;
```

**Afficher la Structure d'une Table**

Obtenir la structure d'une table (colonnes, types, clés) :

```sql
DESCRIBE users;
```

**Exemple de sortie :**

| Field    | Type        | Null | Key | Default | Extra           |
| -------- | ----------- | ---- | --- | ------- | --------------- |
| id       | int         | NO   | PRI | NULL    | auto\_increment |
| username | varchar(50) | NO   |     | NULL    |                 |
| password | varchar(50) | NO   |     | NULL    |                 |

**Créer une Sauvegarde**

Exporter une table ou une base entière avec `mysqldump` :

```bash
mysqldump -u username -p database_name > backup.sql
```

**Restaurer une Sauvegarde**

Importer une sauvegarde dans une base de données :

```bash
mysql -u username -p database_name < backup.sql
```

***

### **6. Conclusion**

Ce guide couvre les principales commandes pour manipuler des bases de données MySQL. Ces techniques permettent d'ajouter, de modifier, de supprimer, et de lire des données de manière efficace. Apprends à bien structurer tes requêtes pour éviter les erreurs ou les pertes de données, et travaille toujours sur une copie pour expérimenter de nouvelles commandes.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
