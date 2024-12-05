# SQLite3

### **SQLite3 : Exploitation d'une Base de Données**

SQLite3 est un système de gestion de bases de données relationnelles léger utilisé dans de nombreuses applications, y compris des sites web et des logiciels embarqués. Voici un guide détaillé pour explorer et manipuler une base de données SQLite3, en utilisant l'exemple d'une base de données récupérée nommée `example.db`.

***

### **1. Vérifier le Type de Base de Données**

Avant de manipuler un fichier de base de données, il est utile de confirmer son type.

```bash
file example.db
```

**Exemple de sortie :**

```plaintext
example.db: SQLite 3.x database, last written using SQLite version 3039002, file counter 1, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 1
```

Cela confirme que le fichier est une base de données SQLite.

***

### **2. Accéder à la Base de Données**

Pour ouvrir la base de données avec l'interpréteur SQLite3, utilise la commande suivante :

```bash
sqlite3 example.db
```

**Exemple de sortie :**

```plaintext
SQLite version 3.39.2 2022-07-21 15:24:47
Enter ".help" for usage hints.
sqlite>
```

Tu es maintenant dans l'interface interactive de SQLite3.

***

### **3. Découvrir la Structure de la Base de Données**

**Lister les Tables Disponibles**

Pour afficher toutes les tables dans la base de données, utilise la commande suivante :

```sql
sqlite> .tables
```

**Exemple de sortie :**

```plaintext
customers
```

**Afficher la Structure d'une Table**

Pour examiner la structure d'une table et ses colonnes, utilise la commande `PRAGMA` :

```sql
sqlite> PRAGMA table_info(customers);
```

**Exemple de sortie :**

```plaintext
0|custID|INT|1||1
1|custName|TEXT|1||0
2|creditCard|TEXT|0||0
3|password|TEXT|1||0
```

Cela indique que la table `customers` a les colonnes suivantes :

* **custID** : Identifiant de type `INT`.
* **custName** : Nom du client de type `TEXT`.
* **creditCard** : Numéro de carte de crédit de type `TEXT`.
* **password** : Mot de passe (probablement haché) de type `TEXT`.

***

### **4. Manipuler les Données**

**Afficher le Contenu d'une Table**

Pour afficher toutes les données contenues dans une table, utilise une requête SQL :

```sql
sqlite> SELECT * FROM customers;
```

**Exemple de sortie :**

```plaintext
0|Joy Paulson|4916 9012 2231 7905|5f4dcc3b5aa765d61d8327deb882cf99
1|John Walters|4671 5376 3366 8125|fef08f333cc53594c8097eba1f35726a
2|Lena Abdul|4353 4722 6349 6685|b55ab2470f160c331a99b8d8a1946b19
3|Andrew Miller|4059 8824 0198 5596|bc7b657bd56e4386e3397ca86e378f70
4|Keith Wayman|4972 1604 3381 8885|12e7a36c0710571b3d827992f4cfe679
5|Annett Scholz|5400 1617 6508 1166|e2795fc96af3f4d6288906a90a52a47f
```

Cela affiche toutes les lignes de la table `customers`.

**Filtrer les Données avec une Condition**

Pour afficher uniquement certaines lignes, utilise une condition `WHERE` :

```sql
sqlite> SELECT * FROM customers WHERE custID = 1;
```

**Exemple de sortie :**

```plaintext
1|John Walters|4671 5376 3366 8125|fef08f333cc53594c8097eba1f35726a
```

***

### **5. Exporter ou Sauvegarder les Données**

**Exporter en CSV**

Pour sauvegarder les données d'une table dans un fichier CSV, utilise les commandes suivantes :

```sql
sqlite> .mode csv
sqlite> .output output.csv
sqlite> SELECT * FROM customers;
sqlite> .output stdout
```

Les données seront écrites dans un fichier nommé `output.csv`.

**Exporter en Fichier Texte**

Pour exporter les données dans un fichier texte brut :

```sql
sqlite> .output output.txt
sqlite> SELECT * FROM customers;
sqlite> .output stdout
```

***

### **6. Ajouter ou Modifier des Données**

**Insérer une Nouvelle Ligne**

Pour ajouter une nouvelle entrée dans une table :

```sql
sqlite> INSERT INTO customers (custID, custName, creditCard, password)
   ...> VALUES (6, 'New Customer', '1234 5678 9012 3456', '098f6bcd4621d373cade4e832627b4f6');
```

Cela insère un nouvel enregistrement avec les informations fournies.

**Mettre à Jour une Entrée**

Pour mettre à jour des informations existantes dans une table :

```sql
sqlite> UPDATE customers
   ...> SET password = '5d41402abc4b2a76b9719d911017c592'
   ...> WHERE custID = 1;
```

Cela change le mot de passe du client avec l'ID 1.

***

### **7. Supprimer des Données**

**Supprimer une Ligne**

Pour supprimer une ligne spécifique :

```sql
sqlite> DELETE FROM customers WHERE custID = 5;
```

**Supprimer Toutes les Données d'une Table**

Pour vider complètement une table tout en conservant sa structure :

```sql
sqlite> DELETE FROM customers;
```

***

### **8. Quitter SQLite**

Pour quitter l'interface SQLite3 :

```sql
sqlite> .exit
```

***

### **9. Bonnes Pratiques**

* **Fais une Sauvegarde** : Avant de modifier ou manipuler des données critiques, assure-toi de sauvegarder la base de données originale.
* **Utilise des Clés de Sécurité** : Si la base de données contient des informations sensibles, sécurise-la avec un mot de passe ou un chiffrement.
* **Analyse avec Prudence** : Les données comme les mots de passe hachés peuvent nécessiter des outils externes pour être analysées.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
