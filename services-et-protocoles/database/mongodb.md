# MongoDB

### MongoDB : Exploitation d'une Base de Données

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

### **Introduction**

Si la base de données MongoDB est hébergée sur un serveur distant, vous pouvez y accéder via l'adresse IP du serveur. Voici un guide détaillé pour interagir avec cette base de données distante.

***

### 1. Vérifier l'Accès à la Base MongoDB

**Vérifiez que le Port MongoDB est Accessible**

MongoDB écoute par défaut sur le port **27017**. Testez si ce port est ouvert avec :

```bash
nmap -p 27017 <IP_SERVEUR>
```

Exemple de sortie :

```arduino
PORT     STATE SERVICE
27017/tcp open  mongodb
```

***

### 2. Connexion à la Base MongoDB Distante

**Avec Authentification Désactivée**

Si l’accès au serveur MongoDB ne nécessite pas d’authentification (souvent en mode non sécurisé ou mal configuré) :

```bash
mongo --host <IP_SERVEUR> --port 27017
```

Exemple :

```bash
mongo --host 192.168.1.10 --port 27017
```

**Avec Authentification Active**

Si une authentification est nécessaire (via un utilisateur et un mot de passe) :

```bash
mongo --host <IP_SERVEUR> --port 27017 -u <UTILISATEUR> -p <MOT_DE_PASSE> --authenticationDatabase <BASE_ADMIN>
```

Exemple :

```bash
mongo --host 192.168.1.10 --port 27017 -u admin -p admin123 --authenticationDatabase admin
```

***

### 3. Découvrir et Explorer les Bases de Données

**Lister les Bases de Données**

Une fois connecté au serveur distant :

```javascript
show dbs
```

Exemple de sortie :

```arduino
admin       0.000GB
config      0.000GB
remoteDB    0.001GB
```

**Sélectionner une Base de Données**

Pour accéder à une base de données spécifique :

```javascript
use remoteDB
```

Exemple de sortie :

```css
switched to db remoteDB
```

***

### 4. Explorer les Collections

**Lister les Collections**

Pour afficher les collections disponibles dans la base de données sélectionnée :

```javascript
show collections
```

Exemple de sortie :

```bash
users
orders
products
```

**Afficher un Exemple de Document**

Pour examiner un document de la collection :

```javascript
db.users.findOne()
```

Exemple de sortie :

```json
{
  "_id": ObjectId("648fc62c9a93e0dfd9234bf2"),
  "name": "Alice",
  "email": "alice@example.com",
  "age": 30
}
```

***

### 5. Manipuler les Données

**Afficher Tous les Documents d’une Collection**

Pour afficher toutes les données d'une collection :

```javascript
db.users.find()
```

Exemple de sortie :

```json
[
  { "_id": ObjectId("648fc62c9a93e0dfd9234bf2"), "name": "Alice", "email": "alice@example.com", "age": 30 },
  { "_id": ObjectId("648fc62c9a93e0dfd9234bf3"), "name": "Bob", "email": "bob@example.com", "age": 25 }
]
```

**Filtrer les Documents**

Pour rechercher des documents spécifiques :

```javascript
db.users.find({ "age": { $gte: 30 } })
```

Exemple de sortie :

```json
[
  { "_id": ObjectId("648fc62c9a93e0dfd9234bf2"), "name": "Alice", "email": "alice@example.com", "age": 30 }
]
```

**Ajouter un Nouveau Document**

Pour insérer un document dans une collection :

```javascript
db.users.insertOne({
  name: "Charlie",
  email: "charlie@example.com",
  age: 28
})
```

Exemple de sortie :

```css
{
  acknowledged: true,
  insertedId: ObjectId("648fc62c9a93e0dfd9234bf4")
}
```

**Modifier un Document**

Pour mettre à jour un document existant :

```javascript
db.users.updateOne(
  { "name": "Charlie" },
  { $set: { "age": 29 } }
)
```

Exemple de sortie :

```yaml
{
  acknowledged: true,
  matchedCount: 1,
  modifiedCount: 1
}
```

**Supprimer un Document**

Pour supprimer un document spécifique :

```javascript
db.users.deleteOne({ "name": "Charlie" })
```

Exemple de sortie :

```yaml
{ acknowledged: true, deletedCount: 1 }
```

***

### 6. Sauvegarder et Restaurer les Données

**Exporter une Collection en JSON**

Pour exporter les données d'une collection dans un fichier JSON :

```bash
mongoexport --host <IP_SERVEUR> --port 27017 --db remoteDB --collection users --out users.json
```

Exemple :

```bash
mongoexport --host 192.168.1.10 --port 27017 --db remoteDB --collection users --out users.json
```

**Importer des Données JSON**

Pour importer des données dans une collection :

```bash
mongoimport --host <IP_SERVEUR> --port 27017 --db remoteDB --collection users --file users.json
```

***

### 7. Bonnes Pratiques pour Travailler avec MongoDB

1. **Sécurisez la Connexion** :
   * Configurez **TLS/SSL** pour chiffrer les communications.
   * Utilisez un VPN ou un tunnel SSH pour sécuriser l'accès.
2. **Authentification** :
   *   Activez l'authentification en configurant `mongod.conf` :

       ```yaml
       security:
         authorization: enabled
       ```
   * Créez des utilisateurs avec des rôles spécifiques.
3. **Restreindre l'Accès Réseau** :
   *   Configurez l'adresse IP de liaison pour limiter les connexions externes :

       ```yaml
       net:
         bindIp: 127.0.0.1,192.168.1.10
       ```
4. **Effectuez des Sauvegardes** :
   *   Utilisez `mongodump` pour sauvegarder régulièrement vos données :

       ```bash
       mongodump --host <IP_SERVEUR> --port 27017 --out /path/to/backup
       ```
5. **Surveillez l’Activité** :
   * Analysez les logs MongoDB pour détecter toute activité suspecte.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
