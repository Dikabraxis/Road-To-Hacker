# RSYNC

### **rsync : Utilisation Complète avec un Serveur rsync (Port 873)**

`rsync` permet également de travailler avec un serveur configuré en mode **daemon** (protocole rsync natif), qui fonctionne indépendamment de SSH et écoute généralement sur le port **873**. Voici un guide complet pour interagir avec un serveur distant configuré de cette manière.

***

### **1. Présentation de la Commande `rsync` pour un Serveur rsync**

La syntaxe de base pour interagir avec un serveur rsync en mode daemon est la suivante :

```bash
rsync [OPTIONS] rsync://<IP_SERVEUR>:873/<MODULE>/<CHEMIN> <DESTINATION>
```

* **`rsync://`** : indique que le protocole natif rsync est utilisé.
* **`<IP_SERVEUR>`** : adresse IP ou nom de domaine du serveur rsync.
* **`873`** : port utilisé par défaut par le daemon rsync (souvent implicite, mais spécifiable si nécessaire).
* **`<MODULE>`** : répertoire ou module exposé par le serveur rsync.
* **`<CHEMIN>`** : chemin relatif dans le module (optionnel).
* **`<DESTINATION>`** : chemin local où les fichiers seront sauvegardés.

***

### **2. Vérifications Préliminaires**

#### **2.1. Lister les Modules Disponibles**

Pour connaître les modules accessibles sur le serveur :

```bash
rsync rsync://<IP_SERVEUR>/
```

Exemple :

```bash
rsync rsync://10.129.228.37/
```

Sortie typique :

```arduino
public          Répertoire public accessible
private         Répertoire restreint
```

#### **2.2. Explorer un Module**

Vous pouvez explorer le contenu d'un module spécifique avant de télécharger quoi que ce soit :

```bash
rsync rsync://<IP_SERVEUR>/<MODULE>/
```

Exemple :

```bash
rsync rsync://10.129.228.37/public/
```

Sortie typique :

```
flag.txt
readme.txt
```

***

### **3. Transférer des Fichiers Depuis un Serveur rsync**

#### **3.1. Télécharger un Fichier Spécifique**

Pour récupérer un fichier particulier depuis un module sur le serveur :

```bash
rsync -avz rsync://<IP_SERVEUR>/<MODULE>/<FICHIER> <DESTINATION>
```

Exemple :

```bash
rsync -avz rsync://10.129.228.37/public/flag.txt .
```

* **`flag.txt`** : fichier à télécharger.
* **`.`** : répertoire courant comme destination.

***

#### **3.2. Télécharger un Répertoire Complet**

Pour copier tout le contenu d'un répertoire dans un module :

```bash
rsync -avz rsync://<IP_SERVEUR>/<MODULE>/<REPERTOIRE>/ <DESTINATION>
```

Exemple :

```bash
rsync -avz rsync://10.129.228.37/public/ ./local_public/
```

***

#### **3.3. Télécharger Tout un Module**

Pour télécharger tous les fichiers exposés par un module :

```bash
rsync -avz rsync://<IP_SERVEUR>/<MODULE>/ <DESTINATION>
```

Exemple :

```bash
rsync -avz rsync://10.129.228.37/public/ ./local_public/
```

***

### **4. Transférer des Fichiers Vers un Serveur rsync**

Si le serveur autorise les transferts de fichiers (non `read-only`), vous pouvez envoyer des fichiers vers le serveur.

#### **4.1. Envoyer un Fichier**

```bash
rsync -avz file.txt rsync://<IP_SERVEUR>/<MODULE>/
```

Exemple :

```bash
rsync -avz file.txt rsync://10.129.228.37/public/
```

#### **4.2. Envoyer un Répertoire**

```bash
rsync -avz /local/dossier/ rsync://<IP_SERVEUR>/<MODULE>/dossier/
```

Exemple :

```bash
rsync -avz /myfiles/ rsync://10.129.228.37/public/myfiles/
```

***

### **5. Options Utiles avec un Serveur rsync**

#### **5.1. Afficher les Statistiques**

Ajoutez les options suivantes pour obtenir des informations sur le transfert :

* **`--progress`** : montre l'état du transfert en temps réel.
* **`--stats`** : fournit un résumé détaillé après le transfert.

Exemple :

```bash
rsync -avz --progress --stats rsync://10.129.228.37/public/ ./local_public/
```

***

#### **5.2. Exclure Certains Fichiers**

Vous pouvez exclure certains fichiers ou dossiers pour affiner vos transferts :

*   Exclure un fichier spécifique :

    ```bash
    rsync -avz --exclude "temp.log" rsync://10.129.228.37/public/ ./local_public/
    ```
*   Exclure plusieurs fichiers ou motifs :

    ```bash
    rsync -avz --exclude "*.log" --exclude "backup/" rsync://10.129.228.37/public/ ./local_public/
    ```

***

#### **5.3. Limiter la Bande Passante**

Pour limiter la bande passante utilisée par `rsync`, utilisez `--bwlimit` (en Ko/s) :

```bash
rsync -avz --bwlimit=500 rsync://10.129.228.37/public/ ./local_public/
```

Cela limite la vitesse de transfert à 500 Ko/s.

***

#### **5.4. Tester Avant de Transférer**

Pour simuler un transfert sans copier réellement les fichiers, utilisez `--dry-run` :

```bash
rsync -avz --dry-run rsync://10.129.228.37/public/ ./local_public/
```

Cela permet de vérifier vos commandes avant d'exécuter l'opération.

***

### **6. Supprimer les Fichiers Supplémentaires**

Pour synchroniser un répertoire local avec le contenu distant, en supprimant les fichiers supplémentaires, utilisez l’option `--delete` :

```bash
rsync -avz --delete rsync://10.129.228.37/public/ ./local_public/
```

⚠️ **Attention :** Les fichiers non présents dans le module distant seront supprimés dans le répertoire local.

***

### **7. Automatiser avec Cron**

Pour automatiser les transferts via rsync, ajoutez une tâche planifiée dans `cron` :

1.  Éditez le fichier `crontab` :

    ```bash
    crontab -e
    ```
2.  Ajoutez une ligne pour exécuter rsync automatiquement, par exemple tous les jours à 3h du matin :

    ```bash
    0 3 * * * rsync -avz rsync://10.129.228.37/public/ ./local_public/ >> /var/log/rsync.log 2>&1
    ```

***

### **8. Bonnes Pratiques**

1. **Toujours Tester avec `--dry-run`** avant d'exécuter une commande critique.
2. **Surveillez les Transferts :** Ajoutez `--progress` pour suivre l’état des transferts.
3. **Sécurisez le Réseau :**
   * Si le serveur rsync est sur un réseau non sécurisé, encapsulez la connexion avec un VPN ou un tunnel SSH.
4. **Effectuez des Sauvegardes :**
   * Utilisez `rsync` régulièrement pour maintenir des sauvegardes à jour.
   * Combinez avec des options comme `--delete` avec précaution.
