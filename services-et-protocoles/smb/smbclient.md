# Smbclient

### **SMBCLIENT : Accéder et interagir avec les partages SMB**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

### **Introduction**

`smbclient` est un outil de ligne de commande pour interagir avec les partages SMB sur un réseau. Il est utile pour accéder aux fichiers, télécharger, et envoyer des données via le protocole SMB.

***

### **1. Accéder à un partage SMB**

**Syntaxe de base**

Pour accéder à un partage SMB :

```bash
smbclient //[IP]/[SHARE] -U [USERNAME]
```

* **\[IP]** : Adresse IP de la machine cible.
* **\[SHARE]** : Nom du partage SMB.
* **-U \[USERNAME]** : Spécifie le nom d'utilisateur pour se connecter.

**Exemple : Connexion avec un mot de passe**

```bash
smbclient -U jean%123456 //10.10.10.10/share
```

* **jean** : Nom d'utilisateur.
* **123456** : Mot de passe associé à l'utilisateur.
* **share** : Nom du partage SMB.

**Exemple : Connexion sans identifiants**

Pour accéder à un partage SMB public (sans mot de passe) :

```bash
smbclient --no-pass //10.10.10.2/repertoire_public
```

***

### **2. Lister les partages disponibles**

Pour afficher tous les partages SMB disponibles sur une machine cible :

```bash
smbclient -L //[IP] -U [USERNAME]
```

**Exemple**

Lister les partages disponibles sur 10.10.10.2 pour l'utilisateur "user" :

```bash
smbclient -L //10.10.10.2 -U user
```

Si le partage est public ou sans authentification :

```bash
smbclient -L //10.10.10.2 --no-pass
```

***

### **3. Naviguer et interagir avec un partage**

**Connexion à un partage spécifique**

Accéder au partage "secret" en tant qu'utilisateur "suit" sur la machine 10.10.10.2 (port par défaut) :

```bash
smbclient //10.10.10.2/secret -U suit
```

**Exemple avec un port spécifique**

Si le service SMB utilise un port différent (par exemple, 445) :

```bash
smbclient //10.10.10.2/secret -U suit -p 445
```

***

### **4. Commandes utiles dans SMBCLIENT**

Une fois connecté à un partage SMB, voici les commandes courantes :

**Lister les fichiers**

```bash
ls
```

**Afficher des informations sur un fichier**

```bash
more [filename]
```

**Télécharger un fichier vers votre machine locale**

```bash
get [filename]
```

**Télécharger plusieurs fichiers**

```bash
mget *
```

**Envoyer un fichier vers la machine cible**

```bash
put [filename]
```

**Créer un répertoire**

```bash
mkdir [directory_name]
```

**Supprimer un fichier**

```bash
rm [filename]
```

**Quitter SMBCLIENT**

```bash
exit
```

***

### **5. Automatisation avec SMBCLIENT**

Pour automatiser certaines tâches avec `smbclient`, utilisez l'option `-c` pour exécuter une commande ou une série de commandes.

**Exemple : Télécharger tous les fichiers dans un répertoire**

Télécharger tous les fichiers depuis un partage SMB en désactivant l'invite de confirmation et en activant la récursivité :

```bash
smbclient //10.10.10.10/share -c "prompt off; recurse on; mget *" -U jean%123456
```

* **prompt off** : Désactive la demande de confirmation pour chaque fichier.
* **recurse on** : Active la récursivité pour parcourir les répertoires.

***

### **6. Cas pratiques**

**Télécharger un fichier spécifique**

Télécharger un fichier nommé `document.txt` depuis le partage "documents" :

```bash
smbclient //10.10.10.10/documents -U jean%123456 -c "get document.txt"
```

**Envoyer un fichier**

Envoyer un fichier nommé `upload.txt` sur le partage "uploads" :

```bash
smbclient //10.10.10.10/uploads -U jean%123456 -c "put upload.txt"
```

**Lister les fichiers dans un répertoire**

Lister les fichiers d'un partage SMB public :

```bash
smbclient --no-pass //10.10.10.10/public -c "ls"
```

**Télécharger uniquement les fichiers avec une extension spécifique**

Télécharger tous les fichiers `.docx` depuis un répertoire partagé :

```bash
smbclient //10.10.10.10/share -U jean%123456 -c "prompt off; recurse on; mget *.docx"
```

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
