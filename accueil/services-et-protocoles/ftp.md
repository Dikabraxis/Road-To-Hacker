# FTP

#### **FTP (File Transfer Protocol)**

Le protocole FTP (File Transfer Protocol) est un protocole standard utilisé pour transférer des fichiers entre un client et un serveur sur un réseau. Voici un tutoriel sur l’utilisation d’outils FTP via la ligne de commande pour interagir avec des serveurs FTP.

***

#### **Connexion à un Serveur FTP**

Pour se connecter à un serveur FTP, utilise la commande suivante :

```bash
ftp [IP] [port]
```

**Options courantes :**

* `[IP]` : Adresse IP ou nom de domaine du serveur FTP.
* `[port]` : Port utilisé par le service FTP (par défaut, 21).

Exemple de connexion :

```bash
ftp 192.168.1.10
```

#### **Authentification**

Une fois connecté, tu seras invité à entrer :

* **Nom d'utilisateur** (login).
* **Mot de passe**.

Si le serveur autorise une connexion anonyme (sans identifiants), tu peux utiliser :

```bash
ftp -n 192.168.1.10
```

Puis entrer `anonymous` comme nom d’utilisateur et un mot de passe vide ou une adresse e-mail fictive.

***

#### **Commandes FTP de Base**

Une fois connecté au serveur FTP, voici quelques commandes de base :

| Commande          | Description                                                            |
| ----------------- | ---------------------------------------------------------------------- |
| `ls`              | Liste les fichiers et dossiers du répertoire distant.                  |
| `pwd`             | Affiche le répertoire courant sur le serveur distant.                  |
| `cd <directory>`  | Change le répertoire courant sur le serveur distant.                   |
| `lcd <directory>` | Change le répertoire local où les fichiers seront téléchargés.         |
| `get <file>`      | Télécharge un fichier unique depuis le serveur vers la machine locale. |
| `mget <files>`    | Télécharge plusieurs fichiers à la fois.                               |
| `put <file>`      | Envoie un fichier de la machine locale vers le serveur.                |
| `mput <files>`    | Envoie plusieurs fichiers à la fois.                                   |
| `bye` ou `quit`   | Termine la session FTP.                                                |

***

#### **Exemples de Scénarios**

**1. Télécharger un Fichier depuis un Serveur**

Pour télécharger un fichier unique depuis un serveur FTP vers ta machine locale :

```bash
get fichier.txt
```

Pour télécharger plusieurs fichiers, utilise :

```bash
mget *.txt
```

Explication :

* `mget *.txt` télécharge tous les fichiers `.txt` disponibles dans le répertoire courant.

**2. Envoyer un Fichier vers un Serveur**

Pour envoyer un fichier depuis ta machine locale vers le serveur :

```bash
put fichier_local.txt
```

Pour envoyer plusieurs fichiers :

```bash
mput *.txt
```

Explication :

* `mput *.txt` télécharge tous les fichiers `.txt` de ton répertoire local vers le répertoire distant.

**3. Naviguer entre Répertoires**

*   Changer le répertoire distant :

    ```bash
    cd /path/to/remote/directory
    ```
*   Changer le répertoire local (où les fichiers sont téléchargés) :

    ```bash
    lcd /path/to/local/directory
    ```

**4. Télécharger tous les Fichiers d’un Répertoire**

Pour télécharger tous les fichiers d’un répertoire sans être interrompu par des confirmations :

```bash
prompt off
mget *
```

***

#### **Connexion FTP via un Nom d’Utilisateur et un Mot de Passe**

Si tu as des identifiants spécifiques, utilise la commande suivante pour te connecter directement :

```bash
ftp -n <IP>
```

Puis, entre les commandes suivantes :

```bash
quote USER <username>
quote PASS <password>
```

Explication :

* `quote USER` : Spécifie le nom d’utilisateur.
* `quote PASS` : Spécifie le mot de passe.

***

#### **FTP via un Port Non Standard**

Si le service FTP utilise un port différent du port standard (21), spécifie le port dans la commande :

```bash
ftp <IP> <port>
```

Exemple :

```bash
ftp 192.168.1.10 2221
```

***

#### **FTP Passif vs Actif**

FTP peut fonctionner en mode actif ou passif. Si tu rencontres des problèmes de connexion ou de transfert, essaye de passer en mode passif :

```bash
passive
```

Explication :

* Le mode passif est utile si tu es derrière un pare-feu ou un NAT.

***

#### **Exécution Automatisée avec un Script**

Pour automatiser les transferts FTP, tu peux créer un script :

```bash
#!/bin/bash
ftp -n <<EOF
open 192.168.1.10
user <username> <password>
lcd /path/to/local/directory
cd /path/to/remote/directory
mget *.txt
bye
EOF
```

***

#### **Bonnes Pratiques**

* **Toujours chiffrer les connexions FTP** : Utilise `SFTP` ou `FTPS` si possible, car FTP envoie les informations d’identification en clair.
* **Limiter les permissions** : Vérifie que les partages FTP ne permettent pas un accès anonyme si cela n’est pas intentionnel.
* **Vérifier les journaux** : Surveille les journaux du serveur FTP pour détecter toute activité suspecte.

***

#### **Alternatives Modernes**

Si tu souhaites utiliser un protocole plus sécurisé, privilégie SFTP (via SSH) :

```bash
sftp <username>@<IP>
```

Ou utilise FTPS (FTP over SSL/TLS) si supporté par le serveur.
