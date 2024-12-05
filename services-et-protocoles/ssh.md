# SSH

### **SSH - Guide Complet pour Utiliser et Sécuriser SSH**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

Le **SSH (Secure Shell)** est un protocole réseau sécurisé qui permet l’accès et le contrôle à distance des serveurs et des appareils. Il est également utilisé pour transférer des fichiers, exécuter des commandes à distance, et créer des tunnels sécurisés. SSH est un outil incontournable pour les administrateurs système, les développeurs, et les pentesters.

**Principales fonctionnalités :**

* Connexion sécurisée à distance.
* Transfert de fichiers via SCP ou SFTP.
* Tunneling sécurisé (port forwarding).
* Authentification par clé publique/privée.

***

### **🚀 Étape 1 : Installation de SSH**

**1. Installation sur Linux (Client SSH)**

SSH est souvent préinstallé sur les distributions Linux. Si ce n’est pas le cas :

```bash
sudo apt update
sudo apt install openssh-client
```

Pour le serveur SSH (si vous voulez autoriser des connexions entrantes) :

```bash
sudo apt install openssh-server
```

Activez et démarrez le serveur :

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

**2. Installation sur macOS**

SSH est intégré à macOS. Vous pouvez l’utiliser directement via le terminal :

```bash
ssh -V
```

**3. Installation sur Windows**

1. Installez **OpenSSH** :
   * Accédez à **Paramètres > Applications > Fonctionnalités Facultatives**.
   * Recherchez et installez **OpenSSH Client** et **OpenSSH Server**.
2. Utilisez le terminal PowerShell ou installez un client comme **PuTTY**.

***

### **🛠️ Étape 2 : Connexions SSH de Base**

**1. Se Connecter à un Serveur**

Commande :

```bash
ssh <username>@<host>
```

**Explications :**

* `<username>` : Nom d'utilisateur sur le serveur distant.
* `<host>` : Adresse IP ou nom de domaine du serveur.

**Exemple :**

```bash
ssh admin@192.168.1.10
```

***

**2. Spécifier un Port Différent**

Par défaut, SSH utilise le port **22**. Pour se connecter à un port personnalisé :

```bash
ssh -p <port> <username>@<host>
```

**Exemple :**

```bash
ssh -p 2222 admin@192.168.1.10
```

***

**3. Exécuter une Commande à Distance**

Vous pouvez exécuter une commande sur un serveur distant sans ouvrir une session interactive :

```bash
ssh <username>@<host> "<commande>"
```

**Exemple :**

```bash
ssh admin@192.168.1.10 "ls /var/www"
```

***

**4. Copier un Fichier avec SCP**

Commande :

```bash
scp <source> <username>@<host>:<destination>
```

**Exemple :**

```bash
scp localfile.txt admin@192.168.1.10:/home/admin/
```

Pour copier un fichier depuis un serveur distant :

```bash
scp admin@192.168.1.10:/home/admin/remotefile.txt ./local/
```

***

**5. Transférer des Fichiers avec SFTP**

Accédez à un serveur via SFTP :

```bash
sftp <username>@<host>
```

**Exemple :**

```bash
sftp admin@192.168.1.10
```

Naviguez dans les répertoires distants et locaux avec `cd` et `lcd`. Utilisez `get` et `put` pour télécharger ou téléverser des fichiers.

***

### **🔍 Étape 3 : Options Avancées**

**1. Utiliser des Clés SSH**

1.  **Générer une paire de clés** :

    ```bash
    ssh-keygen -t rsa -b 4096
    ```

    Cela génère une clé privée (`~/.ssh/id_rsa`) et une clé publique (`~/.ssh/id_rsa.pub`).
2.  **Copier la clé publique vers le serveur** :

    ```bash
    ssh-copy-id <username>@<host>
    ```

    Si `ssh-copy-id` n'est pas disponible, copiez-la manuellement :

    ```bash
    cat ~/.ssh/id_rsa.pub | ssh <username>@<host> "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
    ```
3.  **Se connecter avec la clé privée** :

    ```bash
    ssh -i ~/.ssh/id_rsa <username>@<host>
    ```

***

**2. Tunneling SSH (Port Forwarding)**

1.  **Forwarding Local** : Redirige un port local vers un port distant :

    ```bash
    ssh -L <local_port>:<remote_host>:<remote_port> <username>@<host>
    ```

    **Exemple :**

    ```bash
    ssh -L 8080:127.0.0.1:80 admin@192.168.1.10
    ```

    Accédez ensuite à `http://localhost:8080`.
2.  **Forwarding Distant** : Redirige un port sur le serveur distant vers un port local :

    ```bash
    ssh -R <remote_port>:<local_host>:<local_port> <username>@<host>
    ```

***

**3. Connexion via un Proxy**

Pour accéder à un serveur via un proxy SSH intermédiaire :

```bash
ssh -J <proxy_user>@<proxy_host> <username>@<destination_host>
```

**Exemple :**

```bash
ssh -J jumpserver@proxy.example.com admin@192.168.1.10
```

***

**4. Utiliser un Fichier de Configuration**

Simplifiez les connexions en configurant SSH dans `~/.ssh/config` :

```
Host myserver
    HostName 192.168.1.10
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_rsa
```

Connectez-vous simplement avec :

```bash
ssh myserver
```

***

### **🔧 Étape 4 : Sécurisation de SSH**

**1. Modifier le Port SSH**

Éditez le fichier de configuration du serveur SSH :

```bash
sudo nano /etc/ssh/sshd_config
```

Changez la ligne :

```
Port 2222
```

Redémarrez le service SSH :

```bash
sudo systemctl restart ssh
```

***

**2. Désactiver les Connexions par Mot de Passe**

Dans `/etc/ssh/sshd_config`, désactivez l’authentification par mot de passe :

```
PasswordAuthentication no
```

Activez uniquement l’authentification par clé publique.

***

**3. Restreindre l’Accès**

*   Limitez les utilisateurs autorisés :

    ```
    AllowUsers admin john
    ```
* Restreignez l’accès à des adresses IP spécifiques via un pare-feu.

***

**4. Activer le Journalisation**

Assurez-vous que les journaux SSH sont activés pour détecter les tentatives d'accès non autorisées :

```bash
sudo tail -f /var/log/auth.log
```

***

### **📋 Étape 5 : Outils Associés à SSH**

1. **Fail2Ban** :
   * Bloque les IP après plusieurs échecs de connexion SSH.
   *   Installez avec :

       ```bash
       sudo apt install fail2ban
       ```
2. **SSHuttle** :
   * Utilisé pour créer un VPN via SSH.
3. **SSH Agent** :
   *   Évite de retaper votre mot de passe pour les clés privées :

       ```bash
       ssh-agent bash
       ssh-add ~/.ssh/id_rsa
       ```

***

### **Résumé des Commandes Clés**

| Commande                                   | Description                                      |
| ------------------------------------------ | ------------------------------------------------ |
| `ssh <user>@<host>`                        | Connexion simple.                                |
| `ssh -p <port> <user>@<host>`              | Connexion sur un port personnalisé.              |
| `ssh-copy-id <user>@<host>`                | Installer une clé publique sur un serveur.       |
| `scp <source> <user>@<host>:<destination>` | Copier un fichier local vers un serveur distant. |
| `sftp <user>@<host>`                       | Transférer des fichiers via SFTP.                |
| `ssh -L <local_port>:<remote_host>:<port>` | Port forwarding local.                           |

***

Avec ce guide, vous avez une vue d’ensemble complète des fonctionnalités SSH. Que ce soit pour une connexion simple, des transferts sécurisés ou des tunnels avancés, SSH est un outil puissant et flexible. Assurez-vous de toujours le sécuriser pour protéger vos systèmes contre les accès non autorisés.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
