# NetExec

## **Netexec - Guide Complet pour le Pentest Multi-Protocole**

***

⚠️ **Avertissement :** Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**Netexec** est un outil puissant pour interagir avec divers protocoles réseau tels que **LDAP**, **SMB**, **SSH**, **FTP**, **WMI**, **WinRM**, **RDP**, **VNC**, **MSSQL**, et **NFS**. Il permet aux pentesters de tester des identifiants (mots de passe ou hash NTLM), d’énumérer des ressources, et d’exploiter des vulnérabilités dans des environnements réseau complexes, y compris les domaines Active Directory (AD).

Ce guide décrit chaque fonctionnalité en détail avec des exemples pratiques et exhaustifs.

***

### **🚀 Étape 1 : Installation de Netexec**

**1.1 Prérequis**

* Python 3.6 ou une version ultérieure.
* Git pour cloner le dépôt.

**1.2 Installation sur Linux/MacOS**

1.  Clonez le dépôt officiel de Netexec :

    ```bash
    git clone https://github.com/Pennyw0rth/NetExec.git
    cd NetExec
    ```
2.  Créez un environnement virtuel Python pour isoler les dépendances :

    ```bash
    python3 -m venv netexec_env
    source netexec_env/bin/activate
    ```
3.  Installez les dépendances nécessaires :

    ```bash
    pip install -r requirements.txt
    ```
4.  Vérifiez que Netexec fonctionne correctement :

    ```bash
    python nxc --help
    ```

***

### **🔧 Étape 2 : Protocole par Protocole**

### **2.1 LDAP**

**Description :** LDAP (Lightweight Directory Access Protocol) est un protocole standard utilisé pour interroger et modifier des informations dans les services d’annuaire, comme Active Directory.

**Commandes Clés :**

*   **Lister les utilisateurs** :

    ```bash
    nxc ldap <IP> -u <user> -p <password> --users
    ```
*   **Lister les utilisateurs (avec hash NTLM)** :

    ```bash
    nxc ldap <IP> -u <user> -H <hash> --users
    ```
*   **Identifier les utilisateurs actifs uniquement** :

    ```bash
    nxc ldap <IP> -u <user> -p <password> --active-users
    ```
*   **Lister les groupes** :

    ```bash
    nxc ldap <IP> -u <user> -p <password> --groups
    ```
*   **Lister les membres d’un groupe** :

    ```bash
    nxc ldap <IP> -u <user> -p <password> --group-members "GroupName"
    ```
*   **ASREPRoasting** :

    ```bash
    nxc ldap <IP> -u <user_list.txt> -p '' --asreproast output.txt
    ```
*   **Requête LDAP spécifique** : Pour un utilisateur particulier :

    ```bash
    nxc ldap <IP> -u <user> -p <password> --query "(sAMAccountName=john)" ""
    ```
*   **Lister les contrôleurs de domaine** :

    ```bash
    nxc ldap <IP> -u <user> -p <password> --domain-controllers
    ```
*   **Récupérer le SID du domaine** :

    ```bash
    nxc ldap <IP> -u <user> -p <password> --domain-sid
    ```
*   **Requête personnalisée LDAP avec filtre** :

    ```bash
    nxc ldap <IP> -u <user> -p <password> --query "(objectClass=computer)" "cn"
    ```
*   **Forcer l'utilisation de Kerberos (-k)** :

    ```bash
    nxc ldap <IP> -u <user> -p <password> -k --users
    ```

***

### **2.2 SMB**

**Description :** SMB (Server Message Block) est utilisé pour l’accès partagé aux fichiers, imprimantes et ressources réseau.

**Commandes Clés :**

*   **Lister les partages SMB accessibles** :

    ```bash
    nxc smb <IP> -u <user> -p <password> --shares
    ```
*   **Lister les partages avec hash NTLM** :

    ```bash
    nxc smb <IP> -u <user> -H <hash> --shares
    ```
*   **Explorer un partage** :

    ```bash
    nxc smb <IP> -u <user> -p <password> --list share_name
    ```
*   **Lister les permissions d’un partage** :

    ```bash
    nxc smb <IP> -u <user> -p <password> --share-permissions share_name
    ```
*   **Télécharger un fichier** :

    ```bash
    nxc smb <IP> -u <user> -p <password> --get share_name/file.txt ./local_folder
    ```
*   **Téléverser un fichier** :

    ```bash
    nxc smb <IP> -u <user> -p <password> --put ./local_file.txt share_name/file.txt
    ```
*   **Exécuter une commande sur un hôte distant (PsExec via SMB)** :

    ```bash
    nxc smb <IP> -u <user> -p <password> --exec "whoami"
    ```
*   **Lister les sessions ouvertes sur le partage** :

    ```bash
    nxc smb <IP> -u <user> -p <password> --sessions
    ```
*   **Récupérer des fichiers sensibles en masse** :

    ```bash
    nxc smb <IP> -u <user> -p <password> --recursive-download share_name ./local_folder
    ```
*   **Utiliser Kerberos (-k)** :

    ```bash
    nxc smb <IP> -u <user> -p <password> -k --shares
    ```

***

### **2.3 SSH**

**Description :** SSH (Secure Shell) permet un accès distant sécurisé aux systèmes.

**Commandes Clés :**

*   **Tester des identifiants SSH** :

    ```bash
    nxc ssh <IP> -u <user> -p <password>
    ```
*   **Tester des identifiants SSH avec hash NTLM** :

    ```bash
    nxc ssh <IP> -u <user> -H <hash>
    ```
*   **Exécuter une commande distante** :

    ```bash
    nxc ssh <IP> -u <user> -p <password> --exec "ls -al"
    ```
*   **Lister les utilisateurs locaux** :

    ```bash
    nxc ssh <IP> -u <user> -p <password> --list-users
    ```
*   **Téléverser un fichier via SCP** :

    ```bash
    nxc ssh <IP> -u <user> -p <password> --scp ./local_file.txt /remote/path
    ```
*   **Ouvrir une session interactive** :

    ```bash
    nxc ssh <IP> -u <user> -p <password> --interactive
    ```
*   **Redémarrer le système à distance** :

    ```bash
    nxc ssh <IP> -u <user> -p <password> --exec "sudo reboot"
    ```

***

### **2.4 FTP**

**Description :** FTP (File Transfer Protocol) est utilisé pour transférer des fichiers entre des systèmes.

**Commandes Clés :**

*   **Lister les fichiers sur le serveur** :

    ```bash
    nxc ftp <IP> -u <user> -p <password> --list
    ```
*   **Télécharger un fichier** :

    ```bash
    nxc ftp <IP> -u <user> -p <password> --get remote_file ./local_folder
    ```
*   **Téléverser un fichier** :

    ```bash
    nxc ftp <IP> -u <user> -p <password> --put ./local_file.txt /remote/path
    ```
*   **Supprimer un fichier distant** :

    ```bash
    nxc ftp <IP> -u <user> -p <password> --delete remote_file
    ```
*   **Vérifier les permissions d’un fichier** :

    ```bash
    nxc ftp <IP> -u <user> -p <password> --file-permissions remote_file
    ```

***

### **2.5 WMI**

**Description :** WMI (Windows Management Instrumentation) est utilisé pour gérer et interagir avec des systèmes Windows.

**Commandes Clés :**

*   **Exécuter une commande** :

    ```bash
    nxc wmi <IP> -u <user> -p <password> --exec "whoami"
    ```
*   **Lister les processus** :

    ```bash
    nxc wmi <IP> -u <user> -p <password> --process-list
    ```
*   **Arrêter un processus** :

    ```bash
    nxc wmi <IP> -u <user> -p <password> --kill-process <process_id>
    ```
*   **Lister les services en cours d’exécution** :

    ```bash
    nxc wmi <IP> -u <user> -p <password> --services
    ```
*   **Démarrer ou arrêter un service** :

    ```bash
    nxc wmi <IP> -u <user> -p <password> --service-control "ServiceName" start|stop
    ```
*   **Forcer l'utilisation de Kerberos (-k)** :

    ```
    nxc wmi <IP> -u <user> -p <password> -k --exec "hostname"
    ```

***

### **2.6 WinRM**

**Description :** WinRM (Windows Remote Management) est un protocole pour l’administration à distance des systèmes Windows.

**Commandes Clés :**

*   **Exécuter une commande via PowerShell** :

    ```bash
    nxc winrm <IP> -u <user> -p <password> --exec "ipconfig"
    ```
*   **Déployer un script PowerShell** :

    ```bash
    nxc winrm <IP> -u <user> -p <password> --script ./local_script.ps1
    ```
*   **Ouvrir une session interactive PowerShell** :

    ```bash
    nxc winrm <IP> -u <user> -p <password> --interactive
    ```
*   **Lister les journaux d’événements** :

    ```bash
    nxc winrm <IP> -u <user> -p <password> --event-logs
    ```

***

### **2.7 RDP**

**Description :** RDP (Remote Desktop Protocol) est utilisé pour accéder à des sessions distantes graphiques.

**Commandes Clés :**

*   **Vérifier l’accès RDP** :

    ```bash
    nxc rdp <IP> -u <user> -p <password> --check
    ```
*   **Forcer une déconnexion RDP** :

    ```bash
    nxc rdp <IP> -u <user> -p <password> --disconnect
    ```

***

### **2.8 VNC**

**Description :** VNC (Virtual Network Computing) permet une connexion distante avec une interface graphique.

**Commandes Clés :**

*   **Tester un accès VNC** :

    ```bash
    nxc vnc <IP> -u <user> -p <password>
    ```

***

### **2.9 MSSQL**

**Description :** MSSQL (Microsoft SQL Server) est un système de gestion de bases de données.

**Commandes Clés :**

*   **Tester des identifiants MSSQL** :

    ```bash
    nxc mssql <IP> -u <user> -p <password>
    ```
*   **Exécuter une requête SQL** :

    ```bash
    nxc mssql <IP> -u <user> -p <password> --query "SELECT name FROM sys.databases"
    ```
*   **Lister les utilisateurs SQL** :

    ```bash
    nxc mssql <IP> -u <user> -p <password> --list-users
    ```

***

### **2.10 NFS**

**Description :** NFS (Network File System) est utilisé pour accéder à des fichiers stockés sur un serveur Unix/Linux.

**Commandes Clés :**

*   **Lister les partages NFS disponibles** :

    ```bash
    nxc nfs <IP> --list
    ```
*   **Monter un partage NFS** :

    ```bash
    nxc nfs <IP> --mount share_name ./local_mount
    ```
*   **Démonter un partage NFS** :

    ```bash
    nxc nfs <IP> --unmount ./local_mount
    ```

***

### 📖 **Bonnes Pratiques**

1. **Toujours avoir des autorisations écrites** : Tester un système sans autorisation explicite est illégal.
2. **Limiter l’impact des scans** : Utiliser des options pour ralentir les requêtes ou réduire la charge sur les services.
3. **Analyser les résultats efficacement** : Croiser les données obtenues avec d’autres outils pour mieux comprendre les failles potentielles.
4. **Protéger les données collectées** :
   * Sauvegardez les résultats de manière sécurisée.
   * Chiffrez les fichiers de résultats pour éviter toute fuite accidentelle.
5. **Documenter vos actions** :
   * Prenez des notes détaillées de vos commandes et résultats pour assurer une traçabilité.

***

### **Résumé des Commandes Clés**

| Protocole | Commande Exemple                               | Description                           |
| --------- | ---------------------------------------------- | ------------------------------------- |
| LDAP      | `nxc ldap <IP> --users`                        | Lister les utilisateurs.              |
| SMB       | `nxc smb <IP> --shares`                        | Lister les partages SMB.              |
| SSH       | `nxc ssh <IP> --exec "ls"`                     | Exécuter une commande distante.       |
| FTP       | `nxc ftp <IP> --list`                          | Lister les fichiers d’un serveur FTP. |
| WMI       | `nxc wmi <IP> --exec "whoami"`                 | Exécuter une commande avec WMI.       |
| WinRM     | `nxc winrm <IP> --exec "ipconfig"`             | Exécuter une commande via WinRM.      |
| RDP       | `nxc rdp <IP> --check`                         | Vérifier l’accès RDP.                 |
| VNC       | `nxc vnc <IP>`                                 | Tester un accès VNC.                  |
| MSSQL     | `nxc mssql <IP> --query "SELECT * FROM users"` | Exécuter une requête SQL.             |
| NFS       | `nxc nfs <IP> --list`                          | Lister les partages NFS.              |

***

### Ressources Utiles:

[https://www.netexec.wiki/](https://www.netexec.wiki/)

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
