# Evil-WinRM

### **Evil-WinRM - Guide Complet pour Exploiter un Accès Windows avec WinRM**

***

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**Evil-WinRM** est un outil permettant d’exploiter le protocole **WinRM (Windows Remote Management)** pour accéder à des systèmes Windows. Il offre une shell interactive, facilite le transfert de fichiers, et permet l’exécution de commandes PowerShell sur une machine cible. C’est un outil incontournable pour les pentests lorsque des identifiants valides sont obtenus.

***

### **🚀 Étape 1 : Installation d’Evil-WinRM**

**1.1 Pré-requis**

* Un système Linux avec Ruby installé.

**1.2 Installation**

1.  Installez Evil-WinRM via Ruby :

    ```bash
    gem install evil-winrm
    ```
2.  Vérifiez l’installation :

    ```bash
    evil-winrm
    ```

***

### **🛠️ Étape 2 : Utilisation de Base**

**2.1 Se Connecter à un Serveur Windows**

Utilisez des identifiants valides pour établir une connexion :

```bash
evil-winrm -i <IP> -u <username> -p <password>
```

**Exemple** :

```bash
evil-winrm -i 192.168.1.10 -u Administrator -p Password123
```

**Explications :**

* `-i <IP>` : Adresse IP de la cible.
* `-u <username>` : Nom d’utilisateur.
* `-p <password>` : Mot de passe.

***

**2.2 Utiliser une Clé Privée**

Si vous disposez d’une clé privée pour l’utilisateur cible :

```bash
evil-winrm -i <IP> -u <username> -k <path_to_key>
```

**Exemple** :

```bash
evil-winrm -i 192.168.1.10 -u Administrator -k id_rsa
```

***

**2.3 Transférer des Fichiers**

**Télécharger un fichier depuis la cible :**

```bash
download <remote_file>
```

**Exemple** :

```bash
download C:\Users\Administrator\Documents\important.txt
```

**Envoyer un fichier vers la cible :**

```bash
upload <local_file> <remote_path>
```

**Exemple** :

```bash
upload payload.exe C:\Temp\payload.exe
```

***

**2.4 Exécuter des Commandes**

Exécutez directement des commandes PowerShell :

```bash
<command>
```

**Exemple** :

```bash
Get-Process
```

***

### **🔍 Étape 3 : Techniques Avancées**

**3.1 Charger des Scripts PowerShell**

Pour exécuter un script PowerShell sur la cible :

1.  Téléchargez le script sur la cible :

    ```bash
    upload script.ps1
    ```
2.  Exécutez-le :

    ```bash
    powershell -File script.ps1
    ```

***

**3.2 Obtenir des Informations Système**

*   **Lister les utilisateurs locaux :**

    ```powershell
    Get-LocalUser
    ```
*   **Lister les groupes locaux :**

    ```powershell
    Get-LocalGroup
    ```

***

### **📖 Bonnes Pratiques**

1. **Obtenir des Autorisations**
   * N'utilisez Evil-WinRM que dans un cadre légal avec l’autorisation du propriétaire.
2. **Sécuriser les Identifiants**
   * Utilisez un mot de passe fort et évitez de stocker les identifiants en clair.
3. **Analyser les Logs**
   * Vérifiez les logs d’accès sur la cible pour détecter des activités suspectes.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
