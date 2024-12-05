# IMAP/POP3

### **IMAP et POP3 - Guide Complet pour Comprendre et Exploiter les Protocoles de Messagerie**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

Les protocoles **IMAP (Internet Message Access Protocol)** et **POP3 (Post Office Protocol 3)** sont utilisés pour accéder aux courriels stockés sur un serveur distant. Bien que leur objectif soit similaire, ils diffèrent dans leur mode de fonctionnement :

* **IMAP** : Permet une gestion à distance des courriels, idéal pour accéder à la même boîte aux lettres depuis plusieurs appareils.
* **POP3** : Télécharge les courriels sur un appareil local et les supprime généralement du serveur.

Ces protocoles sont souvent des cibles lors de tests d’intrusion pour vérifier des failles de configuration ou récupérer des informations sensibles.

***

### **1. IMAP - Internet Message Access Protocol**

***

**1.1 Fonctionnement de Base**

* **Port 143** : IMAP standard (non chiffré).
* **Port 993** : IMAP avec SSL/TLS (sécurisé).
* Les courriels restent sur le serveur, sauf s’ils sont explicitement supprimés.

***

**1.2 Commandes IMAP de Base**

1.  **Connexion au Serveur** Avec **Telnet** :

    ```bash
    telnet <server_ip> 143
    ```

    Ou avec **OpenSSL** (pour IMAP sécurisé) :

    ```bash
    openssl s_client -connect <server_ip>:993
    ```
2.  **Authentification** Une fois connecté, utilisez les commandes suivantes :

    ```bash
    a login username password
    ```

    **Exemple** :

    ```bash
    a login user@example.com mypassword
    ```
3.  **Lister les Boîtes aux Lettres** Commande :

    ```bash
    a list "" "*"
    ```

    Cela renvoie une liste de dossiers (ex. INBOX, SENT, etc.).
4.  **Sélectionner une Boîte aux Lettres** Commande :

    ```bash
    a select inbox
    ```

    Cela ouvre la boîte de réception pour lecture.
5.  **Lister les Messages** Commande :

    ```bash
    a fetch 1:* (FLAGS BODY[HEADER])
    ```

    Cela affiche les en-têtes des messages dans la boîte.
6.  **Télécharger un Message** Commande :

    ```bash
    a fetch <message_id> body[text]
    ```

    Remplacez `<message_id>` par le numéro du message.
7.  **Déconnexion** Commande :

    ```bash
    a logout
    ```

***

**1.3 Tests et Pentest IMAP**

1.  **Scanner les Ports** Avec **Nmap**, détectez les services IMAP :

    ```bash
    nmap -p 143,993 --script imap-capabilities <target>
    ```

    **imap-capabilities** énumère les capacités IMAP du serveur.
2.  **Brute-Force des Identifiants** Utilisez **Hydra** pour brute-forcer les identifiants :

    ```bash
    hydra -L usernames.txt -P passwords.txt -s 143 -f <target> imap
    ```
3.  **Exploiter une Mauvaise Configuration** Si l'authentification anonyme est activée, essayez de lister les dossiers :

    ```bash
    telnet <server_ip> 143
    a list "" "*"
    ```
4.  **Énumération des Utilisateurs** Certains serveurs IMAP permettent d’énumérer les utilisateurs par défaut avec la commande `LOGIN`. Testez avec :

    ```bash
    telnet <server_ip> 143
    a login <username> dummy_password
    ```

***

### **2. POP3 - Post Office Protocol 3**

***

**2.1 Fonctionnement de Base**

* **Port 110** : POP3 standard (non chiffré).
* **Port 995** : POP3 avec SSL/TLS (sécurisé).
* Les courriels sont téléchargés sur le client et généralement supprimés du serveur.

***

**2.2 Commandes POP3 de Base**

1.  **Connexion au Serveur** Avec **Telnet** :

    ```bash
    telnet <server_ip> 110
    ```

    Ou avec **OpenSSL** :

    ```bash
    openssl s_client -connect <server_ip>:995
    ```
2.  **Authentification** Commande :

    ```bash
    USER username
    PASS password
    ```

    **Exemple** :

    ```bash
    USER user@example.com
    PASS mypassword
    ```
3.  **Lister les Messages** Commande :

    ```bash
    LIST
    ```

    Cela retourne une liste des messages avec leurs tailles.
4.  **Lire un Message** Commande :

    ```bash
    RETR <message_id>
    ```

    Remplacez `<message_id>` par l'identifiant du message.
5.  **Supprimer un Message** Commande :

    ```bash
    DELE <message_id>
    ```
6.  **Quitter la Session** Commande :

    ```bash
    QUIT
    ```

***

**2.3 Tests et Pentest POP3**

1.  **Scanner les Ports** Identifiez si POP3 est actif :

    ```bash
    nmap -p 110,995 --script pop3-capabilities <target>
    ```

    **pop3-capabilities** énumère les capacités du serveur POP3.
2.  **Brute-Force des Identifiants** Avec **Hydra** :

    ```bash
    hydra -L usernames.txt -P passwords.txt -s 110 -f <target> pop3
    ```
3.  **Tester des Commandes Sensibles** Certains serveurs permettent des commandes non sécurisées :

    ```bash
    telnet <server_ip> 110
    USER admin
    PASS admin
    ```
4.  **Téléchargement de Courriels** Si l’authentification réussit, téléchargez tous les courriels avec une boucle :

    ```bash
    LIST
    RETR 1
    RETR 2
    ```

***

### **3. Sécurisation de IMAP et POP3**

1. **Activer STARTTLS ou SSL/TLS**
   * IMAP : Utilisez le port 993 pour les communications sécurisées.
   * POP3 : Utilisez le port 995 pour les communications sécurisées.
2. **Désactiver les Protocoles Non Chiffrés**
   * Bloquez les ports 143 (IMAP) et 110 (POP3) si STARTTLS n'est pas utilisé.
3. **Limiter les Tentatives de Connexion** Configurez des mécanismes pour limiter les tentatives de connexion brutale.
4. **Surveiller les Logs** Analysez les journaux d'accès pour détecter des comportements anormaux.
5. **Mettre en Place une Authentification Multi-Facteurs (MFA)** Si possible, ajoutez une couche supplémentaire d'authentification.

***

### **4. Comparaison IMAP vs POP3**

| Fonctionnalité        | IMAP                                    | POP3                                    |
| --------------------- | --------------------------------------- | --------------------------------------- |
| Gestion des courriels | À distance, synchronisé entre appareils | Local, généralement supprimé du serveur |
| Port standard         | 143 (STARTTLS : 993)                    | 110 (STARTTLS : 995)                    |
| Lecture partielle     | Possible                                | Non                                     |
| Meilleur usage        | Accès depuis plusieurs appareils        | Usage sur un seul appareil              |

***

### **5. Bonnes Pratiques pour les Pentests IMAP et POP3**

* **Obtenez une Autorisation Légale** : Les tests sur des serveurs tiers sans consentement explicite sont illégaux.
* **Utilisez des Listes Appropriées** : Les outils comme Hydra nécessitent des fichiers de noms d’utilisateur et de mots de passe pertinents.
* **Respectez les Politiques de Sécurité** : Si une alerte est déclenchée, coopérez avec l’équipe de sécurité.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
