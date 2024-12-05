# Commandes de base Windows

### **Tutoriel : Commandes de Base sous Windows CMD**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

### Introduction

Ce tutoriel détaille les commandes essentielles pour naviguer, manipuler des fichiers, gérer des utilisateurs, et configurer le système à partir de l'invite de commandes Windows (CMD).

***

### **Navigation dans les Répertoires**

*   **Répertoire home (répertoire utilisateur)**

    ```cmd
    cd %HOMEPATH%
    ```
*   **Répertoire racine du disque**

    ```cmd
    cd \
    ```
*   **Contenu du répertoire actuel**

    ```cmd
    dir
    ```
*   **Chemin du répertoire actuel**

    ```cmd
    cd
    ```

***

### **Manipulation des Fichiers**

*   **Créer un fichier (vide)**

    ```cmd
    echo. > nom_du_fichier.txt
    ```
*   **Afficher le contenu d’un fichier**

    ```cmd
    type nom_du_fichier.txt
    ```
*   **Éditer un fichier**

    ```cmd
    notepad nom_du_fichier.txt
    ```
*   **Créer un dossier**

    ```cmd
    mkdir nom_du_dossier
    ```
*   **Supprimer un fichier**

    ```cmd
    del nom_du_fichier.txt
    ```
*   **Supprimer un dossier (vide)**

    ```cmd
    rmdir nom_du_dossier
    ```
*   **Supprimer un dossier et son contenu**

    ```cmd
    rmdir /S nom_du_dossier
    ```
*   **Copier un fichier**

    ```cmd
    copy chemin_source\nom_du_fichier.txt chemin_destination\nom_du_fichier.txt
    ```
*   **Déplacer ou renommer un fichier**

    ```cmd
    move nom_du_fichier.txt chemin_destination\nom_du_fichier.txt
    ```

***

### **Commandes en Chaîne et Redirection**

*   **Entrer plusieurs commandes à la suite (sans se soucier du bon fonctionnement des précédentes)**

    ```cmd
    commande1 & commande2 & commande3
    ```
*   **Entrer plusieurs commandes à la suite (en se souciant du bon fonctionnement des précédentes)**

    ```cmd
    commande1 && commande2 && commande3
    ```
*   **Rediriger la sortie d’une commande vers un fichier (écrase le contenu)**

    ```cmd
    commande > fichier.txt
    ```
*   **Rediriger la sortie d’une commande vers un fichier sans écraser le contenu**

    ```cmd
    commande >> fichier.txt
    ```
*   **Introduire une commande dans la précédente (pipe)**

    ```cmd
    commande1 | commande2
    ```

***

### **Recherche et Gestion des Fichiers**

*   **Trouver un fichier**

    ```cmd
    dir nom_du_fichier.txt /S
    ```
*   **Trouver le chemin d’un fichier exécutable (ex : notepad)**

    ```cmd
    where notepad
    ```

***

### **Gestion des Processus**

*   **Afficher les processus**

    ```cmd
    tasklist
    ```
*   **Tuer un processus (par PID ou nom de l'exécutable)**

    ```cmd
    taskkill /PID <pid>
    taskkill /IM nom_executable.exe
    ```

***

### **Gestion du Réseau**

*   **Afficher les connexions réseau actives**

    ```cmd
    netstat
    ```
*   **Afficher la configuration réseau**

    ```cmd
    ipconfig
    ```
*   **Afficher les interfaces réseau et leurs adresses IP**

    ```cmd
    ipconfig /all
    ```
*   **Afficher la table de routage**

    ```cmd
    route print
    ```
*   **Pinger une adresse IP ou un domaine**

    ```cmd
    ping www.example.com
    ```
*   **Tracer une route réseau**

    ```cmd
    tracert www.example.com
    ```

***

### **Gestion des Utilisateurs et Groupes**

*   **Afficher les utilisateurs du système**

    ```cmd
    net user
    ```
*   **Afficher les groupes du système**

    ```cmd
    net localgroup
    ```
*   **Créer un nouvel utilisateur**

    ```cmd
    net user nom_utilisateur mot_de_passe /add
    ```
*   **Ajouter un utilisateur à un groupe**

    ```cmd
    net localgroup nom_du_groupe nom_utilisateur /add
    ```
*   **Supprimer un utilisateur**

    ```cmd
    net user nom_utilisateur /delete
    ```

***

### **Gestion des Permissions**

* **Modifier les droits d’un fichier**\
  &#xNAN;_&#x44;ans Windows, utilisez l’interface graphique : clic droit → Propriétés → Sécurité. Pas d’équivalent direct à `chmod` via CMD._

***

### **Commandes Diverses**

*   **Lancer une application**

    ```cmd
    start nom_application.exe
    ```
*   **Afficher l’aide d’une commande**

    ```cmd
    commande /?
    ```

***

Ce tutoriel couvre les commandes de base pour naviguer, manipuler les fichiers, gérer les utilisateurs et configurer les systèmes sous Windows CMD. Ces commandes sont idéales pour une gestion rapide et efficace via l’invite de commandes.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
