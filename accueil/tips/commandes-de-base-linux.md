# Commandes de base Linux

#### **Tutoriel : Commandes de Base sous Linux**

***

#### **Navigation dans le Système de Fichiers**

*   **Se déplacer dans le répertoire home :**

    ```bash
    cd ~
    ```
*   **Se déplacer dans le répertoire racine :**

    ```bash
    cd /
    ```
*   **Afficher le contenu du répertoire actuel :**

    ```bash
    ls
    ```
*   **Afficher le chemin du répertoire actuel :**

    ```bash
    pwd
    ```

***

#### **Manipulation de Fichiers et Répertoires**

*   **Créer un fichier :**

    ```bash
    touch <nom_du_fichier>
    ```
*   **Afficher le contenu d'un fichier :**

    ```bash
    cat <nom_du_fichier>
    ```
*   **Éditer un fichier :**

    ```bash
    nano <nom_du_fichier>
    ```
*   **Créer un dossier :**

    ```bash
    mkdir <nom_du_dossier>
    ```
*   **Supprimer un fichier :**

    ```bash
    rm <nom_du_fichier>
    ```
*   **Supprimer un dossier vide :**

    ```bash
    rmdir <nom_du_dossier>
    ```
*   **Supprimer un dossier avec son contenu :**

    ```bash
    rm -r <nom_du_dossier>
    ```
*   **Copier un fichier :**

    ```bash
    cp <source> <destination>
    ```
*   **Déplacer un fichier :**

    ```bash
    mv <source> <destination>
    ```

***

#### **Combinaisons de Commandes**

*   **Exécuter plusieurs commandes successivement sans dépendre du succès des précédentes :**

    ```bash
    commande_1 ; commande_2 ; commande_3
    ```
*   **Exécuter plusieurs commandes successivement en dépendant du succès des précédentes :**

    ```bash
    commande_1 && commande_2 && commande_3
    ```

***

#### **Redirection et Piping**

*   **Rediriger la sortie d'une commande vers un fichier :**

    ```bash
    commande > fichier.txt
    ```
*   **Ajouter la sortie d'une commande à un fichier (sans écraser le contenu) :**

    ```bash
    commande >> fichier.txt
    ```
*   **Passer la sortie d'une commande comme entrée d'une autre (pipe) :**

    ```bash
    commande_1 | commande_2
    ```

***

#### **Recherche et Informations Système**

*   **Rechercher un fichier par son nom :**

    ```bash
    find / -name "nom_du_fichier"
    ```
*   **Rechercher un fichier en spécifiant son type :**

    ```bash
    find / -type f -name "user.txt"
    ```
*   **Trouver le chemin d'un fichier exécutable :**

    ```bash
    whereis <nom_executable>
    ```
*   **Afficher les variables d'environnement :**

    ```bash
    printenv
    ```
*   **Afficher les processus actifs :**

    ```bash
    ps
    ```
*   **Afficher les processus en temps réel :**

    ```bash
    top
    ```

***

#### **Permissions et Propriétés des Fichiers**

*   **Afficher les fichiers avec leurs permissions :**

    ```bash
    ls -al
    ```

    *   **Explication des droits :**

        ```yaml
        drwxrwxrwx  -rwxrwxrwx
        d : Répertoire
        - : Fichier
        r : Lecture (read)
        w : Écriture (write)
        x : Exécution (execute)
        ```
*   **Modifier le propriétaire d'un fichier :**

    ```bash
    chown <utilisateur>:<groupe> <nom_du_fichier>
    ```
*   **Modifier les permissions d'un fichier :**

    ```bash
    chmod [u|g|o|a][+|-][r|w|x] <nom_du_fichier>
    ```

***

#### **Réseau**

*   **Afficher les tables de routage :**

    ```bash
    route -n
    ```
*   **Voir les connexions réseau actives :**

    ```bash
    netstat
    ```
*   **Voir le trafic réseau en temps réel :**

    ```bash
    tcpdump -i eth0 -s0 -v
    ```

***

#### **Affichage des Logs**

*   **Lister les logs système :**

    ```bash
    ls /var/log
    ```

***

#### **Statistiques et Diagnostic**

*   **Afficher l'utilisation de l'espace disque :**

    ```bash
    df -h
    ```
*   **Afficher les fichiers ouverts par des processus :**

    ```bash
    lsof
    ```
*   **Afficher les utilisateurs du système :**

    ```bash
    cat /etc/passwd
    ```
*   **Afficher les groupes du système :**

    ```bash
    cat /etc/group
    ```

***

#### **Ajout Optionnel**
