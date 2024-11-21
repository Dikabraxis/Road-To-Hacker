---
layout:
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Curl

#### **Curl : Tutoriel Complet**

***

### 1. **Utilisation de Base**

*   Effectuer une requête GET simple :

    ```bash
    curl http://example.com
    ```
*   Effectuer une requête POST avec des données :

    ```bash
    curl -X POST -d "param1=value1&param2=value2" http://example.com
    ```

***

### 2. **Envoi de Headers**

*   Ajouter un header personnalisé :

    ```bash
    curl -H "Authorization: Bearer token" http://example.com
    ```
*   Ajouter plusieurs headers :

    ```bash
    curl -H "Header1: Value1" -H "Header2: Value2" http://example.com
    ```

***

### 3. **Gestion des Cookies**

*   **Envoyer un cookie :**

    ```bash
    curl -b "name=value" http://example.com
    ```
*   **Enregistrer et utiliser des cookies :**

    ```bash
    curl -c cookies.txt http://example.com  # Enregistrer dans un fichier
    curl -b cookies.txt http://example.com  # Utiliser les cookies enregistrés
    ```

***

### 4. **Suivi des Redirections**

*   Suivre les redirections HTTP :

    ```bash
    curl -L http://example.com
    ```
*   Limiter le nombre de redirections :

    ```bash
    curl -L --max-redirs 5 http://example.com
    ```

***

### 5. **Options de Sortie et d'Affichage**

*   Afficher uniquement le corps de la réponse :

    ```bash
    curl -s http://example.com
    ```
*   Inclure le temps de réponse et d'autres statistiques :

    ```bash
    curl -w "Time: %{time_total}s\n" http://example.com
    ```
*   Enregistrer la réponse dans un fichier :

    ```bash
    curl -o result.txt http://example.com
    ```

***

### 6. **Options de Réseau et de Proxy**

*   Utiliser un proxy :

    ```bash
    curl -x http://proxy.example.com:8080 http://example.com
    ```
*   Limiter la vitesse de téléchargement :

    ```bash
    curl --limit-rate 100K http://example.com
    ```
*   Spécifier une interface réseau :

    ```bash
    curl --interface eth0 http://example.com
    ```
*   Connexion via un proxy SOCKS :

    ```bash
    curl -x socks5://localhost:1080 http://example.com
    ```

***

### 7. **Téléchargements Multiples et Parallèles**

*   Télécharger plusieurs fichiers :

    ```bash
    curl -O http://example.com/file1 -O http://example.com/file2
    ```
*   Utiliser une boucle pour télécharger plusieurs fichiers :

    ```bash
    curl http://example.com/file[1-5].txt
    ```

***

### 8. **Commandes FTP et SFTP**

*   Télécharger un fichier via FTP :

    ```bash
    curl ftp://example.com/file.txt -u username:password
    ```
*   Uploader un fichier via FTP :

    ```bash
    curl -T localfile ftp://example.com/upload/ -u username:password
    ```
*   Lister les fichiers sur un serveur FTP :

    ```bash
    curl ftp://example.com/ -u username:password
    ```
*   Télécharger un fichier via SFTP :

    ```bash
    curl -u username:password sftp://example.com/path/to/file
    ```

***

### 9. **Debugging et Diagnostics**

*   Mode verbeux pour obtenir plus d'infos :

    ```bash
    curl -v http://example.com
    ```
*   Suivi du temps de réponse et autres détails :

    ```bash
    curl -w "@curl-format.txt" http://example.com
    ```
*   Voir les étapes de la résolution DNS :

    ```bash
    curl --trace-ascii trace.txt http://example.com
    ```

***

### 10. **Options Avancées**

*   Téléchargement en mode "résumable" (reprendre un téléchargement) :

    ```bash
    curl -C - -O http://example.com/file.zip
    ```
*   Chiffrer/déchiffrer un fichier lors du transfert :

    ```bash
    curl --krb privatekey.pem -T encryptedfile.txt https://secure.example.com/upload
    ```

***

### 11. **Génération de Commandes Curl**

* Exporter une commande curl depuis Postman :
  * Effectuez une requête dans Postman.
  * Cliquez sur **Code** dans le menu.
  * Sélectionnez le format **curl** pour obtenir la commande.
