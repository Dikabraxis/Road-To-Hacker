# Smbmap

## Smbmap - Guide Complet pour la Gestion des Partages SMB

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### Introduction

**Smbmap** est un outil puissant conçu pour explorer et interagir avec des partages SMB (Server Message Block) sur un réseau. Il permet de lister les partages accessibles, vérifier les permissions, rechercher des fichiers spécifiques, et même télécharger ou exfiltrer des données. Il est particulièrement utile dans les scénarios d'évaluation de la sécurité des partages SMB.

***

### 🚀 Étape 1 : Installation de Smbmap

#### Sous Linux (Debian/Ubuntu)

1.  **Mettre à jour les paquets** :

    ```bash
    sudo apt update && sudo apt upgrade
    ```
2.  **Installer Smbmap via GitHub** :

    ```bash
    git clone https://github.com/ShawnDEvans/smbmap.git
    cd smbmap
    pip install -r requirements.txt
    ```
3.  **Tester l’installation** :

    ```bash
    python smbmap.py -h
    ```

    Si vous utilisez régulièrement l'outil, vous pouvez créer un alias :

    ```bash
    alias smbmap="python /chemin/vers/smbmap.py"
    ```

***

### 🛠️ Étape 2 : Utilisation de Base

***

#### 1. Lister les Partages Disponibles

Pour lister les partages accessibles sur une cible donnée :

```bash
smbmap -H <IP_ADDRESS>
```

*   **Exemple** :

    ```bash
    smbmap -H 192.168.1.10
    ```
* **Explication** :
  * `-H` : Spécifie l'adresse IP ou le nom de domaine de la cible.
  * Sans authentification, Smbmap tente une connexion anonyme.

***

#### 2. Vérifier les Permissions sur les Partages

Pour afficher les permissions des partages avec des informations d'identification :

```bash
smbmap -H <IP_ADDRESS> -u <USERNAME> -p <PASSWORD>
```

*   **Exemple** :

    ```bash
    smbmap -H 192.168.1.10 -u guest -p guest
    ```
* **Explication** :
  * `-u` : Spécifie le nom d'utilisateur.
  * `-p` : Spécifie le mot de passe. Si aucun mot de passe n'est requis, laissez vide (`-p ''`).

***

#### 3. Télécharger un Fichier Spécifique

Pour télécharger un fichier précis depuis un partage SMB :

```bash
smbmap -H <IP_ADDRESS> -u <USERNAME> -p <PASSWORD> -R <SHARE> -T <FILE_PATH> -o <LOCAL_FILE_PATH>
```

*   **Exemple** :

    ```bash
    smbmap -H 192.168.1.10 -u admin -p password -R documents -T important.docx -o /tmp/important.docx
    ```
* **Explication** :
  * `-R` : Spécifie le partage ou le répertoire à explorer (par exemple : `documents`).
  * `-T` : Indique le fichier spécifique à télécharger (par exemple : `important.docx`).
  * `-o` : Définit le chemin local où sauvegarder le fichier téléchargé.

***

#### 4. Rechercher des Fichiers Spécifiques

Pour rechercher des fichiers contenant un mot-clé ou une chaîne spécifique :

```bash
smbmap -H <IP_ADDRESS> -u <USERNAME> -p <PASSWORD> -R <SHARE> -s <SEARCH_TERM>
```

*   **Exemple** :

    ```bash
    smbmap -H 192.168.1.10 -u admin -p password -R documents -s "password"
    ```
* **Explication** :
  * `-s` : Définit le terme à rechercher (par exemple, "password").

***

### 📋 Étape 3 : Cas d’Utilisation

***

#### Exemple 1 : Découverte de Partages SMB Anonymes

Si vous souhaitez vérifier les partages accessibles sans authentification :

```bash
smbmap -H 192.168.1.10
```

* **Résultat attendu** : Liste les partages publics ou accessibles sans authentification, avec leurs permissions (lecture/écriture).

***

#### Exemple 2 : Lister les Permissions pour un Utilisateur Spécifique

Pour vérifier les permissions d'un utilisateur (par exemple : admin) sur les partages d'une cible :

```bash
smbmap -H 192.168.1.10 -u admin -p password
```

* **Résultat attendu** : Affiche une liste des partages disponibles et indique si l'utilisateur peut lire, écrire ou modifier les fichiers.

***

#### Exemple 3 : Téléchargement d’un Fichier Sensible

Pour télécharger un fichier important (par exemple : `config.txt`) depuis un partage spécifique :

```bash
smbmap -H 192.168.1.10 -u admin -p password -R backups -T config.txt -o /tmp/config.txt
```

* **Résultat attendu** : Le fichier `config.txt` sera téléchargé et sauvegardé localement dans `/tmp`.

***

#### Exemple 4 : Rechercher des Fichiers Sensibles

Pour rechercher des fichiers contenant un mot-clé (par exemple, `password`) dans un partage spécifique :

```bash
smbmap -H 192.168.1.10 -u admin -p password -R backups -s "password"
```

* **Résultat attendu** : Affiche une liste des fichiers contenant le terme "password" dans le répertoire `backups`.

***

### 🔍 Étape 4 : Options Avancées

***

#### 1. Exploitation de Partages en Lecture/Écriture

Si un partage est accessible en écriture, vous pouvez tester l'upload de fichiers :

```bash
echo "Test SMBmap" > test.txt
smbmap -H 192.168.1.10 -u admin -p password -R uploads -o test.txt
```

* **Explication** : Upload un fichier nommé `test.txt` dans le partage `uploads`.

***

#### 2. Utilisation de Proxy

Pour masquer votre origine ou rediriger le trafic via un proxy SOCKS :

```bash
smbmap -H <IP_ADDRESS> --proxy http://127.0.0.1:8080
```

* **Explication** : Envoie toutes les requêtes SMB via un proxy à `127.0.0.1` (port 8080).

***

### 📖 Bonnes Pratiques

***

#### 1. Obtenir des Autorisations

* **Important** : N'effectuez jamais de tests sur des systèmes ou réseaux sans une autorisation explicite.
* **Risque légal** : Interagir avec des partages SMB sans autorisation peut entraîner des sanctions légales.

#### 2. Minimiser l’Impact

* Limitez vos tests pour éviter de surcharger les serveurs SMB.
* Configurez des délais entre les requêtes pour minimiser le trafic généré.

#### 3. Nettoyer Après les Tests

*   Si vous avez uploadé des fichiers pour tester l'écriture, supprimez-les pour éviter de laisser des traces :

    ```bash
    rm /tmp/test.txt
    ```

***

### Conclusion

**Smbmap** est un outil essentiel pour les pentesters cherchant à auditer ou interagir avec des partages SMB. Grâce à ses fonctionnalités comme la découverte des permissions, la recherche de fichiers et le téléchargement ciblé, il simplifie grandement l'évaluation de la sécurité des réseaux SMB.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
