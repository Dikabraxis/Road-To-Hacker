# Smbmap

#### Introduction

SMBmap est un outil open-source qui facilite l'exploration des partages SMB sur un réseau. Il peut aider à identifier les fichiers partagés et les permissions d'accès sur les serveurs SMB, souvent dans le cadre de tests de pénétration et d'audits de sécurité.

#### Installation de SMBmap

SMBmap peut être installé à partir de GitHub. Voici comment procéder :

**Installation sur Linux**

1.  **Cloner le dépôt GitHub** :

    ```bash
    git clone https://github.com/ShawnDEvans/SMBMap.git
    ```
2.  **Accéder au répertoire SMBmap** :

    ```bash
    cd SMBMap
    ```
3.  **Installer les dépendances** :

    ```bash
    pip install -r requirements.txt
    ```
4.  **Lancer SMBmap** :

    ```bash
    python smbmap.py
    ```

**Installation via `apt` (si disponible)**

Certaines distributions Linux peuvent proposer SMBmap dans leurs dépôts, mais il est souvent préférable de cloner directement le dépôt GitHub pour obtenir la dernière version.

#### Commandes et Options de Base

**Scanner un Réseau pour les Partages SMB**

1.  **Scanner un Réseau pour Découvrir les Partages**

    ```bash
    smbmap -H <IP_ADDRESS>
    ```

    * **Explication** : `-H` spécifie l'adresse IP de l'hôte que vous souhaitez scanner pour découvrir les partages SMB.



**Vérifier les Permissions sur un Partage**

2. **Lister les Partages et Vérifier les Permissions**

```bash
smbmap -H <IP_ADDRESS> -u <USERNAME> -p <PASSWORD>
```

* **Explication** : `-u` et `-p` permettent de spécifier les informations d'authentification pour accéder aux partages SMB. Sans ces options, SMBmap essaiera de se connecter avec des informations d'authentification anonymes.



**Extraire des Fichiers à Partir des Partages**

3. **Télécharger des Fichiers d’un Partage SMB**

```bash
smbmap -H <IP_ADDRESS> -u <USERNAME> -p <PASSWORD> -R <SHARE> -L
```

* **Explication** : `-R` spécifie le répertoire à l'intérieur du partage SMB, et `-L` liste les fichiers dans ce répertoire. Vous pouvez ensuite utiliser les options supplémentaires pour télécharger des fichiers.



4. **Télécharger un Fichier Spécifique**

```bash
smbmap -H <IP_ADDRESS> -u <USERNAME> -p <PASSWORD> -R <SHARE> -T <FILE_PATH> -o <LOCAL_FILE_PATH>
```

* **Explication** : `-T` spécifie le chemin du fichier sur le partage SMB, et `-o` spécifie le chemin local où le fichier sera sauvegardé.



**Rechercher des Fichiers dans les Partages**

5. **Rechercher des Fichiers Par Nom**

```bash
smbmap -H <IP_ADDRESS> -u <USERNAME> -p <PASSWORD> -R <SHARE> -s <SEARCH_TERM>
```

* **Explication** : `-s` permet de rechercher des fichiers correspondant à un terme de recherche dans le répertoire spécifié.



#### Exemples de Scénarios

**Découverte de Partages SMB**

1.  **Scanner un Réseau pour les Partages**

    ```bash
    smbmap -H 192.168.1.10
    ```

    * **Explication** : Découvre les partages disponibles sur l'hôte spécifié.

**Vérification des Permissions**

2. **Lister les Partages et Permissions**

```bash
smbmap -H 192.168.1.10 -u guest -p guest
```

* **Explication** : Vérifie les partages disponibles et les permissions avec les informations d'identification guest.

**Téléchargement de Fichiers**

3. **Télécharger un Fichier Spécifique**

```bash
smbmap -H 192.168.1.10 -u admin -p password -R documents -T important.docx -o /tmp/important.docx
```

* **Explication** : Télécharge le fichier `important.docx` du partage `documents` sur le serveur SMB.

#### Bonnes Pratiques

1. **Obtenir des Autorisations**
   * **Assurez-vous toujours** d'avoir les autorisations nécessaires avant d'effectuer des tests de sécurité sur des réseaux SMB.
   * **Évitez les tests non autorisés** pour éviter des implications légales et éthiques.
2. **Utiliser les Fonctionnalités de Limitation**
   * **Limiter la portée des tests** pour éviter des impacts sur le réseau et les systèmes cibles.
   * **Configurer des délais entre les requêtes** pour éviter de surcharger le serveur SMB et d'attirer l'attention.
3. **Surveiller les Réactions du Serveur**
   * **Observer les logs et les alertes** générés par les serveurs SMB pour ajuster les tests et minimiser les risques.
