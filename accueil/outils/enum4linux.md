# Enum4linux

#### Introduction

Enum4Linux est un script Perl conçu pour extraire des informations des systèmes Windows à travers le protocole SMB. Il est souvent utilisé pour l'audit de sécurité afin d'obtenir des informations telles que les utilisateurs, les groupes, les partages et les politiques de sécurité d'un domaine Windows.

#### Installation de Enum4Linux

**Installation sur Linux**

1.  **Cloner le Dépôt GitHub** :

    ```bash
    git clone https://github.com/portcullislabs/enum4linux.git
    ```

    * **Explication** : Télécharge le script Enum4Linux depuis le dépôt GitHub.
2.  **Naviguer dans le Répertoire** :

    ```bash
    cd enum4linux
    ```

    * **Explication** : Change le répertoire de travail pour le dossier contenant Enum4Linux.
3.  **Installer les Dépendances** :

    ```bash
    sudo apt-get install perl libnet-ssleay-perl libio-socket-ssl-perl
    ```

    * **Explication** : Installe Perl et les modules nécessaires pour exécuter Enum4Linux.

#### Utilisation de Base

**1. Exécution de Enum4Linux**

*   **Commande de base** :

    ```bash
    perl enum4linux.pl -a <IP_du_Serveur>
    ```

    * **Explication** :
      * `-a` : Effectue une énumération complète (inclut les utilisateurs, les groupes, les partages, etc.).
      * `<IP_du_Serveur>` : Adresse IP du serveur Windows cible.



**2. Récupération des Utilisateurs**

*   **Lister les utilisateurs du domaine** :

    ```bash
    perl enum4linux.pl -u <IP_du_Serveur>
    ```

    * **Explication** :
      * `-u` : Liste les utilisateurs du domaine.



**3. Récupération des Groupes**

*   **Lister les groupes du domaine** :

    ```bash
    perl enum4linux.pl -g <IP_du_Serveur>
    ```

    * **Explication** :
      * `-g` : Liste les groupes du domaine.



**4. Récupération des Partages**

*   **Lister les partages réseau** :

    ```bash
    perl enum4linux.pl -s <IP_du_Serveur>
    ```

    * **Explication** :
      * `-s` : Liste les partages réseau.



#### Options Avancées

**1. Récupération des Politiques de Sécurité**

*   **Obtenir les politiques de sécurité** :

    ```bash
    perl enum4linux.pl -p <IP_du_Serveur>
    ```

    * **Explication** :
      * `-p` : Récupère les politiques de sécurité et les informations sur les utilisateurs.



**2. Récupération des Mappages de Répertoires**

*   **Lister les répertoires mappés** :

    ```bash
    perl enum4linux.pl -r <IP_du_Serveur>
    ```

    * **Explication** :
      * `-r` : Récupère les répertoires mappés (partages et les droits).



#### Exemples de Commandes

**1. Obtenir des Informations Complètes**

*   **Commande pour une énumération complète** :

    ```bash
    perl enum4linux.pl -a 192.168.1.10
    ```



**2. Lister les Utilisateurs**

*   **Commande pour lister les utilisateurs du domaine** :

    ```bash
    perl enum4linux.pl -u 192.168.1.10
    ```



**3. Lister les Partages Réseau**

*   **Commande pour lister les partages réseau** :

    ```bash
    perl enum4linux.pl -s 192.168.1.10
    ```

