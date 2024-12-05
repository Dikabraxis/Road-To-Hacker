# Enum4linux

## Enum4linux - Guide Complet pour l'Énumération des Serveurs Windows

***

### Introduction

**Enum4linux** est un outil open-source écrit en Perl pour l’énumération des informations à partir de serveurs Windows utilisant SMB (Server Message Block). Il permet d’extraire des informations critiques comme :

* Les utilisateurs et groupes du domaine.
* Les partages réseau accessibles.
* Les politiques de sécurité.
* Les configurations des systèmes.

Enum4linux est particulièrement utile dans les audits de sécurité et les tests de pénétration pour explorer les environnements Windows et identifier des configurations vulnérables.

***

### 🚀 Étape 1 : Installation de Enum4linux

#### Prérequis

1. **Perl** :
   * Enum4linux est un script Perl, donc Perl doit être installé.
   *   Vérifiez si Perl est installé :

       ```bash
       perl --version
       ```
   * Si Perl n’est pas installé :
     *   **Linux** :

         ```bash
         sudo apt update
         sudo apt install perl
         ```
     *   **macOS** :

         ```bash
         bashCopier le codebrew install perl
         ```
2. **Dépendances pour SSL** :
   *   Installez les modules nécessaires pour exécuter Enum4linux :

       ```bash
       sudo apt install libnet-ssleay-perl libio-socket-ssl-perl
       ```

***

#### Installation de Enum4linux

1. **Cloner le dépôt GitHub** :
   *   Téléchargez Enum4linux depuis le dépôt officiel :

       ```bash
       git clone https://github.com/CiscoCXSecurity/enum4linux.git
       ```
2. **Naviguer dans le répertoire** :
   *   Accédez au dossier contenant le script :

       ```bash
       cd enum4linux
       ```
3. **Vérifier que le script est prêt à être exécuté** :
   *   Listez les fichiers :

       ```bash
       ls
       ```
   * Vous devriez voir le fichier **`enum4linux.pl`**, qui est le script principal.
4. **Donner les permissions d’exécution (optionnel)** :
   *   Rendez le script exécutable :

       ```bash
       chmod +x enum4linux.pl
       ```

***

### 🛠️ Étape 2 : Utilisation de Base

***

#### 1. Énumération Complète

*   **Commande** :

    ```bash
    perl enum4linux.pl -a <IP_du_Serveur>
    ```
* **Explication** :
  * L’option `-a` lance une énumération complète, incluant :
    * Les utilisateurs.
    * Les groupes.
    * Les partages réseau.
    * Les politiques de sécurité.
  * Remplacez `<IP_du_Serveur>` par l’adresse IP de la cible.

> 💡 **Astuce** : Sauvegardez les résultats dans un fichier pour les analyser plus tard :

```bash
perl enum4linux.pl -a <IP_du_Serveur> > resultat.txt
```

***

#### 2. Lister les Utilisateurs du Domaine

*   **Commande** :

    ```bash
    perl enum4linux.pl -u <IP_du_Serveur>
    ```
* **Explication** :
  * L’option `-u` extrait les noms d’utilisateurs disponibles sur le domaine.

***

#### 3. Lister les Groupes du Domaine

*   **Commande** :

    ```bash
    perl enum4linux.pl -g <IP_du_Serveur>
    ```
* **Explication** :
  * L’option `-g` affiche les groupes disponibles sur la cible.

***

#### 4. Lister les Partages Réseau

*   **Commande** :

    ```bash
    perl enum4linux.pl -s <IP_du_Serveur>
    ```
* **Explication** :
  * L’option `-s` identifie les partages réseau accessibles sur la cible.

***

### 🔍 Options Avancées

***

#### 1. Récupérer les Politiques de Sécurité

*   **Commande** :

    ```bash
    perl enum4linux.pl -p <IP_du_Serveur>
    ```
* **Explication** :
  * L’option `-p` extrait les politiques de sécurité appliquées sur le serveur (ex. : règles de mot de passe).

***

#### 2. Obtenir les Répertoires Mappés

*   **Commande** :

    ```bash
    perl enum4linux.pl -r <IP_du_Serveur>
    ```
* **Explication** :
  * L’option `-r` explore les répertoires mappés sur le serveur cible.

***

#### 3. Filtrer les résultats par type

Vous pouvez combiner plusieurs options pour cibler des informations spécifiques.

Exemple : Pour obtenir uniquement les utilisateurs et groupes :

```bash
perl enum4linux.pl -u -g <IP_du_Serveur>
```

***

### 📋 Étape 3 : Exemples de Commandes Pratiques

***

#### 1. Énumération Complète

*   **Commande** :

    ```bash
    perl enum4linux.pl -a 192.168.1.10
    ```
* **Explication** :
  * Effectue une énumération complète sur l’adresse IP `192.168.1.10`.

***

#### 2. Lister les Utilisateurs

*   **Commande** :

    ```bash
    perl enum4linux.pl -u 192.168.1.10
    ```
* **Explication** :
  * Affiche les noms d’utilisateurs disponibles sur le domaine de la cible.

***

#### 3. Identifier les Partages Réseau

*   **Commande** :

    ```bash
    perl enum4linux.pl -s 192.168.1.10
    ```
* **Explication** :
  * Liste les partages réseau accessibles.

***

#### 4. Extraire les Politiques de Sécurité

*   **Commande** :

    ```bash
    perl enum4linux.pl -p 192.168.1.10
    ```
* **Explication** :
  * Récupère les informations sur les politiques de mot de passe, les verrouillages de compte, etc.

***

### 📖 Bonnes Pratiques

1. **Obtenez les autorisations légales** :
   * Assurez-vous que vous avez le droit d’exécuter des tests sur la cible pour éviter des problèmes juridiques.
2. **Analysez soigneusement les résultats** :
   * Les informations collectées peuvent inclure des données sensibles. Assurez-vous de traiter ces résultats de manière éthique.
3. **Automatisez vos workflows** :
   * Associez Enum4linux à des scripts ou outils comme **Metasploit** pour enrichir vos analyses.
4. **Limiter l’impact** :
   * Utilisez des options comme l’enregistrement dans un fichier pour minimiser les interactions en direct avec la cible.
