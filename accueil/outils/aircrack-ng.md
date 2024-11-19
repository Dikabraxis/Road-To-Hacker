# Aircrack-ng

**Introduction**

\
Aircrack-ng est une suite d'outils dédiée à l'audit de la sécurité des réseaux sans fil. Elle permet d'analyser les réseaux Wi-Fi pour détecter les vulnérabilités et tester la robustesse des clés de sécurité telles que WPA/WPA2 et WEP. Aircrack-ng est particulièrement utile pour les tests de pénétration sur des réseaux sans fil.

**Installation d’Aircrack-ng**

1.  **Installation sur Linux**

    ```bash
    sudo apt update
    sudo apt install aircrack-ng
    ```

    *   **Compilation depuis les sources** (optionnel) :

        ```bash
        sudo apt update
        sudo apt install build-essential libnl-3-dev libnl-genl-3-dev libpcap-dev
        git clone https://github.com/aircrack-ng/aircrack-ng.git
        cd aircrack-ng
        ./autogen.sh
        ./configure
        make
        sudo make install
        ```
2. **Installation sur Windows**
   * Téléchargez le programme d'installation depuis le site officiel [aircrack-ng.org](https://www.aircrack-ng.org/).
   * Décompressez et installez le programme en suivant les instructions.

**Commandes de Base**

1.  **Capture des Paquets**

    ```bash
    sudo airodump-ng wlan0mon
    ```

    * **Explication** : Démarre la capture des paquets sur l'interface sans fil en mode moniteur (`wlan0mon`).


2.  **Filtrage des Paquets**

    ```bash
    sudo airodump-ng --bssid [BSSID] -c [Channel] -w capture wlan0mon
    ```

    * **Explication** : Capture les paquets d'un réseau spécifique, en filtrant par BSSID et canal, et sauvegarde les données dans `capture.cap`.


3.  **Craquage de Clé WEP**

    ```bash
    aircrack-ng capture.cap
    ```

    * **Explication** : Analyse le fichier `capture.cap` pour tenter de craquer une clé WEP.


4.  **Craquage de Clé WPA/WPA2**

    ```bash
    aircrack-ng -w /path/to/wordlist.txt -b [BSSID] capture.cap
    ```

    * **Explication** : Utilise le fichier de dictionnaire `wordlist.txt` pour craquer une clé WPA/WPA2 à partir des paquets capturés.



**Options Avancées**

1.  **Déauthentifier les Clients**

    ```bash
    sudo aireplay-ng --deauth 10 -a [BSSID] wlan0mon
    ```

    * **Explication** : Envoie des paquets de déauthentification pour déconnecter les clients du réseau, facilitant la capture des handshakes WPA/WPA2.


2.  **Injection de Paquets**

    ```bash
    sudo aireplay-ng --fakeauth 10 -a [BSSID] -h [Your MAC] wlan0mon
    ```

    * **Explication** : Injecte des paquets pour simuler une authentification sur le réseau cible, aidant à obtenir des paquets de handshake.


3.  **Détection des Réseaux Cachés**

    ```bash
    sudo airodump-ng --essid "hidden" wlan0mon
    ```

    * **Explication** : Recherche des réseaux sans fil qui ne diffusent pas leur SSID.



**Exemples de Scénarios d'Évasion**

1.  **Scan et Capture de Paquets en Mode Moniteur**

    ```bash
    sudo airodump-ng wlan0mon
    ```

    * **Explication** : Lance une capture de tous les paquets sans filtrage. Peut être utilisé pour détecter des réseaux et des clients.


2.  **Craquage de Clé WPA avec Attaque de Dictionnaire**

    ```bash
    aircrack-ng -w /path/to/wordlist.txt -b 00:11:22:33:44:55 capture.cap
    ```

    * **Explication** : Essaye de trouver la clé WPA en utilisant un fichier de dictionnaire. Idéal pour tester des mots de passe faibles.


3.  **Injection et Déauthentification pour Capture de Handshake**

    ```bash
    sudo aireplay-ng --deauth 10 -a 00:11:22:33:44:55 wlan0mon
    ```

    * **Explication** : Déauthentifie les clients pour provoquer un nouveau handshake et faciliter la capture.

