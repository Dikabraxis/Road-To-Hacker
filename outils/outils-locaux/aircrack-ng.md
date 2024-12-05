# Aircrack-ng

## Aircrack-ng - Suite d'Audit des Réseaux Sans Fil

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

### Introduction

**Aircrack-ng** est une suite d'outils dédiée à l'audit de la sécurité des réseaux sans fil. Elle permet de :

* **Analyser les réseaux Wi-Fi** pour détecter les vulnérabilités.
* **Tester la robustesse des clés de sécurité** (WEP, WPA, WPA2).
* **Effectuer des tests de pénétration** sur des réseaux sans fil.

C'est un outil incontournable pour les professionnels en cybersécurité cherchant à évaluer la sécurité des réseaux sans fil.

***

### 🚀 Installation d'Aircrack-ng

#### Installation sur Linux

La méthode la plus simple consiste à utiliser les gestionnaires de paquets :

1.  **Installer depuis les dépôts** :

    ```bash
    sudo apt update
    sudo apt install aircrack-ng
    ```
2.  **Compilation depuis les sources** (optionnel pour les dernières versions) :

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

#### Installation sur Windows

1. Téléchargez le programme d'installation depuis le [site officiel d'Aircrack-ng](https://www.aircrack-ng.org/).
2. Décompressez l'archive et suivez les instructions d'installation.
3. Accédez à Aircrack-ng via une invite de commande.

***

### 🛠️ Commandes de Base

#### 1. **Capture des Paquets**

*   **Commande** :

    ```bash
    sudo airodump-ng wlan0mon
    ```
* **Explication** : Démarre la capture des paquets sur l'interface sans fil configurée en mode moniteur (`wlan0mon`).

#### 2. **Filtrage des Paquets**

*   **Commande** :

    ```bash
    sudo airodump-ng --bssid [BSSID] -c [Channel] -w capture wlan0mon
    ```
* **Explication** : Capture les paquets spécifiques à un réseau (identifié par son BSSID) sur un canal précis et les sauvegarde dans un fichier nommé `capture.cap`.

#### 3. **Craquage de Clé WEP**

*   **Commande** :

    ```bash
    aircrack-ng capture.cap
    ```
* **Explication** : Analyse le fichier de capture pour tenter de découvrir une clé WEP.

#### 4. **Craquage de Clé WPA/WPA2**

*   **Commande** :

    ```bash
    aircrack-ng -w /path/to/wordlist.txt -b [BSSID] capture.cap
    ```
* **Explication** : Utilise une attaque par dictionnaire (fichier `wordlist.txt`) pour tenter de craquer une clé WPA/WPA2 basée sur les handshakes capturés.

***

### 🔍 Options Avancées

#### 1. **Déauthentifier les Clients**

*   **Commande** :

    ```bash
    sudo aireplay-ng --deauth 10 -a [BSSID] wlan0mon
    ```
* **Explication** : Envoie 10 paquets de déauthentification pour forcer la déconnexion des clients, ce qui permet de capturer un handshake WPA/WPA2 lorsque les clients se reconnectent.

> ⚠️ **Attention** : Utilisez cette commande uniquement sur des réseaux dont vous avez l’autorisation, car elle peut perturber les utilisateurs légitimes.

***

#### 2. **Injection de Paquets**

*   **Commande** :

    ```bash
    sudo aireplay-ng --fakeauth 10 -a [BSSID] -h [Your MAC] wlan0mon
    ```
* **Explication** : Simule une authentification sur le réseau cible pour capturer des paquets ou générer du trafic.

***

#### 3. **Détection des Réseaux Cachés**

*   **Commande** :

    ```bash
    sudo airodump-ng --essid "hidden" wlan0mon
    ```
* **Explication** : Identifie les réseaux Wi-Fi qui ne diffusent pas leur SSID en surveillant les paquets de connexion des clients.

***

### 📋 Exemples de Scénarios d'Utilisation

#### 1. **Scan et Capture de Paquets**

*   **Commande** :

    ```bash
    sudo airodump-ng wlan0mon
    ```
* **Explication** : Scanne et capture tous les paquets sur les réseaux environnants, ce qui permet d’identifier les réseaux et les clients connectés.

***

#### 2. **Craquage de Clé WPA avec Attaque de Dictionnaire**

*   **Commande** :

    ```bash
    aircrack-ng -w /path/to/wordlist.txt -b 00:11:22:33:44:55 capture.cap
    ```
* **Explication** : Utilise un fichier de dictionnaire pour tester les mots de passe faibles et tenter de craquer une clé WPA.

***

#### 3. **Injection et Déauthentification pour Capturer un Handshake**

*   **Commande** :

    ```bash
    sudo aireplay-ng --deauth 10 -a 00:11:22:33:44:55 wlan0mon
    ```
* **Explication** : Déconnecte les clients du réseau pour forcer un nouveau handshake, qui peut ensuite être capturé pour tenter de craquer une clé WPA/WPA2.

***

### 📚 Ressources Complémentaires

* **Site officiel d'Aircrack-ng** : [https://www.aircrack-ng.org](https://www.aircrack-ng.org)
* **Documentation complète** : https://aircrack-ng.org/documentation.html
* **Fichiers de dictionnaire** :
  * [SecLists Wordlists](https://github.com/danielmiessler/SecLists)
  * [RockYou Wordlist](https://github.com/brannondorsey/naive-hashcat/releases)

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
