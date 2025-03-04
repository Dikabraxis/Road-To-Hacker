# Tcpdump

### **TCPDump - Guide Complet pour l'Analyse du Trafic Réseau**

***

⚠️ **Avertissement :** Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

***

### **Introduction**

**TCPDump** est un outil en ligne de commande puissant permettant de capturer et d’analyser le trafic réseau sur une machine en temps réel. Il est souvent utilisé pour :

* Diagnostiquer des problèmes réseau.
* Analyser le comportement d’un protocole spécifique.
* Identifier des communications suspectes lors d’un test de sécurité.

TCPDump utilise **libpcap** pour capturer les paquets et permet une grande flexibilité dans la sélection, le filtrage et l’analyse du trafic réseau.

***

### **🚀 Étape 1 : Installation de TCPDump**

**1.1 Installation sur Linux (Debian/Ubuntu)**

```bash
sudo apt update
sudo apt install tcpdump
```

***

### **🛠️ Étape 2 : Commandes de Base**

**2.1 Afficher les informations et interfaces disponibles**

```bash
tcpdump --version  # Affiche la version
```

```bash
tcpdump -h  # Affiche l'aide et les options disponibles
```

```bash
tcpdump -D  # Affiche les interfaces disponibles pour capturer le trafic
```

**2.2 Capturer le trafic réseau**

```bash
sudo tcpdump -i eth0
```

📌 **Explication** :

* `-i eth0` : Spécifie l'interface réseau (remplacez `eth0` par `wlan0` pour Wi-Fi, `ens33`, etc.).
* Nécessite des privilèges root.

**2.3 Enregistrer le trafic dans un fichier pour une analyse ultérieure**

```bash
sudo tcpdump -i eth0 -w capture.pcap
```

* `-w capture.pcap` : Sauvegarde les paquets capturés dans un fichier `.pcap` pour une analyse avec Wireshark ou autres outils.

**2.4 Lire un fichier de capture**

```bash
sudo tcpdump -r capture.pcap
```

* `-r capture.pcap` : Relit les paquets enregistrés.

**2.5 Filtrer et extraire des données spécifiques**

```bash
sudo tcpdump -r capture.pcap -l | grep 'password'
```

* `-l` : Rend la sortie interactive pour permettre la recherche en temps réel.

***

### **🔍 Étape 3 : Filtres de Capture Avancés**

**3.1 Filtrer par Protocole**

*   **Capturer uniquement les paquets ICMP (ping)**

    ```bash
    sudo tcpdump -i eth0 icmp
    ```
*   **Capturer uniquement le trafic TCP**

    ```bash
    sudo tcpdump -i eth0 tcp
    ```
*   **Capturer uniquement le trafic UDP**

    ```bash
    sudo tcpdump -i eth0 udp
    ```

**3.2 Filtrer par Adresse IP**

*   **Capturer le trafic d’une adresse spécifique**

    ```bash
    sudo tcpdump -i eth0 host 192.168.1.10
    ```
*   **Capturer uniquement le trafic en provenance d’une IP spécifique**

    ```bash
    sudo tcpdump -i eth0 src host 192.168.1.10
    ```
*   **Capturer uniquement le trafic destiné à une IP spécifique**

    ```bash
    sudo tcpdump -i eth0 dst host 8.8.8.8
    ```

**3.3 Filtrer par Port**

*   **Capturer le trafic HTTP (port 80)**

    ```bash
    sudo tcpdump -i eth0 port 80
    ```
*   **Capturer le trafic d’une plage de ports**

    ```bash
    sudo tcpdump -i eth0 portrange 20-25
    ```

**3.4 Combiner plusieurs filtres**

*   **Capturer le trafic d’un hôte sur un port spécifique**

    ```bash
    sudo tcpdump -i eth0 host 192.168.1.10 and port 443
    ```
*   **Capturer uniquement le trafic qui n’est pas UDP**

    ```bash
    sudo tcpdump -i eth0 not udp
    ```
*   **Capturer les paquets dont la taille est supérieure à 1000 octets**

    ```bash
    sudo tcpdump -i eth0 greater 1000
    ```

***

### **Résumé des Commandes Clés**

| Commande                                                                                                        | Description                                                                                                                       |
| --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `tcpdump --version`                                                                                             | Affiche la version de TCPDump.                                                                                                    |
| `tcpdump -h`                                                                                                    | Affiche l’aide et les options disponibles.                                                                                        |
| `tcpdump -D`                                                                                                    | Liste les interfaces réseau disponibles.                                                                                          |
| `tcpdump -i eth0`                                                                                               | Capture le trafic en temps réel sur eth0.                                                                                         |
| `tcpdump -i eth0 -c 10`                                                                                         | Capture 10 paquets uniquement.                                                                                                    |
| `tcpdump -i eth0 -w fichier.pcap`                                                                               | Enregistre la capture dans un fichier.                                                                                            |
| `tcpdump -r fichier.pcap`                                                                                       | Relit un fichier de capture.                                                                                                      |
| `tcpdump -i eth0 port 80`                                                                                       | Capture uniquement le trafic sur le port 80.                                                                                      |
| `tcpdump -i eth0 portrange 0-1024`                                                                              | Permet de spécifier une plage de ports. (0-1024)                                                                                  |
| `tcpdump -i eth0 host 192.168.1.1`                                                                              | Capture le trafic lié à une IP spécifique.                                                                                        |
| `tcpdump -i eth0 -X`                                                                                            | Affiche les paquets en ASCII et hexadécimal.                                                                                      |
| `tcpdump -i eth0 -XX`                                                                                           | Identique à X, mais spécifiera également les en-têtes Ethernet. (comme en utilisant Xe)                                           |
| `tcpdump -i eth0 -n`                                                                                            | Désactive la résolution DNS des IPs.                                                                                              |
| `tcpdump -i eth0 -nn`                                                                                           | Désactive la résolution DNS des IPs et des ports.                                                                                 |
| <p><code>tcpdump -i eth0 -v</code><br><code>tcpdump -i eth0 -vv</code><br><code>tcpdump -i eth0 -vvv</code></p> | Augmentez la verbosité des sorties affichées et enregistrées.                                                                     |
| `tcpdump -i eth0 -s`                                                                                            | Définit la quantité d'un paquet à récupérer.                                                                                      |
| `tcpdump -i eth0 -S`                                                                                            | Changer les numéros de séquence relatifs dans l'affichage de capture en numéros de séquence absolus. (13248765839 au lieu de 101) |
| `tcpdump -i eth0 greater 1000`                                                                                  | Capture les paquets de plus de 1000 octets.                                                                                       |
| `tcpdump -i eth0 less 100`                                                                                      | Capture les paquets de moins de 100 octets.                                                                                       |
| `tcpdump -i eth0 host 192.168.1.10 and port 443`                                                                | Capture le trafic d’un hôte sur un port spécifique.                                                                               |
| `tcpdump -i eth0 not udp`                                                                                       | Capture uniquement le trafic qui n’est pas UDP.                                                                                   |
| `tcpdump -i eth0 host 192.168.1.10 or port 80`                                                                  | Capture uniquement le trafic de l'hôte 192.168.1.10 OU le traffic du port 80.                                                     |
| `tcpdump -i eth0 host 192.168.1.10 and port 80`                                                                 | Capture uniquement le trafic de l'hôte 192.168.1.10 ET le traffic du port 80.                                                     |
| `tcpdump -i eth0 src 192.168.1.10`                                                                              | Capture le traffic provenant de 192.168.1.10.                                                                                     |
| `tcpdump -i eth0 dest 192.168.1.10`                                                                             | Capture le traffic à destination de 192.168.1.10.                                                                                 |

***

### **Conclusion**

TCPDump est un outil essentiel pour l’analyse réseau, offrant des capacités puissantes de capture et de filtrage. Que ce soit pour diagnostiquer des problèmes réseau, analyser du trafic HTTP ou surveiller des connexions suspectes, TCPDump est un incontournable pour tout pentester ou administrateur réseau.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
