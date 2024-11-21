# Nmap

## Nmap - Guide Complet pour l'Analyse et l'Audit de Réseaux

***

### Introduction

**Nmap** est un outil incontournable pour les administrateurs systèmes, les pentesters et les chercheurs en cybersécurité. Il est utilisé pour :

* Explorer des réseaux et identifier des hôtes.
* Scanner les ports ouverts et détecter les services.
* Auditer les systèmes pour identifier des vulnérabilités.

***

### 🚀 Étape 1 : Installation de Nmap

***

#### Installation sur Linux

**1. Installer depuis les dépôts (Debian/Ubuntu)**

```bash
sudo apt update
sudo apt install nmap
```

**2. Vérifier l’installation**

```bash
nmap --version
```

> Si cette commande affiche la version de Nmap, l’installation a réussi.

***

#### Installation sur macOS

1.  **Installer Homebrew** (si non installé) :

    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
2.  **Installer Nmap via Homebrew** :

    ```bash
    brew install nmap
    ```
3.  **Vérifier l’installation** :

    ```bash
    nmap --version
    ```

***

#### Installation sur Windows

1. Téléchargez l'installeur depuis le site officiel : https://nmap.org/download.html.
2. Installez-le en suivant les instructions à l’écran.
3.  Lancez une invite de commande et testez avec :

    ```cmd
    nmap --version
    ```

***

### 🚀 Étape 2 : Types de Scans et Commandes

***

#### 1. Analyses TCP Basées sur des Indicateurs

Ces analyses manipulent les indicateurs TCP pour provoquer différentes réponses des ports.

| **Type d'Analyse**            | **Commande**                                          | **Description**                                                                                      |
| ----------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **Analyse TCP nulle**         | `sudo nmap -sN MACHINE_IP`                            | N'envoie aucun indicateur TCP (ni SYN, FIN, RST, etc.).                                              |
| **Analyse TCP FIN**           | `sudo nmap -sF MACHINE_IP`                            | Envoie un paquet avec l'indicateur FIN activé.                                                       |
| **Scan de Noël TCP**          | `sudo nmap -sX MACHINE_IP`                            | Active les indicateurs FIN, PSH, et URG, comme une guirlande.                                        |
| **Analyse TCP Maimon**        | `sudo nmap -sM MACHINE_IP`                            | Exploite une particularité de certains systèmes avec des paquets TCP FIN/ACK.                        |
| **Analyse TCP ACK**           | `sudo nmap -sA MACHINE_IP`                            | Utilisée pour vérifier les règles du pare-feu (ports filtrés ou non).                                |
| **Analyse de fenêtre TCP**    | `sudo nmap -sW MACHINE_IP`                            | Une variante de l'analyse ACK qui mesure la taille de la fenêtre TCP pour déterminer l'état du port. |
| **Analyse TCP personnalisée** | `sudo nmap --scanflags URGACKPSHRSTSYNFIN MACHINE_IP` | Envoie des paquets avec des indicateurs TCP définis manuellement.                                    |

***

#### 2. Techniques d'Usurpation et de Masquage

| **Option**                | **Commande**                                   | **Description**                                                   |
| ------------------------- | ---------------------------------------------- | ----------------------------------------------------------------- |
| **IP source usurpée**     | `sudo nmap -S SPOOFED_IP MACHINE_IP`           | Envoie des paquets avec une adresse IP source usurpée.            |
| **Adresse MAC usurpée**   | `sudo nmap --spoof-mac SPOOFED_MAC MACHINE_IP` | Change l'adresse MAC pour masquer l'origine des paquets.          |
| **Scan de leurre**        | `nmap -D DECOY_IP,ME MACHINE_IP`               | Ajoute des hôtes leurres pour masquer l'origine réelle du scan.   |
| **Scan inactif (zombie)** | `sudo nmap -sI ZOMBIE_IP MACHINE_IP`           | Utilise une machine "zombie" pour effectuer le scan en votre nom. |
| **Fragmentation IP**      | `nmap -f` ou `nmap -ff`                        | Divise les paquets en fragments pour contourner certains IDS/IPS. |

***

#### 3. Ajout de Données Personnalisées

| **Option**                   | **Commande**             | **Description**                                                     |
| ---------------------------- | ------------------------ | ------------------------------------------------------------------- |
| **Port source personnalisé** | `--source-port PORT_NUM` | Définit un port source spécifique pour le scan.                     |
| **Données aléatoires**       | `--data-length NUM`      | Ajoute des données aléatoires pour atteindre une taille spécifique. |

***

### 🚀 Options et Explications

***

#### Options Verbosité et Débogage

| **Option** | **Description**                                                                               |
| ---------- | --------------------------------------------------------------------------------------------- |
| `-v`       | Mode verbeux (affiche plus de détails).                                                       |
| `-vv`      | Mode très verbeux.                                                                            |
| `-d`       | Mode débogage.                                                                                |
| `-dd`      | Mode débogage avancé.                                                                         |
| `--reason` | Explique les conclusions du scan (par exemple : pourquoi un port est considéré comme ouvert). |

***

#### Options de Détection

| **Option**            | **Description**                                                                            |
| --------------------- | ------------------------------------------------------------------------------------------ |
| `-sV`                 | Détecte les services en cours d'exécution et leurs versions.                               |
| `-sV --version-light` | Utilise les sondes les plus probables pour détecter les versions de service (plus rapide). |
| `-sV --version-all`   | Essaie toutes les sondes disponibles pour plus de précision (plus lent).                   |
| `-O`                  | Détecte le système d'exploitation de la cible.                                             |
| `--traceroute`        | Exécute un traceroute vers la cible pour identifier le chemin réseau.                      |
| `-A`                  | Combine les options `-sV`, `-O`, et `--traceroute` pour une analyse approfondie.           |

***

#### Options de Sortie

| **Option** | **Description**                                                                                      |
| ---------- | ---------------------------------------------------------------------------------------------------- |
| `-oN file` | Sauvegarde les résultats au format texte classique.                                                  |
| `-oG file` | Sauvegarde les résultats dans un format compatible grep.                                             |
| `-oX file` | Sauvegarde les résultats au format XML.                                                              |
| `-oA base` | Sauvegarde les résultats dans les trois formats en utilisant "base" comme préfixe pour les fichiers. |

***

### 🚀 Scripts Nmap (NSE - Nmap Scripting Engine)

***

Les scripts Nmap ajoutent une couche de fonctionnalités avancées pour l'analyse des vulnérabilités, l'audit de sécurité, et plus encore.

#### Catégories de Scripts

| **Catégorie** | **Description**                                                                  |
| ------------- | -------------------------------------------------------------------------------- |
| `auth`        | Scripts liés à l'authentification (exemple : tests de connexion).                |
| `discovery`   | Découverte des informations accessibles (DNS, base de données, etc.).            |
| `brute`       | Effectue des attaques par force brute.                                           |
| `vuln`        | Vérifie la présence de vulnérabilités connues.                                   |
| `exploit`     | Exploite les vulnérabilités pour obtenir un accès ou des informations sensibles. |
| `dos`         | Détecte les services vulnérables aux attaques par déni de service (DoS).         |
| `malware`     | Recherche des traces de logiciels malveillants (backdoors, etc.).                |
| `safe`        | Scripts sûrs à exécuter sans risque de planter la cible.                         |

***

#### Utilisation des Scripts

| **Commande**               | **Description**                                       |
| -------------------------- | ----------------------------------------------------- |
| `--script=script_name`     | Lance un script spécifique.                           |
| `--script="default"`       | Lance les scripts par défaut (équivalent à `-sC`).    |
| `--script=vuln`            | Exécute tous les scripts liés aux vulnérabilités.     |
| `--script="vuln or brute"` | Exécute les scripts des catégories "vuln" et "brute". |

***

#### Exemples Pratiques

1.  **Vérifier les Vulnérabilités SMB** :

    ```bash
    nmap --script=smb-vuln-* -p 445 192.168.1.10
    ```
2.  **Tester les Logins FTP avec Force Brute** :

    ```bash
    nmap --script=ftp-brute -p 21 192.168.1.10
    ```
3.  **Découvrir les Services Web** :

    ```bash
    nmap --script=http-* -p 80,443 192.168.1.0/24
    ```

***

### 📋 Exemples Combinés

***

#### 1. Analyse Complète d'un Hôte

*   **Commande** :

    ```bash
    sudo nmap -A -p- 192.168.1.10
    ```
* **Explication** :
  * Combine la détection de version, de système d'exploitation, et un traceroute sur tous les ports.

***

#### 2. Analyse Silencieuse avec Fragmentation

*   **Commande** :

    ```bash
    sudo nmap -f -sS -T2 -p 22,80,443 192.168.1.10
    ```
* **Explication** :
  * Utilise des paquets fragmentés (`-f`) pour contourner les IDS, une analyse SYN (`-sS`) avec une vitesse lente (`-T2`).

***

#### 3. Sauvegarder les Résultats dans Plusieurs Formats

*   **Commande** :

    ```bash
    nmap -oA scan_results -p 22,80,443 192.168.1.0/24
    ```
* **Explication** :
  * Sauvegarde les résultats en formats texte, XML, et grepable sous le préfixe "scan\_results".

***

### 📖 Bonnes Pratiques

1. **Obtenez des autorisations légales** :
   * Effectuez vos scans uniquement sur des réseaux où vous avez les permissions.
2. **Commencez par des analyses discrètes** :
   * Si nécessaire, utilisez des scans masqués (`-f`, `-T2`), surtout dans des environnements sensibles.
3. **Analyser les résultats avec des outils externes** :
   * Exportez vos résultats au format XML pour les utiliser avec des outils comme **Metasploit** ou **OpenVAS**.