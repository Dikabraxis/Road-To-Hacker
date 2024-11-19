# Recon-ng

#### Introduction

Recon-ng est conçu pour faciliter l'automatisation de la reconnaissance et de la collecte d'informations sur des cibles. Il offre une interface en ligne de commande avec une série de modules pour différents types de collecte de données.

#### Installation de Recon-ng

Recon-ng peut être installé directement depuis GitHub. Voici comment procéder :

**Installation sur Linux**

1.  **Cloner le dépôt GitHub**

    ```bash
    git clone https://github.com/lanmaster53/recon-ng.git
    ```
2.  **Accéder au répertoire Recon-ng**

    ```bash
    cd recon-ng
    ```
3.  **Installer les dépendances Python**

    ```bash
    pip install -r REQUIREMENTS
    ```
4.  **Lancer Recon-ng**

    ```bash
    ./recon-ng
    ```

#### Commandes de Base

**Démarrer Recon-ng**

1. **Lancer Recon-ng**

```bash
./recon-ng
```

* **Explication** : Lance l'interface en ligne de commande de Recon-ng.



**Créer un Workspace**

2. **Créer un nouveau workspace**

```bash
workspaces create <workspace_name>
```

* **Explication** : Crée un nouvel espace de travail pour organiser les enquêtes. Les espaces de travail permettent de séparer les projets et les données.



**Importer un Domaine**

3. **Ajouter un domaine à l'espace de travail**

```bash
modules load recon/domains-hosts/baidu_ip
options set SOURCE <domain>
options set IP 1
run
```

* **Explication** : Charge un module spécifique (`baidu_ip`) pour ajouter un domaine et collecter des informations sur les adresses IP associées.



#### Modules de Collecte d'Information

**Recherche de Domaines et de Sous-domaines**

1.  **Rechercher des sous-domaines**

    ```bash
    modules load recon/domains-hosts/bing_domain
    options set SOURCE <domain>
    run
    ```

    * **Explication** : Utilise le module `bing_domain` pour rechercher des sous-domaines en utilisant Bing.


2.  **Rechercher des informations sur les adresses IP**

    ```bash
    modules load recon/hosts-hosts/resolve
    options set SOURCE <domain>
    run
    ```

    * **Explication** : Utilise le module `resolve` pour résoudre les adresses IP associées à un domaine.



**Collecte d'Informations sur les Adresses E-mail**

3. **Trouver des adresses e-mail associées à un domaine**

```bash
modules load recon/emails-contacts/emailharvest
options set SOURCE <domain>
run
```

* **Explication** : Utilise le module `emailharvest` pour rechercher des adresses e-mail associées à un domaine.



#### Utilisation des Modules d'Exploitation

**Découverte d'Informations sur les Serveurs**

4. **Découverte des serveurs web**

```bash
modules load recon/hosts-hosts/http_header
options set SOURCE <domain>
run
```

* **Explication** : Utilise le module `http_header` pour analyser les en-têtes HTTP des serveurs web associés à un domaine.



**Analyse de Réseaux Sociaux**

5. **Rechercher des informations sur les réseaux sociaux**

```bash
modules load recon/contacts-social/facebook
options set SOURCE <username>
run
```

* **Explication** : Utilise le module `facebook` pour rechercher des informations publiques associées à un nom d'utilisateur sur Facebook.



#### Exporter et Sauvegarder les Résultats

1.  **Exporter les résultats vers un fichier**

    ```bash
    show hosts
    save <file_name>.csv
    ```

    * **Explication** : Affiche les hôtes collectés et sauvegarde les résultats dans un fichier CSV.


2.  **Sauvegarder l'espace de travail**

    ```bash
    workspaces export <file_name>.json
    ```

    * **Explication** : Sauvegarde l'espace de travail actuel dans un fichier JSON pour une utilisation ultérieure ou une analyse approfondie.



#### Exemples de Scénarios

**Collecte d'Informations de Base**

1.  **Rechercher des sous-domaines et des IPs**

    ```bash
    workspaces create example_workspace
    modules load recon/domains-hosts/baidu_ip
    options set SOURCE example.com
    options set IP 1
    run
    ```

**Collecte d'Adresses E-mail**

2. **Trouver des adresses e-mail associées à un domaine**

```bash
modules load recon/emails-contacts/emailharvest
options set SOURCE example.com
run
```

**Exportation des Données Collectées**

3. **Exporter les résultats**

```bash
show hosts
save example_results.csv
```

#### Bonnes Pratiques

1. **Obtenir des Autorisations**
   * **Assurez-vous toujours** d'avoir les autorisations nécessaires avant de collecter des informations sur des cibles.
   * **Respectez les lois et les politiques** de confidentialité.
2. **Utiliser des Sources Publiques**
   * **Collectez des informations à partir de sources publiques** pour éviter d'attirer une attention indésirable.
3. **Minimiser l'Impact**
   * **Limiter la fréquence des requêtes** pour éviter de surcharger les services et d'attirer des alertes.
