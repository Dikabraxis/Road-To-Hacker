# Zap

## ZAP (OWASP Zed Attack Proxy) - Guide Complet

***

### Introduction

**ZAP** (OWASP Zed Attack Proxy) est un outil de test de sécurité des applications web open-source. Il est conçu pour aider les testeurs de sécurité à identifier les vulnérabilités dans les applications web. Avec ses fonctionnalités telles qu’un proxy interceptant, un scanner actif, et des outils de manipulation des requêtes, ZAP est une solution puissante pour les audits de sécurité.

***

### 🚀 Étape 1 : Installation de ZAP

***

#### 1. Installation via **apt** (pour les distributions Debian/Ubuntu)

ZAP est disponible dans les dépôts officiels des distributions Linux basées sur Debian. Installez-le avec les commandes suivantes :

```bash
sudo apt update
sudo apt install zaproxy
```

* **Explications** :
  * `sudo apt update` : Met à jour la liste des paquets disponibles.
  * `sudo apt install zaproxy` : Installe ZAP Proxy.

***

#### 2. Installation depuis le Site Officiel

1. Accédez au site officiel de ZAP : [OWASP ZAP](https://www.zaproxy.org/).
2. Téléchargez la version appropriée pour votre système d’exploitation (Windows, macOS ou Linux).
3. Suivez les instructions d’installation fournies avec l’installateur.

* **Explication** :
  * Cette méthode garantit que vous installez la dernière version de ZAP.

***

#### 3. Vérifier l’installation

Pour vérifier que ZAP est correctement installé, exécutez :

```bash
zaproxy --version
```

* **Résultat attendu** : La version installée de ZAP sera affichée.

***

### 🚀 Étape 2 : Utilisation de Base

***

#### 1. Démarrer ZAP

Pour lancer ZAP, exécutez :

```bash
zaproxy
```

* **Explication** :
  * Lance l'interface graphique de ZAP.

***

#### 2. Configurer le Proxy

Pour intercepter les requêtes entre le navigateur et l’application cible, configurez votre navigateur pour utiliser le proxy de ZAP :

1. **Port du Proxy** : Par défaut, ZAP utilise `localhost:8080` comme proxy.
2. **Configuration du Navigateur** :
   * Allez dans les paramètres réseau de votre navigateur.
   * Configurez un proxy HTTP avec `localhost` comme adresse et `8080` comme port.

***

#### 3. Scanner une Application Web

**Ajouter une Application Cible**

1. Ouvrez ZAP.
2. Dans le panneau **Sites**, faites un clic droit et sélectionnez **"Add Context"**.
3. Entrez l’URL de l’application cible (par exemple, `http://example.com`).

**Lancer un Scan Actif**

1. Allez dans l’onglet **Active Scan**.
2. Sélectionnez la cible ou le contexte ajouté.
3. Cliquez sur **Start Scan** pour lancer une analyse active des vulnérabilités.

* **Explication** :
  * Un scan actif teste les vulnérabilités en envoyant des requêtes malveillantes et en analysant les réponses.

***

#### 4. Analyser les Résultats

1. Une fois le scan terminé, les résultats apparaîtront dans le panneau **Alerts** ou **Results**.
2. Vous pouvez consulter les détails de chaque vulnérabilité, notamment :
   * Le type de vulnérabilité (Injection SQL, XSS, etc.).
   * Les requêtes et réponses associées.
3. Exportez les résultats via le menu **Reports**.

***

### 🚀 Étape 3 : Options Avancées

***

#### 1. Manipulation des Requêtes

**Rejouer ou Modifier des Requêtes**

1. Interceptez une requête via l’onglet **History**.
2. Modifiez les paramètres ou les en-têtes, puis rejouez-la.

***

#### 2. Utilisation des Add-ons

OWASP ZAP dispose d’un **marketplace** d’add-ons pour ajouter des fonctionnalités supplémentaires, telles que :

* Scan des API REST.
* Test des applications WebSocket.
* Scripts d’automatisation personnalisés.

Pour installer des add-ons :

1. Allez dans **Tools** > **Add-ons**.
2. Recherchez et installez les modules nécessaires.

***

#### 3. Configuration d’un Proxy HTTPS

Pour intercepter le trafic HTTPS :

1. Configurez le certificat SSL de ZAP comme autorité de confiance dans votre navigateur.
   * **Exporter le Certificat** :
     * Dans ZAP, allez dans **Tools** > **Options** > **Dynamic SSL Certificates**.
     * Exportez le certificat et ajoutez-le aux certificats de confiance de votre navigateur.
2. Configurez le proxy de votre navigateur comme expliqué dans la section de base.

***

#### 4. Exécuter ZAP en Mode Ligne de Commande

Pour exécuter un scan rapide sans interface graphique :

```bash
zaproxy -cmd -quickurl http://example.com -quickout report.html
```

* **Explications** :
  * `-cmd` : Lance ZAP en mode commande.
  * `-quickurl` : Spécifie l’URL cible.
  * `-quickout` : Définit le fichier de sortie du rapport.

***

### 🚀 Étape 4 : Exemples de Scénarios

***

#### 1. Scan Complet d’une Application

1. Configurez le proxy dans votre navigateur.
2. Naviguez dans l’application cible pour permettre à ZAP d’enregistrer les pages.
3. Lancez un **Active Scan** sur le site enregistré.

***

#### 2. Test d’une API REST

1. Allez dans **Tools** > **Import OpenAPI Definition**.
2. Importez le fichier OpenAPI (Swagger) de l’API.
3. Configurez un scan sur les endpoints identifiés.

***

#### 3. Automatisation des Tests

Pour intégrer ZAP dans des pipelines CI/CD (par exemple, avec Jenkins) :

1. Utilisez le mode commande pour lancer des scans.
2. Exportez les résultats sous forme de rapports compatibles CI/CD.

***

### 📖 Bonnes Pratiques

***

#### 1. Obtenir des Autorisations

* **Important** : Ne scannez jamais une application sans autorisation explicite.
* **Respectez les lois** : Toute analyse non autorisée peut entraîner des poursuites judiciaires.

#### 2. Limiter les Impacts

* Configurez des délais entre les requêtes pour éviter de surcharger le serveur.
* Effectuez les tests en dehors des heures de production.

#### 3. Analyser les Résultats avec Soin

* Évitez les faux positifs en validant les vulnérabilités détectées.
* Priorisez les correctifs en fonction de la gravité des problèmes.

***

### Conclusion

OWASP ZAP est un outil essentiel pour les professionnels de la cybersécurité, offrant des fonctionnalités puissantes pour tester la sécurité des applications web. Que vous soyez débutant ou expérimenté, ZAP peut s’intégrer dans votre workflow pour améliorer la sécurité des applications.
