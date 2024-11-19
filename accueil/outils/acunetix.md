# Acunetix

## Acunetix - Scanner de Vulnérabilités Web

### Introduction

**Acunetix** est un scanner de vulnérabilités web automatisé conçu pour identifier des failles critiques telles que :

* **Injections SQL**
* **Vulnérabilités XSS**
* **Erreurs de configuration de serveur**

#### Pourquoi utiliser Acunetix ?

* **Gain de temps** : Analyse automatique des applications web.
* **Rapports détaillés** : Des recommandations pour corriger les vulnérabilités.
* **Large couverture** : Scans personnalisables et tests avancés.

***

### 🚀 Installation d'Acunetix

#### Systèmes supportés :

* **Windows**
* **Linux**
* **macOS**

#### Étapes pour l'installation :

1. **Télécharger le logiciel** :
   * Rendez-vous sur le [site officiel d'Acunetix](https://www.acunetix.com/) et téléchargez la version d’évaluation ou achetez une licence.
2. **Suivez les instructions spécifiques** :
   * **Windows** :
     * Double-cliquez sur l’exécutable téléchargé et suivez l’assistant.
     * Une fois installé, démarrez le service via l'interface ou la ligne de commande.
   * **Linux/macOS** :
     *   Exécutez la commande :

         ```bash
         sudo dpkg -i acunetix_installer.deb
         ```

         Ou pour les systèmes RPM :

         ```bash
         sudo rpm -i acunetix_installer.rpm
         ```
     * Accédez à l'interface web : `https://localhost:443`.

***

### 🛠️ Utilisation de base

#### 1. Lancer une Analyse de Site

* **Accès** : Ouvrez votre navigateur et accédez à : `https://localhost:443`.
* **Étapes** :
  1. Connectez-vous à l'interface web.
  2. Allez dans **`Scans`** → **`New Scan`**.
  3. Entrez l’URL du site cible (ex. : `http://example.com`).
  4. Cliquez sur **`Start`**.

> 💡 **Astuce** : Activez les options de crawling pour explorer toutes les pages et paramètres dynamiques du site.

***

#### 2. Configurer des Analyses Programmées

* **Objectif** : Planifiez des analyses récurrentes pour surveiller régulièrement les nouvelles vulnérabilités.
* **Étapes** :
  1. Accédez à **`Scans`** → **`New Scan`**.
  2. Configurez :
     * **Fréquence** (quotidienne, hebdomadaire, mensuelle).
     * **Heure d’exécution**.
  3. Activez les notifications pour recevoir les résultats par email.

> ⚠️ **Attention** : Assurez-vous que votre serveur cible accepte les scans à la fréquence choisie pour éviter tout blocage.

***

### 🔍 Options avancées

#### 1. Configurer les Profils d'Analyse

* **Pourquoi ?** :
  * Personnalisez les types de tests (ex. : uniquement SQL/XSS).
  * Excluez certains chemins pour éviter les faux positifs.
* **Étapes** :
  1. Lors de la création d'un scan, allez dans **`Advanced Settings`**.
  2. Modifiez :
     * **Politiques de sécurité** (par exemple : OWASP Top 10).
     * **Chemins exclus** : `/admin`, `/test`.
  3. Enregistrez votre profil pour l'utiliser lors des futures analyses.

***

#### 2. Génération et Exportation des Rapports

* **Étapes** :
  1. Une fois le scan terminé, allez dans **`Scans`** → **`Reports`**.
  2. Sélectionnez un format :
     * **PDF** : Lisible pour les réunions ou les présentations.
     * **HTML** : Facilement partageable.
     * **CSV** : Pratique pour une analyse approfondie des résultats.
  3. Exportez le rapport et partagez-le avec votre équipe.

> 💡 **Astuce** : Choisissez un format interactif pour les rapports HTML afin de naviguer facilement entre les vulnérabilités.

***

### 📋 Exemples d'analyses

#### 1. Analyse pour les Injections SQL

* **Configuration** :
  * Activez les tests SQL Injection dans **`Advanced Settings`**.
  * Ciblez les formulaires et URL dynamiques.
*   **Commandes associées** :

    ```bash
    nmap --script http-sql-injection http://example.com
    ```
* **Explication** : Identifie les champs susceptibles d'accepter des requêtes malveillantes.

***

#### 2. Analyse pour les Vulnérabilités XSS

* **Configuration** :
  * Activez les tests XSS dans **`Advanced Settings`**.
  * Ciblez les champs de saisie utilisateur (recherche, commentaires).
* **Exemple** :
  *   Si le scan détecte une vulnérabilité, essayez :

      ```html
      <script>alert('XSS')</script>
      ```
* **Explication** : Vérifie si les entrées utilisateur sont mal filtrées et peuvent exécuter du code malveillant.
