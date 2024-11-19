# Acunetix

**Introduction**

\
Acunetix est un scanner de vulnérabilités web automatisé qui identifie les failles de sécurité dans les applications web telles que les injections SQL, les vulnérabilités XSS et les erreurs de configuration. Il fournit des rapports détaillés pour aider à corriger les vulnérabilités découvertes.

**Installation d'Acunetix**

* **Sous Linux/macOS/Windows** : Téléchargez la version d’évaluation ou achetez une licence depuis le [site officiel d’Acunetix](https://www.acunetix.com/). Suivez les instructions pour l’installation spécifique à votre système d'exploitation.

**Utilisation de Base**

1.  **Lancer une Analyse de Site**

    * **Commande** : Accédez à l’interface web d’Acunetix (`https://localhost:443`), allez dans `Scans` et créez un nouveau scan en entrant l’URL du site cible.

    **Explication** : Acunetix scanne le site web pour détecter des vulnérabilités potentielles en explorant les pages, les formulaires, et les paramètres de requêtes.\

2.  **Configurer des Analyses Programmées**

    * **Commande** : Interface web d'Acunetix, dans `Scans > New Scan`, configurez les paramètres pour une analyse récurrente, en définissant la fréquence et les heures d'exécution.

    **Explication** : Permet de planifier des analyses automatiques pour surveiller les applications web régulièrement pour de nouvelles vulnérabilités.\


**Options Avancées**

1.  **Configurer les Profils d'Analyse**

    * **Commande** : Lors de la création d'un scan dans l'interface web, accédez aux paramètres avancés pour ajuster les politiques de sécurité, les types de tests à effectuer, et les chemins à exclure.

    **Explication** : Personnalise les paramètres de l’analyse pour répondre à des besoins spécifiques, comme exclure certains répertoires ou inclure des tests de sécurité particuliers.\

2.  **Génération et Exportation des Rapports**

    * **Commande** : Accédez à `Scans > Reports`, sélectionnez le rapport d'analyse, et exportez-le en PDF, HTML, ou CSV.

    **Explication** : Exporte les résultats de l’analyse pour une évaluation et une documentation plus approfondies. Les rapports contiennent des détails sur les vulnérabilités trouvées et les recommandations de correction.\


**Exemples d'Analyses**

1.  **Analyse d’un Site pour les Injections SQL**

    * **Commande** : Configurez le scan pour inclure les tests de vulnérabilités SQL et lancez-le.

    **Explication** : Identifie les points faibles dans les formulaires et les paramètres de requêtes susceptibles d’être vulnérables aux injections SQL.\

2.  **Analyse pour les Vulnérabilités XSS**

    * **Commande** : Configurez le scan pour inclure des tests pour les vulnérabilités Cross-Site Scripting (XSS).

    **Explication** : Détecte les failles XSS dans les applications web en testant les entrées des utilisateurs et les réponses du serveur.\
