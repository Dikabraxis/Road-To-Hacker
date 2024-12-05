# Onesixtyone

### **onesixtyone - Guide Complet pour Tester et Énumérer les Community Strings SNMP**

***

### **Introduction**

**onesixtyone** est un outil rapide et léger conçu pour le brute-forcing des **community strings** sur des appareils SNMP. Il est particulièrement utile pour identifier les chaînes d'accès SNMP faibles ou par défaut, comme `public` ou `private`. L'outil peut tester rapidement plusieurs cibles sur un réseau, ce qui en fait un outil incontournable pour les pentesters et les administrateurs réseau.

***

### **🚀 Étape 1 : Installation de onesixtyone**

**1. Installation sur Linux (Debian/Ubuntu)**

1.  Mettez à jour vos paquets :

    ```bash
    sudo apt update
    ```
2.  Installez onesixtyone :

    ```bash
    sudo apt install onesixtyone
    ```
3.  Vérifiez l'installation :

    ```bash
    onesixtyone -h
    ```

***

**2. Installation depuis les Sources**

1.  Clonez le dépôt officiel :

    ```bash
    git clone https://github.com/roesch/onesixtyone.git
    ```
2.  Compilez le programme :

    ```bash
    cd onesixtyone
    make
    ```
3.  Exécutez le programme :

    ```bash
    ./onesixtyone -h
    ```

***

**3. Installation sur Windows**

1. Installez une distribution Linux via **WSL** ou utilisez une machine virtuelle.
2. Suivez les étapes pour Linux.

***

### **🛠️ Étape 2 : Utilisation de Base de onesixtyone**

**1. Scanner une Cible Unique**

Commande :

```bash
onesixtyone -c community_strings.txt <target>
```

**Explications :**

* `-c community_strings.txt` : Spécifie un fichier contenant les chaînes à tester.
* `<target>` : Adresse IP ou nom d'hôte de l'appareil cible.

**Exemple :**

```bash
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.1.1
```

***

**2. Scanner Plusieurs Cibles**

Commande :

```bash
onesixtyone -c community_strings.txt -i targets.txt
```

**Explications :**

* `-i targets.txt` : Spécifie un fichier contenant une liste d'adresses IP ou de noms d'hôte à scanner.

**Exemple de contenu pour `targets.txt` :**

```
192.168.1.1
192.168.1.2
192.168.1.3
```

***

**3. Utiliser une Community String Unique**

Pour tester une chaîne spécifique :

```bash
onesixtyone -c - <target>
```

Puis entrez manuellement la chaîne.

**Exemple :**

```bash
onesixtyone -c - 192.168.1.1
public
```

***

**4. Scanner un Réseau Complet**

Commande :

```bash
onesixtyone -c community_strings.txt 192.168.1.0/24
```

**Explications :**

* Scanne toutes les adresses dans la plage `192.168.1.0/24`.

***

### **🔍 Étape 3 : Cas Pratiques avec onesixtyone**

**1. Identifier les Community Strings Valides**

Commande :

```bash
onesixtyone -c community_strings.txt 192.168.1.1
```

**Résultat attendu :** Si une chaîne est valide, elle est affichée avec des détails sur le dispositif.

***

**2. Découverte des Dispositifs SNMP sur un Réseau**

1. Créez un fichier `targets.txt` contenant toutes les adresses IP du réseau.
2.  Lancez le scan :

    ```bash
    onesixtyone -c community_strings.txt -i targets.txt
    ```

***

**3. Tester des Chaînes Connues**

Vous pouvez utiliser des listes prédéfinies comme celles-ci :

```bash
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.1.1
```

**Exemples de chaînes courantes :**

* `public`
* `private`
* `snmp`
* `default`

***

### **📋 Étape 4 : Optimisations et Techniques Avancées**

**1. Enregistrer les Résultats**

Pour sauvegarder les résultats dans un fichier :

```bash
onesixtyone -c community_strings.txt -i targets.txt > results.txt
```

***

**2. Limiter les Requêtes Simultanées**

Pour éviter de surcharger le réseau, réduisez les requêtes parallèles :

```bash
onesixtyone -c community_strings.txt -i targets.txt -t 5
```

**Explications :**

* `-t 5` : Limite à 5 requêtes simultanées.

***

**3. Utiliser en Conjonction avec snmpwalk**

Après avoir identifié une chaîne valide, utilisez **snmpwalk** pour explorer les OID disponibles :

```bash
snmpwalk -v 2c -c <valid_community_string> <target>
```

**Exemple :**

```bash
snmpwalk -v 2c -c public 192.168.1.1
```

***

**4. Automatiser le Scan avec un Script**

Pour exécuter onesixtyone sur plusieurs réseaux :

```bash
#!/bin/bash
for subnet in 192.168.1.0/24 192.168.2.0/24; do
    onesixtyone -c community_strings.txt $subnet >> results.txt
done
```

***

#### **5. Résultats Attendus**

*   **Si une Community String est Valide :**

    ```scss
    192.168.1.1 [public] Linux 3.10.0-957.el7.x86_64 (x86_64)
    ```
*   **Si Aucune String n'est Valide :**

    ```css
    192.168.1.1 [No Response]
    ```

***

#### **6. Sécurisation Contre les Failles Onesixyone**

1. **Changer les Community Strings :**
   * Remplacez les chaînes par défaut (`public`, `private`) par des valeurs fortes et uniques.
2. **Limiter l'Accès SNMP :**
   * Configurez des ACL pour n'autoriser que des adresses IP de confiance.
3. **Désactiver SNMP si Non Nécessaire :**
   * Supprimez SNMP sur les dispositifs où il n’est pas utilisé.
4. **Utiliser SNMPv3 :**
   * Préférez SNMPv3, qui inclut des mécanismes de chiffrement et d'authentification.
5. **Surveiller les Journaux SNMP :**
   * Analysez les logs pour détecter des scans ou des tentatives d'accès non autorisés.

***

### **Résumé des Commandes Clés**

| Commande                                              | Description                              |
| ----------------------------------------------------- | ---------------------------------------- |
| `onesixtyone -c community_strings.txt <target>`       | Teste les chaînes sur une cible unique.  |
| `onesixtyone -c community_strings.txt -i targets.txt` | Teste les chaînes sur plusieurs cibles.  |
| `onesixtyone -c community_strings.txt 192.168.1.0/24` | Scanne une plage d’adresses IP.          |
| `onesixtyone -c - <target>`                           | Permet d'entrer une chaîne manuellement. |

***

Avec **onesixtyone**, vous disposez d’un outil rapide et efficace pour identifier les failles liées aux community strings SNMP. Utilisé avec d'autres outils comme **snmpwalk**, il permet une énumération approfondie des dispositifs réseau. Assurez-vous toujours d’avoir une autorisation légale avant de l’utiliser.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
