# Scanner réseau web (PHP + Nmap)

Interface web qui pilote Nmap pour inventorier un réseau local : hôtes actifs, système d'exploitation probable, ports ouverts et services. Les résultats s'affichent dans un tableau et s'exportent en CSV.

Projet intégratif réalisé en première année de BUT Réseaux et Télécommunications (IUT d'Auxerre).

La présentation de soutenance (`docs/presentation-projet-integratif.pdf`) décrit la version initiale du projet. La version actuelle corrige les failles de sécurité identifiées lors d'une relecture du code : voir la section Sécurité et l'historique des commits.

## Fonctionnalités

- **Scan d'une machine :** système d'exploitation probable et ports ouverts avec leur service, en un seul passage de Nmap (`-O -sV`).
- **Scan d'un réseau :** découverte des hôtes actifs (`-sn`), puis analyse de chacun.
- **Scan d'un port précis :** état de ce port sur tous les hôtes actifs du réseau.
- **Export CSV** du dernier scan, téléchargeable après connexion.

## Architecture

| Fichier | Rôle |
|---|---|
| `inc/securite.php` | Session, en-têtes HTTP de sécurité, contrôle d'accès, jeton CSRF |
| `config.example.php` | Modèle de configuration : compte, emplacement du rapport, réseau par défaut |
| `login.php` / `logout.php` | Connexion et déconnexion |
| `index.php` | Formulaire de scan |
| `scan.php` | Validation des paramètres, appels à Nmap, analyse des sorties, affichage et export CSV |
| `telecharger.php` | Téléchargement du rapport CSV, réservé aux utilisateurs connectés |
| `js/main.js` | Affichage du bon champ selon le type de scan, validation côté navigateur |
| `css/style.css` | Mise en forme (Bootstrap 5 chargé par CDN) |

## Installation (Debian / Ubuntu)

```bash
sudo apt install apache2 php libapache2-mod-php nmap
sudo cp -r . /var/www/html/scanner
cd /var/www/html/scanner

# Configuration : compte administrateur et réseau par défaut
sudo cp config.example.php config.php
php -r 'echo password_hash("choisir-un-mot-de-passe", PASSWORD_DEFAULT), PHP_EOL;'
sudo nano config.php        # coller l'empreinte obtenue dans ADMIN_EMPREINTE

# Dossier du rapport CSV, en dehors du dossier web
sudo mkdir -p /var/lib/scanner-reseau
sudo chown www-data:www-data /var/lib/scanner-reseau

# Droits réseau de Nmap (voir la section Sécurité)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

## Sécurité

Ce projet est un outil de laboratoire, à n'utiliser que sur un réseau dont on a l'autorisation, de préférence depuis une machine virtuelle dédiée.

| Risque | Mesure |
|---|---|
| Injection de commande | Chaque argument passé à Nmap est protégé par `escapeshellarg()`. L'adresse, le réseau (IPv4/CIDR, /24 au maximum) et le port (1 à 65535) sont validés côté serveur. |
| Accès sans authentification | Toutes les pages, scan et téléchargement compris, vérifient la session. |
| Mot de passe | Stocké sous forme d'empreinte (`password_hash`) dans `config.php`, exclu du dépôt. Une pause d'une seconde après chaque échec ralentit la force brute. |
| Vol ou fixation de session | Cookie `HttpOnly` et `SameSite=Strict`, identifiant régénéré à la connexion, expiration après 30 minutes d'inactivité. |
| Requêtes forgées (CSRF) | Connexion et scans en POST avec un jeton aléatoire vérifié par `hash_equals()`. |
| Injection HTML (XSS) | Toutes les données affichées passent par `htmlspecialchars()`. |
| Fuite du rapport | Le CSV est écrit hors du dossier web et servi uniquement par `telecharger.php`. Les cellules commençant par `=`, `+`, `-` ou `@` sont neutralisées pour les tableurs. |
| Droits root | Nmap n'est pas lancé avec `sudo`. Les capacités réseau sont accordées au binaire (`setcap`) et Nmap tourne avec `--privileged` sous l'utilisateur du serveur web. |

**Limites connues**
- Les capacités données à Nmap valent pour tous les utilisateurs de la machine : c'est une raison de plus pour l'installer sur une VM dédiée.
- Le scan est synchrone : la page attend la fin de Nmap, ce qui peut prendre plusieurs minutes sur un réseau /24.
- Un seul compte, et un seul rapport conservé (le dernier scan).
