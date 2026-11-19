# Scanner réseau web (PHP + Nmap)

Interface web qui pilote Nmap pour inventorier un réseau local : hôtes actifs, système d'exploitation probable, ports ouverts et services. Les résultats s'affichent dans un tableau et s'exportent en CSV.

Projet intégratif réalisé en première année de BUT Réseaux et Télécommunications (IUT d'Auxerre). La présentation de soutenance est dans `docs/presentation-projet-integratif.pdf`.

## Fonctionnalités

- **Scan d'une machine :** système d'exploitation (`nmap -O --osscan-guess`) et ports ouverts avec leur service (`nmap -sV`).
- **Scan d'un réseau complet :** découverte des hôtes actifs (`nmap -sn`), puis analyse de chacun.
- **Scan d'un port précis :** état d'un port sur tous les hôtes du réseau.
- **Export CSV** des résultats.
- **Accès** par une page de connexion (session PHP).

## Fichiers

| Fichier | Rôle |
|---|---|
| `login.php` / `logout.php` | Connexion et déconnexion |
| `index.php` | Formulaire de scan |
| `scan.php` | Appels à Nmap, analyse des sorties, affichage des résultats et export CSV |
| `js/main.js` | Affichage du bon champ selon le type de scan, validation du formulaire |
| `css/style.css` | Mise en forme (Bootstrap 5 chargé par CDN) |
