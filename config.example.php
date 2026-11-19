<?php
// Copier ce fichier en config.php puis remplacer l'empreinte du mot de passe.
// Générer une empreinte avec :
//   php -r 'echo password_hash("mon-mot-de-passe", PASSWORD_DEFAULT), PHP_EOL;'
// config.php est exclu du dépôt Git (.gitignore).

const ADMIN_UTILISATEUR = 'admin';
const ADMIN_EMPREINTE   = 'remplacer-par-une-empreinte-password_hash';

// Fichier du dernier rapport CSV : en dehors du dossier publié par le serveur web,
// pour qu'il ne soit accessible qu'à travers telecharger.php (après connexion)
const FICHIER_RAPPORT = '/var/lib/scanner-reseau/resultat_scan.csv';

// Réseau proposé par défaut dans le formulaire
const RESEAU_DEFAUT = '192.168.1.0/24';
