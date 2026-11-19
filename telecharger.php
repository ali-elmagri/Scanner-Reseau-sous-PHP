<?php
// Téléchargement du dernier rapport CSV, réservé aux utilisateurs connectés
require __DIR__ . '/inc/securite.php';
require __DIR__ . '/config.php';
exigerConnexion();

$fichier = FICHIER_RAPPORT;
if (!is_file($fichier)) {
    http_response_code(404);
    exit('Aucun rapport disponible.');
}

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="resultat_scan.csv"');
header('Content-Length: ' . filesize($fichier));
readfile($fichier);
