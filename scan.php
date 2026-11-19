<?php
// =======================
// Fonctions utilitaires
// =======================

function obtenirHotesVifs($plage_reseau) {
    $sortie = shell_exec("sudo /usr/bin/nmap -sn $plage_reseau");
    if (!$sortie) return [];
    preg_match_all("/Nmap scan report for ([\d\.]+)/", $sortie, $correspondances);
    return $correspondances[1] ?? [];
}

function detecterOS($adresse_ip) {
    $sortie = shell_exec("sudo /usr/bin/nmap -O --osscan-guess -T4 $adresse_ip");
    foreach ([
        "/Running:\s*([^\n\r]*)/",
        "/OS details:\s*([^\n\r]*)/",
        "/Aggressive OS guesses:\s*([^\n\r]*)/"
    ] as $motif) {
        if (preg_match($motif, $sortie, $correspondance)) {
            // Supprime tout ce qui suit un pourcentage (ex: "Linux 3.2 - 4.9 (93%)" => "Linux 3.2 - 4.9")
            return preg_replace('/\s*\(\d+%\).*/', '', explode(',', $correspondance[1])[0]);
        }
    }
    return "Inconnu";
}

function detecterPortsOuverts($adresse_ip) {
    $sortie = shell_exec("sudo /usr/bin/nmap -sV $adresse_ip");
    $lignes = explode("\n", $sortie);
    $ports = [];
    $parsing = false;
    foreach ($lignes as $ligne) {
        if (preg_match("/^PORT\s+STATE\s+SERVICE/", $ligne)) {
            $parsing = true;
            continue;
        }
        if ($parsing && preg_match("/^(\d+)\/tcp\s+open\s+(\S+)/", $ligne, $correspondance)) {
            $ports[] = [
                "port" => $correspondance[1],
                "service" => $correspondance[2]
            ];
        }
    }
    return $ports;
}

// =======================
// Traitement des paramètres (francisés)
// =======================

$type_scan = $_GET['type_scan'] ?? '';
$ip = $_GET['ip'] ?? null;
$reseau = $_GET['reseau'] ?? null;
$port = $_GET['port'] ?? null;
$reseau_defaut = '10.129.59.0/24';

$liste_hotes = [];
$erreur_scan = null;

if ($type_scan === 'unique') {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $erreur_scan = "Adresse IP invalide.";
    } else {
        $hotes_vifs = obtenirHotesVifs($ip . "/32");
        if (empty($hotes_vifs)) {
            $liste_hotes = [];
        } else {
            $liste_hotes = [$ip];
        }
    }
} elseif ($type_scan === 'reseau' && $reseau) {
    $liste_hotes = obtenirHotesVifs($reseau);
} elseif ($type_scan === 'port' && $port && is_numeric($port)) {
    $reseau_a_scanner = $reseau ?: $reseau_defaut;
    $liste_hotes = obtenirHotesVifs($reseau_a_scanner);
} else {
    $erreur_scan = "Paramètres invalides";
}

// =======================
// Affichage pour le scan de port spécifique 
// =======================

if ($type_scan === 'port' && $port && is_numeric($port) && !$erreur_scan) {
    $resultats_scan_port = [];
    foreach ($liste_hotes as $hote) {
        $sortie = shell_exec("sudo /usr/bin/nmap -p " . escapeshellarg($port) . " -T4 " . escapeshellarg($hote));
        $ouvert = false;
        foreach (explode("\n", $sortie) as $ligne) {
            if (preg_match("/^$port\/tcp\s+open/", $ligne)) {
                $ouvert = true;
                break;
            }
        }
        $resultats_scan_port[] = [
            'hote' => $hote,
            'port' => $port,
            'ouvert' => $ouvert
        ];
    }
    ?>
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Résultat du scan de port</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
        <link rel="stylesheet" href="css/style.css">
    </head>
    <body class="bg-light">
    <div class="container my-5">
        <div class="d-flex align-items-center mb-4">
            <a href="index.php" class="btn btn-outline-secondary me-3">
                <i class="bi bi-arrow-left"></i> Retour
            </a>
            <h2 class="mb-0">Scan du port <span class="text-primary"><?= htmlspecialchars($port) ?></span> sur <span class="text-secondary"><?= htmlspecialchars($reseau_a_scanner) ?></span></h2>
        </div>
        <div class="mb-4">
            <div class="alert alert-info d-flex align-items-center mb-0" role="alert">
                <i class="bi bi-info-circle-fill me-2"></i>
                <div>
                    <strong><?= count($resultats_scan_port) ?></strong> hôte(s) scannés pour le port <strong><?= htmlspecialchars($port) ?></strong>.
                </div>
            </div>
        </div>
        <?php if (empty($resultats_scan_port)): ?>
            <div class="alert alert-warning mt-4">Aucun hôte détecté sur ce réseau.</div>
        <?php else: ?>
            <div class="table-responsive my-4">
                <table class="table table-bordered table-hover align-middle">
                    <thead class="table-primary">
                        <tr>
                            <th scope="col">Adresse IP</th>
                            <th scope="col">Port</th>
                            <th scope="col">État</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($resultats_scan_port as $res): ?>
                        <tr>
                            <td>
                                <i class="bi bi-pc-display text-primary me-1"></i>
                                <strong><?= htmlspecialchars($res['hote']) ?></strong>
                            </td>
                            <td>
                                <span class="badge bg-secondary">TCP <?= htmlspecialchars($res['port']) ?></span>
                            </td>
                            <td>
                                <?php if ($res['ouvert']): ?>
                                    <span class="badge bg-success"><i class="bi bi-unlock"></i> Ouvert</span>
                                <?php else: ?>
                                    <span class="badge bg-danger"><i class="bi bi-lock"></i> Fermé</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    exit;
}
// =======================
// Génération du CSV
// =======================
if (!$erreur_scan && !empty($liste_hotes)) {
    $fichier_csv = __DIR__ . '/resultat/resultat_scan.csv';
    $fp = fopen($fichier_csv, 'w');
    fputcsv($fp, ['IP', 'OS', 'Ports ouverts (service)']);
    foreach ($liste_hotes as $adresse_ip) {
        $os = detecterOS($adresse_ip);
        $ports = detecterPortsOuverts($adresse_ip);
        $ports_str = implode(', ', array_map(fn($p) => $p['port'] . ' (' . $p['service'] . ')', $ports));
        fputcsv($fp, [$adresse_ip, $os, $ports_str]);
    }
    fclose($fp);
}


?>
<!DOCTYPE html>
<html lang="fr" class="h-100">
<head>
    <meta charset="UTF-8">
    <title>Résultats du scan réseau</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Résultats détaillés du scan réseau">
    <meta name="theme-color" content="#0d6efd">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="css/style.css">
</head>
<body class="d-flex flex-column h-100 bg-light">
    <!-- Navigation principale -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary sticky-top shadow-sm">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center" href="index.php">
                <i class="bi bi-hdd-network-fill me-2"></i>
                <span class="fw-bold">Surveillance Réseau</span>
            </a>
            <div class="ms-auto d-flex align-items-center">
                <div class="vr bg-white opacity-25 d-none d-lg-block me-3" style="height: 24px;"></div>
                <span class="text-white">
                    <i class="bi bi-pc-display"></i> <?= count($liste_hotes ?? []) ?> hôtes
                </span>
            </div>
        </div>
    </nav>

    <main class="flex-shrink-0 py-4">
    <div class="container">
        <!-- Affichage des erreurs ou des cas où aucun hôte n'est trouvé -->
        <?php if ($erreur_scan): ?>
            <div class="alert alert-danger">Erreur : <?= htmlspecialchars($erreur_scan) ?></div>
        <?php elseif (empty($liste_hotes)): ?>
            <div class="alert alert-warning">
                <?php if ($type_scan === 'unique'): ?>
                    L'adresse IP saisie n'est pas active ou n'existe pas sur le réseau.
                <?php else: ?>
                    Aucun hôte détecté sur ce réseau.
                <?php endif; ?>
            </div>
        <?php endif; ?>

            <!-- Actions principales : retour et téléchargement CSV -->
            <div class="d-sm-flex align-items-center justify-content-between mb-4">
                <a href="index.php" class="btn btn-outline-secondary btn-lg">
                    <i class="bi bi-arrow-left"></i> Retour
                </a>
                <a href="resultat/resultat_scan.csv" download class="btn btn-success btn-lg">
                    <i class="bi bi-file-earmark-spreadsheet"></i> Télécharger CSV
                </a>
            </div>

            <!-- Résumé du scan -->
            <div class="alert alert-info border-0 shadow-sm mb-4" role="alert">
                <div class="d-flex align-items-center">
                    <div class="me-3">
                        <div class="bg-info bg-opacity-25 p-3 rounded-circle">
                            <i class="bi bi-info-circle-fill h4 mb-0 text-info"></i>
                        </div>
                    </div>
                    <div>
                        <h4 class="alert-heading fw-bold mb-1">Résumé du scan</h4>
                        <p class="mb-0 opacity-75">
                            <span class="badge bg-primary rounded-pill me-2"><?= count($liste_hotes ?? []) ?> hôtes</span>
                            <span class="badge bg-secondary rounded-pill me-2"><?= array_sum(array_map(fn($h) => count(detecterPortsOuverts($h)), $liste_hotes)) ?> ports ouverts</span>
                            <span class="badge bg-success rounded-pill">Scan terminé</span>
                        </p>
                    </div>
                </div>
            </div>

            <!-- Résultats détaillés dans un tableau Bootstrap -->
            <div class="table-responsive my-4">
                <table class="table table-bordered table-hover align-middle">
                    <thead class="table-primary">
                        <tr>
                            <th scope="col">Adresse IP</th>
                            <th scope="col">Système d'exploitation</th>
                            <th scope="col">Ports ouverts (service)</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($liste_hotes as $adresse_ip): 
                            $os = detecterOS($adresse_ip);
                            $ports = detecterPortsOuverts($adresse_ip);
                            $ports_str = empty($ports)
                                ? '<span class="text-muted">Aucun</span>'
                                : implode('<br>', array_map(fn($p) => '<span class="badge bg-success me-1">TCP ' . htmlspecialchars($p['port']) . '</span> <span class="text-muted small">' . htmlspecialchars($p['service']) . '</span>', $ports));
                        ?>
                        <tr>
                            <td>
                                <i class="bi bi-pc-display text-primary me-1"></i>
                                <strong><?= htmlspecialchars($adresse_ip) ?></strong>
                            </td>
                            <td>
                                <span class="badge bg-info text-dark">
                                    <i class="bi bi-gear-fill"></i> <?= htmlspecialchars($os) ?>
                                </span>
                            </td>
                            <td><?= $ports_str ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <!-- Fin du tableau -->
        </div>
    </main>

    <!-- Footer -->
    <footer class="pied-page mt-auto py-3 bg-white border-top">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-6 text-center text-md-start">
                    <span class="text-muted">
                        Projet Intégratif - BUT RT1
                    </span>
                </div>
                <div class="col-md-6 text-center text-md-end">
                </div>
            </div>
        </div>
    </footer>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="js/scan.js"></script>
</body>
</html>

