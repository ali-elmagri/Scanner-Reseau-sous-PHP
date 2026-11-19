<?php
require __DIR__ . '/inc/securite.php';
require __DIR__ . '/config.php';
exigerConnexion();

// Le scan ne se lance que depuis le formulaire de l'application (POST + jeton CSRF)
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !verifierCsrf()) {
    header('Location: index.php');
    exit;
}

// Un scan de réseau complet peut durer plusieurs minutes
set_time_limit(900);

// Taille maximale d'un réseau scanné : /24, soit 256 adresses
const PREFIXE_MINIMUM = 24;

// =======================
// Fonctions utilitaires
// =======================

// Lance Nmap avec une liste d'arguments, chacun protégé par escapeshellarg().
// --privileged : Nmap utilise les capacités réseau accordées au binaire (setcap)
// au lieu de demander les droits root, ce qui évite d'exécuter Nmap avec sudo.
// -n : pas de résolution DNS, pour des sorties plus rapides et plus simples à analyser.
function executerNmap(array $arguments): string
{
    $commande = '/usr/bin/nmap --privileged -n';
    foreach ($arguments as $argument) {
        $commande .= ' ' . escapeshellarg((string)$argument);
    }
    return (string)shell_exec($commande . ' 2>/dev/null');
}

// Vérifie qu'une plage est au format IPv4/CIDR (ex : 192.168.1.0/24) et pas trop grande
function estReseauValide($plage): bool
{
    if (!is_string($plage) || !preg_match('#^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$#', $plage, $m)) {
        return false;
    }
    $prefixe = (int)$m[2];
    return filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
        && $prefixe >= PREFIXE_MINIMUM && $prefixe <= 32;
}

// Découverte des hôtes actifs (ping scan, sans scan de ports)
function obtenirHotesVifs(string $plage_reseau): array
{
    $sortie = executerNmap(['-sn', $plage_reseau]);
    preg_match_all('/Nmap scan report for (\d{1,3}(?:\.\d{1,3}){3})/', $sortie, $correspondances);
    return $correspondances[1] ?? [];
}

// Analyse complète d'un hôte en un seul appel à Nmap : système d'exploitation (-O)
// et services (-sV). Retourne ['os' => ..., 'ports' => [['port' => .., 'service' => ..], ...]]
function analyserHote(string $adresse_ip): array
{
    $sortie = executerNmap(['-O', '--osscan-guess', '-sV', '-T4', $adresse_ip]);

    $os = 'Inconnu';
    foreach (['/Running:\s*([^\n\r]*)/', '/OS details:\s*([^\n\r]*)/', '/Aggressive OS guesses:\s*([^\n\r]*)/'] as $motif) {
        if (preg_match($motif, $sortie, $correspondance)) {
            // Garde la première proposition, sans le pourcentage (ex : "Linux 3.2 - 4.9 (93%)")
            $os = trim(preg_replace('/\s*\(\d+%\).*/', '', explode(',', $correspondance[1])[0]));
            break;
        }
    }

    $ports = [];
    preg_match_all('/^(\d+)\/tcp\s+open\s+(\S+)/m', $sortie, $lignes, PREG_SET_ORDER);
    foreach ($lignes as $ligne) {
        $ports[] = ['port' => (int)$ligne[1], 'service' => $ligne[2]];
    }

    return ['os' => $os, 'ports' => $ports];
}

// Neutralise les cellules qui seraient interprétées comme des formules par un tableur
function celluleCsv(string $valeur): string
{
    return preg_match('/^[=+\-@\t\r]/', $valeur) ? "'" . $valeur : $valeur;
}

// =======================
// Lecture et validation des paramètres
// =======================

$type_scan = (string)($_POST['type_scan'] ?? '');
$ip = $_POST['ip'] ?? null;
$reseau = $_POST['reseau'] ?? RESEAU_DEFAUT;
$port = filter_var($_POST['port'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);

$liste_hotes = [];
$erreur_scan = null;

if ($type_scan === 'unique') {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $erreur_scan = 'Adresse IP invalide.';
    } else {
        $liste_hotes = obtenirHotesVifs($ip . '/32');
    }
} elseif ($type_scan === 'reseau' || $type_scan === 'port') {
    if (!estReseauValide($reseau)) {
        $erreur_scan = 'Réseau invalide (format attendu : 192.168.1.0/24, /' . PREFIXE_MINIMUM . ' au maximum).';
    } elseif ($type_scan === 'port' && $port === false) {
        $erreur_scan = 'Port invalide (1 à 65535).';
    } else {
        $liste_hotes = obtenirHotesVifs($reseau);
    }
} else {
    $erreur_scan = 'Type de scan inconnu.';
}

// =======================
// Scan d'un port précis sur tous les hôtes actifs (un seul appel à Nmap)
// =======================

if ($type_scan === 'port' && !$erreur_scan) {
    $reseau_a_scanner = $reseau;
    $ouverts = [];
    if ($liste_hotes) {
        $sortie = executerNmap(array_merge(['-p', $port, '-T4', '-oG', '-'], $liste_hotes));
        preg_match_all('/^Host: (\S+).*Ports: ' . $port . '\/open\//m', $sortie, $correspondances);
        $ouverts = array_flip($correspondances[1]);
    }
    $resultats_scan_port = [];
    foreach ($liste_hotes as $hote) {
        $resultats_scan_port[] = ['hote' => $hote, 'port' => $port, 'ouvert' => isset($ouverts[$hote])];
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
// Analyse des hôtes : chaque hôte n'est scanné qu'une seule fois
// =======================

$resultats = [];
if (!$erreur_scan) {
    foreach ($liste_hotes as $adresse_ip) {
        $resultats[$adresse_ip] = analyserHote($adresse_ip);
    }
}
$total_ports = array_sum(array_map(fn($r) => count($r['ports']), $resultats));

// Enregistrement du rapport CSV hors du dossier web (téléchargement via telecharger.php)
if ($resultats) {
    $fp = @fopen(FICHIER_RAPPORT, 'w');
    if ($fp) {
        fputcsv($fp, ['IP', 'OS', 'Ports ouverts (service)']);
        foreach ($resultats as $adresse_ip => $r) {
            $ports_str = implode(', ', array_map(fn($p) => $p['port'] . ' (' . $p['service'] . ')', $r['ports']));
            fputcsv($fp, [$adresse_ip, celluleCsv($r['os']), celluleCsv($ports_str)]);
        }
        fclose($fp);
    }
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
                    <i class="bi bi-pc-display"></i> <?= count($resultats) ?> hôte(s)
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
                <?php if ($resultats): ?>
                <a href="telecharger.php" class="btn btn-success btn-lg">
                    <i class="bi bi-file-earmark-spreadsheet"></i> Télécharger CSV
                </a>
                <?php endif; ?>
            </div>

            <?php if ($resultats): ?>
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
                            <span class="badge bg-primary rounded-pill me-2"><?= count($resultats) ?> hôte(s)</span>
                            <span class="badge bg-secondary rounded-pill me-2"><?= $total_ports ?> port(s) ouvert(s)</span>
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
                        <?php foreach ($resultats as $adresse_ip => $r):
                            $os = $r['os'];
                            $ports = $r['ports'];
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
            <?php endif; ?>
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
</body>
</html>

