<?php
// ===============================
// 1. SÉCURITÉ ET PRÉPARATION DES DONNÉES
// ===============================

// Démarre une nouvelle session ou reprend la session existante.
// Cela permet de gérer l'authentification et de conserver les informations de l'utilisateur entre les pages.
session_start();

// Vérifie si l'utilisateur est authentifié en consultant la variable de session 'authenticated'.
// Si l'utilisateur n'est pas connecté, il est redirigé vers la page de connexion pour empêcher l'accès non autorisé.
if (!isset($_SESSION['est_authentifie']) || $_SESSION['est_authentifie'] !== true) {
    header('Location: login.php');
    exit;
}

// Prépare un tableau pour stocker les résultats des scans réseau.
$donnees_scans = [];

// Définit le chemin du fichier CSV contenant les résultats des scans précédents.
$fichier_csv = "resultat/resultat_scan.csv";

// Si le fichier de résultats existe, lit son contenu et le convertit en tableau associatif.
// Chaque ligne du CSV correspond à un scan, avec des colonnes pour l'IP, l'OS, les ports, etc.
if (file_exists($fichier_csv)) {
    $lignes = array_map("str_getcsv", file($fichier_csv)); // Lit chaque ligne du fichier CSV.
    $entetes = array_shift($lignes); // Récupère la première ligne comme en-têtes de colonnes.
    foreach ($lignes as $ligne) {
        $donnees_scans[] = array_combine($entetes, $ligne); // Associe chaque valeur à son en-tête pour chaque scan.
    }
}
?>
<!DOCTYPE html>
<html lang="fr" class="h-100">
<head>
    <meta charset="UTF-8">
    <title>Surveillance Réseau - Scanner</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Scanner réseau avancé pour la détection des systèmes, services et analyse de sécurité en temps réel.">
    <meta name="theme-color" content="#0d6efd">
    <meta name="author" content="BUT RT1">
    <!-- Bootstrap CSS pour le style général -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons pour les icônes -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <!-- Animate.css pour les animations -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/animate.css@4.1.1/animate.min.css">
    <!-- Ajout du CSS personnalisé -->
    <link rel="stylesheet" href="css/style.css">
</head>
<body class="d-flex flex-column h-100 bg-light corps-page">
    <!-- ===============================
         2. NAVIGATION PRINCIPALE
         =============================== -->
    <header>
        <nav class="navbar navbar-expand-lg navbar-dark bg-light sticky-top shadow-sm" aria-label="Navigation principale">
            <div class="container">
                <!-- Logo et nom du projet -->
                <a class="navbar-brand d-flex align-items-center animate__animated animate__fadeIn text-dark" href="#">
                    <i class="bi bi-hdd-network-fill me-2"></i>
                    <span class="fw-bold">Surveillance Réseau</span>
                </a>
                <!-- Bouton burger pour mobile -->
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Basculer la navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <!-- Liens de navigation -->
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav ms-auto">
                        <li class="nav-item">
                            <a class="nav-link active text-dark" href="#"><i class="bi bi-house-fill"></i> Accueil</a>
                        </li>
                        <li class="nav-item">
                            <a href="logout.php" class="nav-link text-dark"><i class="bi bi-box-arrow-right"></i> Déconnexion</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>
    </header>

    <!-- ===============================
         3. FORMULAIRE DE SCAN
         =============================== -->
    <main class="flex-shrink-0" id="main-content">
        <section class="bg-primary bg-gradient text-white py-5 mb-5">
            <div class="container">
                <div class="row justify-content-center">
                    <div class="col-lg-8 text-center animate__animated animate__fadeInUp">
                        <h1 class="display-4 fw-bold mb-4">Scanner réseau avancé</h1>
                        <p class="lead mb-4 opacity-75">Détectez et analysez votre infrastructure réseau en temps réel</p>
                        
                        <!-- Formulaire de scan réseau -->
                        <form action="scan.php" method="GET" class="mb-4">

                                    <!-- Choix du type de scan (radio boutons) -->
                                    <div class="btn-group w-100" role="group" aria-label="Type de scan">
                                        <input type="radio" class="btn-check" name="type_scan" id="scanUnique" value="unique" checked>
                                        <label class="btn btn-outline-light" for="scanUnique">
                                            <i class="bi bi-pc-display"></i> Machine unique
                                        </label>
                                        
                                        <input type="radio" class="btn-check" name="type_scan" id="scanReseau" value="reseau">
                                        <label class="btn btn-outline-light" for="scanReseau">
                                            <i class="bi bi-hdd-network"></i> Réseau complet
                                        </label>

                                        <!-- Scan de port spécifique -->
                                        <input type="radio" class="btn-check" name="type_scan" id="scanPort" value="port">
                                        <label class="btn btn-outline-light" for="scanPort">
                                            <i class="bi bi-plug"></i> Scan de port
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-10 mx-auto">
                                    <!-- Champ pour scan machine unique -->
                                    <div id="champScanUnique" class="w-100 text-center" style="max-width:1000px; margin: 0 auto;">
                                        <div class="input-group input-group-lg shadow-sm w-100">
                                            <input type="text"
                                                id="champIp"
                                                name="ip"
                                                class="form-control border-0 py-3 champ-formulaire"
                                                placeholder="ex: 10.129.59.0"
                                                pattern="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                                                required
                                            />
                                            <button type="submit" class="btn bouton-jaune px-5 w-100">
                                                <i class="bi bi-search"></i>
                                            </button>
                                        </div>
                                    </div>
                                    <!-- Champ pour scan réseau complet -->
                                    <div id="champScanReseau" class="w-100 text-center" style="display:none; max-width:1000px; margin: 0 auto;">
                                        <input type="hidden" name="reseau" value="10.129.59.0/24">
                                        <button type="submit" class="btn btn-light btn-lg w-100 py-3 rounded-3 shadow-sm hover-lift">
                                            <i class="bi bi-hdd-network me-2"></i> Scanner tout le réseau
                                        </button>
                                    </div>
                                    <!-- Champ pour scan de port -->
                                    <div id="champScanPort" class="w-100 text-center" style="display:none; max-width:1000px; margin: 0 auto;">
                                        <div class="input-group input-group-lg shadow-sm mb-2 w-100">
                                            <input type="number" class="form-control border-0 py-3" name="port" id="champPort" placeholder="Port ex: 22" min="1" max="65535" required>
                                            <button type="submit" class="btn bouton-jaune px-5 w-100">
                                                <i class="bi bi-search"></i> Scanner ce port
                                            </button>
                                        </div>
                                        <input type="hidden" name="reseau" value="10.129.59.0/24">
                                        <small class="text-white">Scanne un port précis sur la plage réseau sélectionnée.</small>
                                    </div>
                                </div>
                            </div>
                        </form>

                    </div>
                </div>
            </div>
        </section>

        <!-- ===============================
             8. STATISTIQUES AVANCÉES
             =============================== -->
        <section class="container mb-5">
            <div class="row g-4">
                <!-- Carte : Sécurité renforcée -->
                <div class="col-md-4">
                    <div class="card border-0 shadow-sm h-100">
                        <div class="card-body text-center">
                            <div class="display-4 text-primary mb-3">
                                <i class="bi bi-shield-check"></i>
                            </div>
                            <h3 class="h5 card-title">Sécurité Renforcée</h3>
                            <p class="card-text text-muted">Analysez votre réseau pour détecter les vulnérabilités potentielles</p>
                        </div>
                    </div>
                </div>
                <!-- Carte : Analyse en temps réel -->
                <div class="col-md-4">
                    <div class="card border-0 shadow-sm h-100">
                        <div class="card-body text-center">
                            <div class="display-4 text-success mb-3">
                                <i class="bi bi-graph-up"></i>
                            </div>
                            <h3 class="h5 card-title">Analyse en Temps Réel</h3>
                            <p class="card-text text-muted">Surveillez les performances et l'état de votre réseau en direct</p>
                        </div>
                    </div>
                </div>
                <!-- Carte : Historique détaillé -->
                <div class="col-md-4">
                    <div class="card border-0 shadow-sm h-100">
                        <div class="card-body text-center">
                            <div class="display-4 text-info mb-3">
                                <i class="bi bi-database-check"></i>
                            </div>
                            <h3 class="h5 card-title">Historique Détaillé</h3>
                            <p class="card-text text-muted">Accédez à l'historique complet des analyses précédentes</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- ===============================
             9. DOCUMENTATION RAPIDE (3 colonnes)
             =============================== -->
        <section class="container mb-5">
            <div class="card border-0 shadow-sm">
                <div class="card-body">
                    <h5 class="card-title mb-4"><i class="bi bi-book text-primary me-2"></i>Documentation Rapide</h5>
                    <div class="row g-4">
                        <div class="col-md-4">
                            <h6><i class="bi bi-1-circle me-2"></i>Scanner une IP</h6>
                            <p class="small text-muted">Entrez une adresse IP valide dans le champ de recherche pour analyser une machine spécifique.</p>
                        </div>
                        <div class="col-md-4">
                            <h6><i class="bi bi-2-circle me-2"></i>Scanner le Réseau</h6>
                            <p class="small text-muted">Utilisez l'option "Réseau complet" pour analyser tous les hôtes de votre réseau local.</p>
                        </div>
                        <div class="col-md-4">
                            <h6><i class="bi bi-3-circle me-2"></i>Analyser les Résultats</h6>
                            <p class="small text-muted">Consultez les résultats détaillés pour chaque scan dans l'historique des analyses.</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

    <!-- ===============================
         10. Footer
         =============================== -->
    <footer class="footer mt-auto py-3 bg-white border-top">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-6 text-center text-md-start">
                    <span class="text-muted">&copy; <?= date('Y') ?> Projet Intégratif - BUT RT1</span>
                </div>
                <div class="col-md-6 text-center text-md-end"></div>
            </div>
        </div>
    </footer>

    <!-- ===============================
         11. SCRIPTS JS
         =============================== -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="js/main.js"></script>
</body>
</html>