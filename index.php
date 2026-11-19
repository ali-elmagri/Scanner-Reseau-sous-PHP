<?php
require __DIR__ . '/inc/securite.php';
require __DIR__ . '/config.php';
exigerConnexion();
?>
<!DOCTYPE html>
<html lang="fr" class="h-100">
<head>
    <meta charset="UTF-8">
    <title>Surveillance Réseau - Scanner</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Scanner réseau avancé pour la détection des systèmes, services et ports ouverts d'un réseau local.">
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
                        <p class="lead mb-4 opacity-75">Inventoriez les hôtes, systèmes et services de votre réseau local</p>
                        
                        <!-- Formulaire de scan réseau -->
                        <form action="scan.php" method="POST" class="mb-4">
                            <?= champCsrf() ?>
                            <input type="hidden" name="reseau" value="<?= htmlspecialchars(RESEAU_DEFAUT) ?>">
                            <div class="row g-3">
                                <div class="col-12">

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
                                                placeholder="ex : 192.168.1.10"
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
                                        <small class="text-white">Scanne un port précis sur le réseau <?= htmlspecialchars(RESEAU_DEFAUT) ?>.</small>
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
                            <h3 class="h5 card-title">Services exposés</h3>
                            <p class="card-text text-muted">Repérez les ports ouverts et les services qui écoutent sur chaque machine</p>
                        </div>
                    </div>
                </div>
                <!-- Carte : Identification du système -->
                <div class="col-md-4">
                    <div class="card border-0 shadow-sm h-100">
                        <div class="card-body text-center">
                            <div class="display-4 text-success mb-3">
                                <i class="bi bi-pc-display"></i>
                            </div>
                            <h3 class="h5 card-title">Systèmes identifiés</h3>
                            <p class="card-text text-muted">Obtenez le système d'exploitation probable de chaque hôte actif</p>
                        </div>
                    </div>
                </div>
                <!-- Carte : Export CSV -->
                <div class="col-md-4">
                    <div class="card border-0 shadow-sm h-100">
                        <div class="card-body text-center">
                            <div class="display-4 text-info mb-3">
                                <i class="bi bi-file-earmark-spreadsheet"></i>
                            </div>
                            <h3 class="h5 card-title">Export CSV</h3>
                            <p class="card-text text-muted">Téléchargez les résultats du dernier scan pour les analyser ailleurs</p>
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
                            <p class="small text-muted">Utilisez l'option "Réseau complet" pour analyser tous les hôtes du réseau <?= htmlspecialchars(RESEAU_DEFAUT) ?>.</p>
                        </div>
                        <div class="col-md-4">
                            <h6><i class="bi bi-3-circle me-2"></i>Analyser les Résultats</h6>
                            <p class="small text-muted">Consultez les résultats détaillés de chaque hôte et téléchargez-les au format CSV.</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

    </main>

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