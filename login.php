<?php
require __DIR__ . '/inc/securite.php';

if (!is_file(__DIR__ . '/config.php')) {
    http_response_code(500);
    exit('Configuration absente : copier config.example.php en config.php.');
}
require __DIR__ . '/config.php';

// Déjà connecté : retour à l'accueil
if (($_SESSION['est_authentifie'] ?? false) === true) {
    header('Location: index.php');
    exit;
}

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $utilisateur = (string)($_POST['username'] ?? '');
    $mot_de_passe = (string)($_POST['password'] ?? '');

    if (!verifierCsrf()) {
        $message = 'Session expirée, veuillez réessayer.';
    } elseif (hash_equals(ADMIN_UTILISATEUR, $utilisateur) && password_verify($mot_de_passe, ADMIN_EMPREINTE)) {
        // Nouvel identifiant de session pour empêcher la fixation de session
        session_regenerate_id(true);
        $_SESSION['est_authentifie'] = true;
        header('Location: index.php');
        exit;
    } else {
        // Pause pour ralentir les attaques par force brute
        sleep(1);
        $message = 'Identifiants incorrects.';
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Connexion</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
</head>
<body class="page-login fond-degrade">
    <div class="boite-connexion">
        <span class="icone-login"><i class="bi bi-person-circle"></i></span>
        <h2>Connexion</h2>
        <?php if ($message): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        <form method="POST" action="login.php">
            <?= champCsrf() ?>
            <label for="username">Nom d'utilisateur :</label>
            <input type="text" id="username" name="username" class="champ-formulaire" required autocomplete="username">

            <label for="password">Mot de passe :</label>
            <input type="password" id="password" name="password" class="champ-formulaire" required autocomplete="current-password">

            <input type="submit" value="Se connecter" class="bouton-principal">
        </form>
    </div>
</body>
</html>
