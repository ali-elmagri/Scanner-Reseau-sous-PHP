<?php
// Traitement du formulaire
$message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["username"];
    $password = $_POST["password"];

    // Vérification simple
    if ($username === "admin" && $password === "admin") {
        session_start();
        $_SESSION['est_authentifie'] = true;
        header('Location: index.php');
        exit;
    } else {
        $message = "Identifiants incorrects.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
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
        <form method="POST" action="">
            <label>Nom d'utilisateur :</label>
            <input type="text" name="username" class="champ-formulaire" required autocomplete="username" placeholder="admin">

            <label>Mot de passe :</label>
            <input type="password" name="password" class="champ-formulaire" required autocomplete="current-password" placeholder="admin">

            <input type="submit" value="Se connecter" class="bouton-principal">
        </form>
    </div>
</body>
</html>