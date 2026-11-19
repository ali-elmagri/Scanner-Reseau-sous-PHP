<?php
// Fonctions de sécurité communes à toutes les pages : session, en-têtes HTTP,
// contrôle d'accès et protection CSRF.

// Cookie de session inaccessible au JavaScript et non envoyé par les sites tiers
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => !empty($_SERVER['HTTPS']),
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

// En-têtes de sécurité : interdiction d'afficher le site dans une iframe,
// pas de devinette du type de fichier, pas de fuite de l'URL vers d'autres sites
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

// Déconnexion automatique après 30 minutes d'inactivité
const DUREE_SESSION = 1800;
if (isset($_SESSION['derniere_activite']) && time() - $_SESSION['derniere_activite'] > DUREE_SESSION) {
    $_SESSION = [];
    session_destroy();
    session_start();
}
$_SESSION['derniere_activite'] = time();

// Redirige vers la page de connexion si l'utilisateur n'est pas authentifié
function exigerConnexion(): void
{
    if (($_SESSION['est_authentifie'] ?? false) !== true) {
        header('Location: login.php');
        exit;
    }
}

// Jeton CSRF : prouve que le formulaire envoyé vient bien de ce site
function jetonCsrf(): string
{
    if (empty($_SESSION['jeton_csrf'])) {
        $_SESSION['jeton_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['jeton_csrf'];
}

function champCsrf(): string
{
    return '<input type="hidden" name="jeton_csrf" value="' . htmlspecialchars(jetonCsrf()) . '">';
}

function verifierCsrf(): bool
{
    $recu = $_POST['jeton_csrf'] ?? '';
    return is_string($recu) && !empty($_SESSION['jeton_csrf']) && hash_equals($_SESSION['jeton_csrf'], $recu);
}
