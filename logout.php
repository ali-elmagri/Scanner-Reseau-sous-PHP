<?php
require __DIR__ . '/inc/securite.php';

// Supprime les données et le cookie de session
$_SESSION = [];
$params = session_get_cookie_params();
setcookie(session_name(), '', time() - 3600, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
session_destroy();

header('Location: login.php');
exit;
