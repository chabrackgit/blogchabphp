<?php

require_once './database/database.php';
$authDB = require_once './database/security.php';
const ERROR_REQUIRED = 'Veuillez renseigner ce champ';
const ERROR_PASSWORD_TOO_SHORT = 'Le mot de passe doit contenir au moins 6 caractères';
const ERROR_EMAIL = 'Merci de saisir une adresse email valide';
const ERROR_PASSWORD = 'mot de passe non valide';
const ERROR_EMAIL_UNKNOWM = 'email inconnu';

$errors = [
    'email' => '',
    'password' => '',
];
$category = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = filter_input_array(INPUT_POST, [
        'email' => FILTER_SANITIZE_EMAIL
    ]);

    $email = $input['email'] ?? '';
    $password = $_POST['password'] ?? '';

    if(!$email) {
        $errors['email'] = ERROR_REQUIRED;
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = ERROR_EMAIL;
    }
    if(!$password) {
        $errors['password'] = ERROR_REQUIRED;
    } elseif (strlen($password) < 6) {
        $errors['password'] = ERROR_PASSWORD_TOO_SHORT;
    }

    if (empty(array_filter($errors, fn ($e) => $e !== ''))) {
        $user = $authDB->getUserByEmail($email);
        if(!$user) {
            $errors['email'] = ERROR_EMAIL_UNKNOWM;
        } else {
            if(!password_verify($password, $user['password'])) {
                $errors['password'] = ERROR_PASSWORD;
            } else {
                $authDB->login($user['id']);
                header('Location: /');
            }
        }
    }
}

?>


<!DOCTYPE html>
<html lang="en">

<head>
    <?php require_once 'includes/head.php' ?>
    <link rel="stylesheet" href="/public/css/index.css">
    <title>Connexion</title>
</head>

<body>
    <div class="container">
        <?php require_once 'includes/header.php' ?>
        <div class="content">
        <div class="block p-20 form-container">
                <h1>Connexion</h1>
                <form action="/auth-login.php", method="POST">
                    <div class="form-control">
                        <label for="email">Email</label>
                        <input type="email" name="email" id="email" value="<?= $email ?? '' ?>">
                        <?php if ($errors['email']) : ?>
                            <p class="text-danger"><?= $errors['email'] ?></p>
                        <?php endif; ?>
                    </div>
                    <div class="form-control">
                        <label for="password">Mot de passe</label>
                        <input type="password" name="password" id="password">
                        <?php if ($errors['password']) : ?>
                            <p class="text-danger"><?= $errors['password'] ?></p>
                        <?php endif; ?>
                    </div>
                    <div class="form-actions">
                        <a href="/" class="btn btn-secondary" type="button">Annuler</a>
                        <button class="btn btn-primary" type="submit">Se connecter</button>
                    </div>
                </form>
            </div>
        </div>
        </div>    
        <?php require_once 'includes/footer.php' ?>
    </div>
</body>

</html>