<?php

$pdo = require_once __DIR__. '/database/database.php';
$authDB = require_once __DIR__. '/database/security.php';
const ERROR_REQUIRED = 'Veuillez renseigner ce champ';
const ERROR_TOO_SHORT = 'Ce champ est trop court';
const ERROR_PASSWORD_TOO_SHORT = 'Le mot de passe doit contenir au moins 6 caractères';
const ERROR_EMAIL = 'Merci de saisir une adresse email valide';
const ERROR_PASSWORD = 'les mots de passe doivent être identitques';

$errors = [
    'firstname' => '',
    'lastname' => '',
    'email' => '',
    'password' => '',
    'confirmPassword' => ''

];
$category = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = filter_input_array(INPUT_POST, [
        'firstname' => FILTER_SANITIZE_SPECIAL_CHARS,
        'lastname' => FILTER_SANITIZE_FULL_SPECIAL_CHARS,
        'email' => FILTER_SANITIZE_EMAIL
    ]);

    $firstname = $input['firstname'] ?? '';
    $lastname = $input['lastname'] ?? '';
    $email = $input['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirmPassword'] ?? '';

    if(!$firstname) {
        $errors['firstname'] = ERROR_REQUIRED;
    } elseif(strlen($firstname) < 2) {
        $errors['firstname'] = ERROR_TOO_SHORT;
    }
    if(!$lastname) {
        $errors['lastname'] = ERROR_REQUIRED;
    } elseif (strlen($lastname) < 2) {
        $errors['lastname'] = ERROR_TOO_SHORT;
    }
    if(!$email) {
        $errors['email'] = ERROR_REQUIRED;
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = ERROR_EMAIL;
    }
    if(!$password) {
        $errors['password'] = ERROR_REQUIRED;
    } elseif (strlen($password) < 6) {
        $errors['password'] = ERROR_TOO_SHORT;
    }
    if(!$confirmPassword) {
        $errors['confirmPassword'] = ERROR_REQUIRED;
    } elseif ($confirmPassword !== $password) {
        $errors['confirmPassword'] = ERROR_PASSWORD;
    }

    if (empty(array_filter($errors, fn ($e) => $e !== ''))) {
        $authDB->register([
            'firstname' => $firstname,
            'lastname' =>$lastname,
            'email' => $email,
            'password' => $password
        ]);
        header('Location: /auth-login.php');
    }
}

?>



<!DOCTYPE html>
<html lang="en">

<head>
    <?php require_once 'includes/head.php' ?>
    <link rel="stylesheet" href="/public/css/auth-index.css">
    <title>Inscription</title>
</head>

<body>
    <div class="container">
        <?php require_once 'includes/header.php' ?>
        <div class="content">
        <div class="block p-20 form-container">
                <h1>Inscription</h1>
                <form action="/auth-register.php", method="POST">
                    <div class="form-control">
                        <label for="firstname">Prénom</label>
                        <input type="text" name="firstname" id="firstname" value="<?= $firstname ?? '' ?>">
                        <?php if ($errors['firstname']) : ?>
                            <p class="text-danger"><?= $errors['firstname'] ?></p>
                        <?php endif; ?>
                    </div>
                    <div class="form-control">
                        <label for="lastname">Nom</label>
                        <input type="text" name="lastname" id="lastname" value="<?= $lastname ?? '' ?>">
                        <?php if ($errors['lastname']) : ?>
                            <p class="text-danger"><?= $errors['lastname'] ?></p>
                        <?php endif; ?>
                    </div>
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
                    <div class="form-control">
                        <label for="confirmPassword">Confirmation mot de passe</label>
                        <input type="password" name="confirmPassword" id="confirmPassword">
                        <?php if ($errors['confirmPassword']) : ?>
                            <p class="text-danger"><?= $errors['confirmPassword'] ?></p>
                        <?php endif; ?>
                    </div>
                    <div class="form-actions">
                        <a href="/" class="btn btn-secondary" type="button">Annuler</a>
                        <button class="btn btn-primary" type="submit">Valider</button>
                    </div>
                </form>
            </div>
        </div>    
        <?php require_once 'includes/footer.php' ?>
    </div>

</body>

</html>