<?php


class AuthDB {

    private PDOStatement $statementRegister;
    private PDOStatement $statementReadSession;
    private PDOStatement $statementReadUser;
    private PDOStatement $statementReadUserFromEmail;
    private PDOStatement $statementCreateSession;
    private PDOStatement $statementEraseSession;

    function __construct(private PDO $pdo)
    {
        $this->statementRegister = $this->pdo->prepare('INSERT INTO user VALUES (
            DEFAULT,
            :lastname,
            :firstname,
            :email,
            :password
        )');

        $this->statementReadSession = $pdo->prepare('SELECT * FROM session WHERE id=:id');
        $this->statementReadUser = $pdo->prepare('SELECT * FROM user WHERE id=:id');
        $this->statementReadUserFromEmail = $pdo->prepare('SELECT * FROM user WHERE email= :email');
        $this->statementCreateSession = $pdo->prepare('INSERT INTO session VALUES (
            :sessionid,
            :userid
        )');
        $this->statementEraseSession = $pdo->prepare('DELETE FROM session WHERE id=:id');
    }

    function login(string $userId): void
    {
        $sessionId = bin2hex(random_bytes(32));
        $this->statementCreateSession->bindValue(':userid', $userId);
        $this->statementCreateSession->bindValue(':sessionid', $sessionId);
        $this->statementCreateSession->execute();
        $signature = hash_hmac('sha256', $sessionId, 'cinq petits chats');
        setcookie('session', $sessionId, time() + 60 * 60 * 24 * 14, '', '', false, true);
        setcookie('signature', $signature, time() + 60 * 60 * 24 * 14, '', '', false, true);
        return;
    }

    function register(array $user): void
    {
        $hashedPassword = password_hash($user['password'], PASSWORD_ARGON2I);
        $this->statementRegister->bindValue(':lastname', $user['lastname']);
        $this->statementRegister->bindValue(':firstname', $user['firstname']);
        $this->statementRegister->bindValue(':email', $user['email']);
        $this->statementRegister->bindValue(':password', $hashedPassword);
        $this->statementRegister->execute();
        return;
    }

    function isLoggedin(){
        $sessionId = $_COOKIE['session'] ?? '';
        $signature = $_COOKIE['signature'] ?? '';
        if($sessionId && $signature) {
            $hash = hash_hmac('sha256', $sessionId, 'cinq petits chats');
            if (hash_equals($hash, $signature)){
                $this->statementReadSession->bindValue(':id', $sessionId);
                $this->statementReadSession->execute();
                $session = $this->statementReadSession->fetch();
                if($session) {
                    $this->statementReadUser->bindValue(':id', $session['userid']);
                    $this->statementReadUser->execute();
                    $user = $this->statementReadUser->fetch();
                }
            }  
        }
        return $user ?? false;
    }

    function getUserByEmail(string $email): array 
    {
        $this->statementReadUserFromEmail->bindValue(':email', $email);
        $this->statementReadUserFromEmail->execute();
        return $this->statementReadUserFromEmail->fetch();
    }

    function logout(string $sessionId): void{
        $this->statementEraseSession->bindValue(':id', $sessionId);
        $this->statementEraseSession->execute();
        setcookie('session','', time()- 1);
        setcookie('signature','', time()- 1);
    }
}

return new AuthDB($pdo);
