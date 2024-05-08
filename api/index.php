<?php declare(strict_types=1);

include ('Crypt/RSA.php');


// get the public key, private key and test encryption and decryption

// create a new key pair if not provided
$rsa = new Crypt_RSA();
$rsa->setPrivateKeyFormat(CRYPT_RSA_PRIVATE_FORMAT_PKCS1);
$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS1);
$keys = $rsa->createKey(4096);

if (isset($_POST['publicKey']) || isset($_POST['privateKey'])) {
    $publickey = $_POST['publicKey'];
    $privateKey = $_POST['privateKey'];
} else {
    $publickey = $keys['publickey'];
    $privateKey = $keys['privatekey'];
}

$KeyRandom = (string) random_int(1111111111111111, 9999999999999999); // Número aleatorio
$Key = str_pad($KeyRandom, 32, '0', STR_PAD_LEFT); //32 bits

$IVRandom = (string) random_int(1111111111111111, 9999999999999999); // Número aleatorio
$IV = str_pad($IVRandom, 16, '0', STR_PAD_LEFT); //16 bits

$data = json_decode($_POST['toEncrypt'] ?? json_encode([
    'test' => 'data',
]), true);


$rsa = new Crypt_RSA();

$cipher = 'aes-256-gcm';
$tag = "";
$ciphertext = openssl_encrypt(json_encode($data), $cipher, $Key, OPENSSL_RAW_DATA, $IV, $tag);
$encriptado = base64_encode($ciphertext . $tag);


$rsa->loadKey($publickey);
$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP); // RSA/ECB/OAEPWithSHA-256AndMGF1Padding
$rsa->setMGFHash('sha256');
$rsa->setHash('sha256');

//$sessionKeyRSA = base64_encode($rsa->encrypt($Key));
$sessionKeyRSA = $_POST['toDecrypt'] ?? base64_encode($rsa->encrypt($Key));
//$IVRSA = base64_encode($rsa->encrypt($IV));
$IVRSA = $_POST['toDecryptIV'] ?? base64_encode($rsa->encrypt($IV));


$newSessionKey = str_replace(" ", "+", $sessionKeyRSA);
$newIV = str_replace(" ", "+", $IVRSA);
//$newData = str_replace(" ", "+", $encriptado);
$newData = $_POST['toDecryptData'] ?? str_replace(" ", "+", $encriptado);


$newRsa = new Crypt_RSA();
$newRsa->loadKey($privateKey);
$newRsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
$newRsa->setMGFHash('sha256');
$newRsa->setHash('sha256');

$decriptedSessionKey = $newRsa->decrypt(base64_decode($newSessionKey));
$IV = $newRsa->decrypt(base64_decode($newIV));

$newEncriptado = base64_decode($newData);
$cipher = 'aes-256-gcm';
$tag_length = 16;
$tag = substr($newEncriptado, -$tag_length);
$ciphertext = substr($newEncriptado, 0, strlen($newEncriptado) - $tag_length);

$decrypted = openssl_decrypt($ciphertext, $cipher, $decriptedSessionKey, OPENSSL_RAW_DATA, $IV, $tag);

$dataDecrypted = json_decode($decrypted);

?>
<style>
    html {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
        width: 100%;
        display: flex;
        flex-direction: column;
        height: 100%;
        overflow: auto;
    }

    main {
        display: flex;
        flex-direction: column;
    }

    @media (min-width: 800px) {
        main {
            flex-direction: row;
            width: 100%;
        }
    }

    form {
        margin: 1rem;
        padding: 1rem;
        border: 1px solid #ccc;
        border-radius: 5px;
        background-color: #f9f9f9;
        width: 100%;
    }

    div {
        display: flex;
        flex-direction: column;
        margin-bottom: 1rem;
    }
</style>
<h1>Encriptacion y Desencriptacion con RSA y AES</h1>
<main>
    <form method="POST">
        <h2>
            Encriptación
        </h2>
        <div>
            <label for="toEncrypt">Data a encriptar</label>
            <textarea name="toEncrypt" id="toEncrypt" cols="30"
                rows="10"><?= json_encode($data, JSON_PRETTY_PRINT) ?></textarea>
        </div>
        <div>
            <label for="publicKey">Llave publica</label>
            <textarea name="publicKey" id="publicKey" cols="30" rows="10"><?= $publickey ?></textarea>
        </div>
        <div>
            <label for="encrypted">Data encriptada</label>
            <textarea name="encrypted" id="encrypted" cols="30" rows="10" readonly disabled><?= $newData ?></textarea>
        </div>

        <div>
            <label for="sessionKey">Llave de sesion encriptada</label>
            <textarea name="sessionKey" id="sessionKey" cols="30" rows="10" readonly
                disabled><?= $newSessionKey ?></textarea>
        </div>

        <div>
            <label for="IV">IV encriptado</label>
            <textarea name="IV" id="IV" cols="30" rows="10" readonly disabled><?= $newIV ?></textarea>
        </div>

        <button>
            Encriptar
        </button>

    </form>

    <form method="POST">

        <h2>
            Desencriptación
        </h2>
        <div>

            <label for="toDecrypt">Session Key a desencriptar</label>
            <textarea name="toDecrypt" id="toDecrypt" cols="30" rows="10"><?= $newSessionKey ?></textarea>
        </div>

        <div>
            <label for="toDecryptIV">IV a desencriptar</label>
            <textarea name="toDecryptIV" id="toDecryptIV" cols="30" rows="10"><?= $newIV ?></textarea>
        </div>

        <div>
            <label for="toDecryptData">Data a desencriptar</label>
            <textarea name="toDecryptData" id="toDecryptData" cols="30" rows="10"><?= $newData ?></textarea>
        </div>

        <div>
            <label for="privateKey">Llave privada</label>
            <textarea name="privateKey" id="privateKey" cols="30" rows="10"><?= $privateKey ?></textarea>
        </div>

        <div>
            <label for="decryptedSessionKey">Llave de sesion desencriptada</label>
            <textarea name="decryptedSessionKey" id="decryptedSessionKey" cols="30" rows="10" readonly
                disabled><?= $decriptedSessionKey ?></textarea>
        </div>

        <div>
            <label for="decryptedIV">IV desencriptado</label>
            <textarea name="decryptedIV" id="decryptedIV" cols="30" rows="10" readonly disabled><?= $IV ?></textarea>
        </div>

        <div>
            <label for="decryptedData">Data desencriptada</label>
            <textarea name="decryptedData" id="decryptedData" cols="30" rows="10" readonly
                disabled><?= json_encode($dataDecrypted, JSON_PRETTY_PRINT) ?></textarea>
        </div>
        <button>
            Desencriptar
        </button>
    </form>
</main>