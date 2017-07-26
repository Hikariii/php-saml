<?php

namespace Saml\Message\Validator;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use Saml\Exception\ValidationError;

class BinarySignValidator
{
    /**
     * Validates a get parameter signature query
     *
     * @param $signedQuery
     * @param $signAlg
     * @param array $multiCerts
     * @return bool
     * @throws ValidationError
     * @throws \Exception
     */
    function isValid($signedQuery, $signAlg, array $multiCerts)
    {
        $signatureValid = false;

        foreach ($multiCerts as $cert) {
            $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'public'));
            $objKey->loadKey($cert, false, true);

            if ($signAlg != XMLSecurityKey::RSA_SHA1) {
                try {
                    $objKey = $this->castKey($objKey, $signAlg, 'public');
                } catch (\Exception $e) {
                    $ex = new ValidationError(
                        "Invalid signAlg received",
                        ValidationError::INVALID_SIGNATURE
                    );
                    if (count($multiCerts) == 1) {
                        throw $ex;
                    }
                }
            }

            if ($objKey->verifySignature($signedQuery, base64_decode($_GET['Signature'])) === 1) {
                $signatureValid = true;
                break;
            }
        }

        return $signatureValid;
    }

    /**
     * Converts a XMLSecurityKey to the correct algorithm.
     *
     * @param XMLSecurityKey $key The key.
     * @param string $algorithm The desired algorithm.
     * @param string $type Public or private key, defaults to public.
     *
     * @return XMLSecurityKey The new key.
     *
     * @throws \Exception
     */
    protected function castKey(XMLSecurityKey $key, $algorithm, $type = 'public')
    {
        assert('is_string($algorithm)');
        assert('$type === "public" || $type === "private"');
        // do nothing if algorithm is already the type of the key
        if ($key->type === $algorithm) {
            return $key;
        }
        $keyInfo = openssl_pkey_get_details($key->key);
        if ($keyInfo === false) {
            throw new \Exception('Unable to get key details from XMLSecurityKey.');
        }
        if (!isset($keyInfo['key'])) {
            throw new \Exception('Missing key in public key details.');
        }
        $newKey = new XMLSecurityKey($algorithm, array('type'=>$type));
        $newKey->loadKey($keyInfo['key']);
        return $newKey;
    }
}
