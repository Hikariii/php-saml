<?php

namespace Saml\Message\Xml;

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Saml\Settings;
use Saml\Utils;

class Builder
{
    /**
     * @var Settings
     */
    protected $samlSettings;

    /**
     * Builder constructor.
     * @param Settings $samlSettings
     */
    public function __construct(Settings $samlSettings)
    {
        $this->samlSettings = $samlSettings;
    }


    /**
     * Generates a nameID.
     *
     * @param string      $value  fingerprint
     * @param string      $spnq   SP Name Qualifier
     * @param string      $format SP Format
     * @param string|null $cert   IdP Public cert to encrypt the nameID
     *
     * @return string $nameIDElement DOMElement | XMLSec nameID
     */
    public static function generateNameId($value, $spnq, $format, $cert = null)
    {
        $doc = new \DOMDocument();

        $nameId = $doc->createElement('saml:NameID');
        if (isset($spnq)) {
            $nameId->setAttribute('SPNameQualifier', $spnq);
        }
        $nameId->setAttribute('Format', $format);
        $nameId->appendChild($doc->createTextNode($value));

        $doc->appendChild($nameId);

        if (!empty($cert)) {
            $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'public'));
            $seckey->loadKey($cert);

            $enc = new XMLSecEnc();
            $enc->setNode($nameId);
            $enc->type = XMLSecEnc::Element;

            $symmetricKey = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
            $symmetricKey->generateSessionKey();
            $enc->encryptKey($seckey, $symmetricKey);

            $encryptedData = $enc->encryptNode($symmetricKey);

            $newdoc = new \DOMDocument();

            $encryptedID = $newdoc->createElement('saml:EncryptedID');

            $newdoc->appendChild($encryptedID);

            $encryptedID->appendChild($encryptedID->ownerDocument->importNode($encryptedData, true));

            return $newdoc->saveXML($encryptedID);
        } else {
            return $doc->saveXML($nameId);
        }
    }
}
