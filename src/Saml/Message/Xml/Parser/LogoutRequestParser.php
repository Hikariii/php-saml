<?php

namespace Saml\Message\Xml\Parser;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use Saml\Exception\Error;
use Saml\Exception\ValidationError;
use Saml\Utils;

class LogoutRequestParser
{
    /**
     * Returns the ID of the Logout Request.
     *
     * @param string|\DOMDocument $request Logout Request Message
     *
     * @return string ID
     */
    public static function getID($request)
    {
        if ($request instanceof \DOMDocument) {
            $dom = $request;
        } else {
            $dom = new \DOMDocument();
            $dom = Utils::loadXML($dom, $request);
        }

        $id = $dom->documentElement->getAttribute('ID');
        return $id;
    }

    /**
     * Gets the NameID Data of the the Logout Request.
     *
     * @param string|\DOMDocument $request Logout Request Message
     * @param string|null        $key     The SP key
     *
     * @return array Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
     * @throws \Exception
     */
    public static function getNameIdData($request, $key = null)
    {
        if ($request instanceof \DOMDocument) {
            $dom = $request;
        } else {
            $dom = new \DOMDocument();
            $dom = Utils::loadXML($dom, $request);
        }

        $encryptedEntries = Utils::query($dom, '/samlp:LogoutRequest/saml:EncryptedID');

        if ($encryptedEntries->length == 1) {
            $encryptedDataNodes = $encryptedEntries->item(0)->getElementsByTagName('EncryptedData');
            $encryptedData = $encryptedDataNodes->item(0);

            if (empty($key)) {
                throw new Error(
                    "Private Key is required in order to decrypt the NameID, check settings",
                    Error::PRIVATE_KEY_NOT_FOUND
                );
            }

            $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'private'));
            $seckey->loadKey($key);

            $nameId = Utils::decryptElement($encryptedData, $seckey);

        } else {
            $entries = Utils::query($dom, '/samlp:LogoutRequest/saml:NameID');
            if ($entries->length == 1) {
                $nameId = $entries->item(0);
            }
        }

        if (!isset($nameId)) {
            throw new ValidationError(
                "NameID not found in the Logout Request",
                ValidationError::NO_NAMEID
            );
        }

        $nameIdData = array();
        $nameIdData['Value'] = $nameId->nodeValue;
        foreach (array('Format', 'SPNameQualifier', 'NameQualifier') as $attr) {
            if ($nameId->hasAttribute($attr)) {
                $nameIdData[$attr] = $nameId->getAttribute($attr);
            }
        }

        return $nameIdData;
    }

    /**
     * Gets the NameID of the Logout Request.
     *
     * @param string|\DOMDocument $request Logout Request Message
     * @param string|null        $key     The SP key
     *
     * @return string Name ID Value
     */
    public static function getNameId($request, $key = null)
    {
        $nameId = self::getNameIdData($request, $key);
        return $nameId['Value'];
    }

    /**
     * Gets the Issuer of the Logout Request.
     *
     * @param string|\DOMDocument $request Logout Request Message
     *
     * @return string|null $issuer The Issuer
     */
    public static function getIssuer($request)
    {
        if ($request instanceof \DOMDocument) {
            $dom = $request;
        } else {
            $dom = new \DOMDocument();
            $dom = Utils::loadXML($dom, $request);
        }

        $issuer = null;
        $issuerNodes = Utils::query($dom, '/samlp:LogoutRequest/saml:Issuer');
        if ($issuerNodes->length == 1) {
            $issuer = $issuerNodes->item(0)->textContent;
        }
        return $issuer;
    }

    /**
     * Gets the SessionIndexes from the Logout Request.
     * Notice: Our Constructor only support 1 SessionIndex but this parser
     *         extracts an array of all the  SessionIndex found on a
     *         Logout Request, that could be many.
     *
     * @param string|\DOMDocument $request Logout Request Message
     *
     * @return array The SessionIndex value
     */
    public static function getSessionIndexes($request)
    {
        if ($request instanceof \DOMDocument) {
            $dom = $request;
        } else {
            $dom = new \DOMDocument();
            $dom = Utils::loadXML($dom, $request);
        }

        $sessionIndexes = array();
        $sessionIndexNodes = Utils::query($dom, '/samlp:LogoutRequest/samlp:SessionIndex');
        foreach ($sessionIndexNodes as $sessionIndexNode) {
            $sessionIndexes[] = $sessionIndexNode->textContent;
        }
        return $sessionIndexes;
    }
}