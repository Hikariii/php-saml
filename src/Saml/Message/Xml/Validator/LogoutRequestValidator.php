<?php

namespace Saml\Message\Xml\Validator;

use Saml\Exception\ValidationError;
use Saml\Settings;
use Saml\Utils;

class LogoutRequestValidator
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
     * Checks if the Logout Request recieved is valid.
     *
     * @return bool If the Logout Request is or not valid
     */
    public function isValid($logoutRequestString)
    {
        $this->_error = null;
        try {
            $dom = new \DOMDocument();
            $dom = Utils::loadXML($dom, $logoutRequestString);

            $idpData = $this->samlSettings->getIdPData();
            $idPEntityId = $idpData['entityId'];

            if ($this->samlSettings->isStrict()) {
                $security = $this->samlSettings->getSecurityData();

                if ($security['wantXMLValidation']) {
                    $res = Utils::validateXML($dom, 'saml-schema-protocol-2.0.xsd', $this->samlSettings->isDebugActive());
                    if (!$res instanceof \DOMDocument) {
                        throw new ValidationError(
                            "Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd",
                            ValidationError::INVALID_XML_FORMAT
                        );
                    }
                }

                $currentURL = Utils::getSelfRoutedURLNoQuery();

                // Check NotOnOrAfter
                if ($dom->documentElement->hasAttribute('NotOnOrAfter')) {
                    $na = Utils::parseSAML2Time($dom->documentElement->getAttribute('NotOnOrAfter'));
                    if ($na <= time()) {
                        throw new ValidationError(
                            "Could not validate timestamp: expired. Check system clock.",
                            ValidationError::RESPONSE_EXPIRED
                        );
                    }
                }

                // Check destination
                if ($dom->documentElement->hasAttribute('Destination')) {
                    $destination = $dom->documentElement->getAttribute('Destination');
                    if (!empty($destination)) {
                        if (strpos($destination, $currentURL) === false) {
                            throw new ValidationError(
                                "The LogoutRequest was received at $currentURL instead of $destination",
                                ValidationError::WRONG_DESTINATION
                            );
                        }
                    }
                }

                $nameId = $this->getNameId($dom, $this->samlSettings->getSPkey());

                // Check issuer
                $issuer = $this->getIssuer($dom);
                if (!empty($issuer) && $issuer != $idPEntityId) {
                    throw new ValidationError(
                        "Invalid issuer in the Logout Request",
                        ValidationError::WRONG_ISSUER
                    );
                }

                if ($security['wantMessagesSigned']) {
                    if (!isset($_GET['Signature'])) {
                        throw new ValidationError(
                            "The Message of the Logout Request is not signed and the SP require it",
                            ValidationError::NO_SIGNED_MESSAGE
                        );
                    }
                }
            }

            if (isset($_GET['Signature'])) {
                $signatureValid = Utils::validateBinarySign("SAMLRequest", $_GET, $idpData, $retrieveParametersFromServer);
                if (!$signatureValid) {
                    throw new ValidationError(
                        "Signature validation failed. Logout Request rejected",
                        ValidationError::INVALID_SIGNATURE
                    );
                }
            }

            return true;
        } catch (\Exception $e) {
            $this->_error = $e->getMessage();
            $debug = $this->samlSettings->isDebugActive();
            if ($debug) {
                echo $this->_error;
            }
            return false;
        }
    }
}