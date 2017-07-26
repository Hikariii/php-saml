<?php

namespace Saml\Message\Validator;

use Saml\Constants;
use Saml\Exception\ValidationError;
use Saml\Message\Xml\Parser;
use Saml\Message\Xml\Parser\AuthResponseParser;
use Saml\Utils;

class AuthResponseValidator extends AbstractValidator
{
    /**
     * Determines if the SAML Response is valid using the certificate.
     *
     * @param \DOMDocument $document
     * @param \DOMDocument|null $decryptedDocument
     * @param null $requestId
     * @return bool
     * @throws ValidationError
     * @throws \Exception
     */
    public function isValid(\DOMDocument $document, \DOMDocument $decryptedDocument = null, $requestId = null)
    {
        $this->_error = null;
        $encrypted = empty($decryptedDocument);

        try {
            // Check SAML version
            if ($document->documentElement->getAttribute('Version') != '2.0') {
                throw new ValidationError(
                    "Unsupported SAML version",
                    ValidationError::UNSUPPORTED_SAML_VERSION
                );
            }

            if (!$document->documentElement->hasAttribute('ID')) {
                throw new ValidationError(
                    "Missing ID attribute on SAML Response",
                    ValidationError::MISSING_ID
                );
            }

            $this->checkStatus($document);

            $singleAssertion = $this->validateNumAssertions($document, $decryptedDocument);
            if (!$singleAssertion) {
                throw new ValidationError(
                    "SAML Response must contain 1 assertion",
                    ValidationError::WRONG_NUMBER_OF_ASSERTIONS
                );
            }

            $idpData = $this->samlSettings->getIdPData();
            $idPEntityId = $idpData['entityId'];
            $spData = $this->samlSettings->getSPData();
            $spEntityId = $spData['entityId'];

            $signedElements = $this->processSignedElements();

            $responseTag = '{'.Constants::NS_SAMLP.'}Response';
            $assertionTag = '{'.Constants::NS_SAML.'}Assertion';

            $hasSignedResponse = in_array($responseTag, $signedElements);
            $hasSignedAssertion = in_array($assertionTag, $signedElements);

            if ($this->samlSettings->isStrict()) {
                $security = $this->samlSettings->getSecurityData();

                if ($security['wantXMLValidation']) {
                    $errorXmlMsg = "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd";
                    $res = Utils::validateXML($document, 'saml-schema-protocol-2.0.xsd', $this->samlSettings->isDebugActive());
                    if (!$res instanceof \DOMDocument) {
                        throw new ValidationError(
                            $errorXmlMsg,
                            ValidationError::INVALID_XML_FORMAT
                        );
                    }

                    # If encrypted, check also the decrypted document
                    if ($encrypted) {
                        $res = Utils::validateXML($decryptedDocument, 'saml-schema-protocol-2.0.xsd', $this->samlSettings->isDebugActive());
                        if (!$res instanceof \DOMDocument) {
                            throw new ValidationError(
                                $errorXmlMsg,
                                ValidationError::INVALID_XML_FORMAT
                            );
                        }
                    }

                }

                $currentURL = Utils::getSelfRoutedURLNoQuery();

                if ($document->documentElement->hasAttribute('InResponseTo')) {
                    $responseInResponseTo = $document->documentElement->getAttribute('InResponseTo');
                }

                // Check if the InResponseTo of the Response matchs the ID of the AuthNRequest (requestId) if provided
                if (isset($requestId) && isset($responseInResponseTo)) {
                    if ($requestId != $responseInResponseTo) {
                        throw new ValidationError(
                            "The InResponseTo of the Response: $responseInResponseTo, does not match the ID of the AuthNRequest sent by the SP: $requestId",
                            ValidationError::WRONG_INRESPONSETO
                        );
                    }
                }

                if (!$encrypted && $security['wantAssertionsEncrypted']) {
                    throw new ValidationError(
                        "The assertion of the Response is not encrypted and the SP requires it",
                        ValidationError::NO_ENCRYPTED_ASSERTION
                    );
                }

                if ($security['wantNameIdEncrypted']) {
                    $encryptedIdNodes = $this->_queryAssertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData');
                    if ($encryptedIdNodes->length != 1) {
                        throw new ValidationError(
                            "The NameID of the Response is not encrypted and the SP requires it",
                            ValidationError::NO_ENCRYPTED_NAMEID
                        );
                    }
                }

                // Validate Conditions element exists
                if (!$this->checkOneCondition()) {
                    throw new ValidationError(
                        "The Assertion must include a Conditions element",
                        ValidationError::MISSING_CONDITIONS
                    );
                }

                // Validate Asserion timestamps
                $this->validateTimestamps();

                // Validate AuthnStatement element exists and is unique
                if (!$this->checkOneAuthnStatement()) {
                    throw new ValidationError(
                        "The Assertion must include an AuthnStatement element",
                        ValidationError::WRONG_NUMBER_OF_AUTHSTATEMENTS
                    );
                }

                // EncryptedAttributes are not supported
                $encryptedAttributeNodes = $this->_queryAssertion('/saml:AttributeStatement/saml:EncryptedAttribute');
                if ($encryptedAttributeNodes->length > 0) {
                    throw new ValidationError(
                        "There is an EncryptedAttribute in the Response and this SP not support them",
                        ValidationError::ENCRYPTED_ATTRIBUTES
                    );
                }

                // Check destination
                if ($document->documentElement->hasAttribute('Destination')) {
                    $destination = trim($document->documentElement->getAttribute('Destination'));
                    if (empty($destination)) {
                        if (!$security['relaxDestinationValidation']) {
                            throw new ValidationError(
                                "The response has an empty Destination value",
                                ValidationError::EMPTY_DESTINATION
                            );
                        }
                    } else {
                        if (strpos($destination, $currentURL) !== 0) {
                            $currentURLNoRouted = Utils::getSelfURLNoQuery();

                            if (strpos($destination, $currentURLNoRouted) !== 0) {
                                throw new ValidationError(
                                    "The response was received at $currentURL instead of $destination",
                                    ValidationError::WRONG_DESTINATION
                                );
                            }
                        }
                    }
                }

                // Check audience
                $validAudiences = $this->getAudiences();
                if (!empty($validAudiences) && !in_array($spEntityId, $validAudiences, true)) {
                    throw new ValidationError(
                        sprintf(
                            "Invalid audience for this Response (expected '%s', got '%s')",
                            $spEntityId,
                            implode(',', $validAudiences)
                        ),
                        ValidationError::WRONG_AUDIENCE
                    );
                }

                // Check the issuers
                $issuers = $this->getIssuers();
                foreach ($issuers as $issuer) {
                    $trimmedIssuer = trim($issuer);
                    if (empty($trimmedIssuer) || $trimmedIssuer !== $idPEntityId) {
                        throw new ValidationError(
                            "Invalid issuer in the Assertion/Response (expected '$idPEntityId', got '$trimmedIssuer')",
                            ValidationError::WRONG_ISSUER
                        );
                    }
                }

                // Check the session Expiration
                $sessionExpiration = $this->getSessionNotOnOrAfter();
                if (!empty($sessionExpiration) && $sessionExpiration + Constants::ALLOWED_CLOCK_DRIFT <= time()) {
                    throw new ValidationError(
                        "The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response",
                        ValidationError::SESSION_EXPIRED
                    );
                }

                // Check the SubjectConfirmation, at least one SubjectConfirmation must be valid
                $anySubjectConfirmation = false;
                $subjectConfirmationNodes = $this->_queryAssertion('/saml:Subject/saml:SubjectConfirmation');
                foreach ($subjectConfirmationNodes as $scn) {
                    if ($scn->hasAttribute('Method') && $scn->getAttribute('Method') != Constants::CM_BEARER) {
                        continue;
                    }
                    $subjectConfirmationDataNodes = $scn->getElementsByTagName('SubjectConfirmationData');
                    if ($subjectConfirmationDataNodes->length == 0) {
                        continue;
                    } else {
                        $scnData = $subjectConfirmationDataNodes->item(0);
                        if ($scnData->hasAttribute('InResponseTo')) {
                            $inResponseTo = $scnData->getAttribute('InResponseTo');
                            if (isset($responseInResponseTo) && $responseInResponseTo != $inResponseTo) {
                                continue;
                            }
                        }
                        if ($scnData->hasAttribute('Recipient')) {
                            $recipient = $scnData->getAttribute('Recipient');
                            if (!empty($recipient) && strpos($recipient, $currentURL) === false) {
                                continue;
                            }
                        }
                        if ($scnData->hasAttribute('NotOnOrAfter')) {
                            $noa = Utils::parseSAML2Time($scnData->getAttribute('NotOnOrAfter'));
                            if ($noa + Constants::ALLOWED_CLOCK_DRIFT <= time()) {
                                continue;
                            }
                        }
                        if ($scnData->hasAttribute('NotBefore')) {
                            $nb = Utils::parseSAML2Time($scnData->getAttribute('NotBefore'));
                            if ($nb > time() + Constants::ALLOWED_CLOCK_DRIFT) {
                                continue;
                            }
                        }

                        // Save NotOnOrAfter value
                        if ($scnData->hasAttribute('NotOnOrAfter')) {
                            $this->_validSCDNotOnOrAfter = $noa;
                        }
                        $anySubjectConfirmation = true;
                        break;
                    }
                }

                if (!$anySubjectConfirmation) {
                    throw new ValidationError(
                        "A valid SubjectConfirmation was not found on this Response",
                        ValidationError::WRONG_SUBJECTCONFIRMATION
                    );
                }

                if ($security['wantAssertionsSigned'] && !$hasSignedAssertion) {
                    throw new ValidationError(
                        "The Assertion of the Response is not signed and the SP requires it",
                        ValidationError::NO_SIGNED_ASSERTION
                    );
                }

                if ($security['wantMessagesSigned'] && !$hasSignedResponse) {
                    throw new ValidationError(
                        "The Message of the Response is not signed and the SP requires it",
                        ValidationError::NO_SIGNED_MESSAGE
                    );
                }
            }

            // Detect case not supported
            if ($encrypted) {
                $encryptedIDNodes = Parser::query($decryptedDocument, '/samlp:Response/saml:Assertion/saml:Subject/saml:EncryptedID');
                if ($encryptedIDNodes->length > 0) {
                    throw new ValidationError(
                        'Unsigned SAML Response that contains a signed and encrypted Assertion with encrypted nameId is not supported.',
                        ValidationError::NOT_SUPPORTED
                    );
                }
            }

            if (empty($signedElements) || (!$hasSignedResponse && !$hasSignedAssertion)) {
                throw new ValidationError(
                    'No Signature found. SAML Response rejected',
                    ValidationError::NO_SIGNATURE_FOUND
                );
            } else {
                $cert = $idpData['x509cert'];
                $fingerprint = $idpData['certFingerprint'];
                $fingerprintalg = $idpData['certFingerprintAlgorithm'];

                $multiCerts = null;
                $existsMultiX509Sign = isset($idpData['x509certMulti']) && isset($idpData['x509certMulti']['signing']) && !empty($idpData['x509certMulti']['signing']);

                if ($existsMultiX509Sign) {
                    $multiCerts = $idpData['x509certMulti']['signing'];
                }

                # If find a Signature on the Response, validates it checking the original response
                if ($hasSignedResponse && !Utils::validateSign($document, $cert, $fingerprint, $fingerprintalg, Utils::RESPONSE_SIGNATURE_XPATH, $multiCerts)) {
                    throw new ValidationError(
                        "Signature validation failed. SAML Response rejected",
                        ValidationError::INVALID_SIGNATURE
                    );
                }

                # If find a Signature on the Assertion (decrypted assertion if was encrypted)
                $documentToCheckAssertion = $encrypted ? $decryptedDocument : $document;
                if ($hasSignedAssertion && !Utils::validateSign($documentToCheckAssertion, $cert, $fingerprint, $fingerprintalg, Utils::ASSERTION_SIGNATURE_XPATH, $multiCerts)) {
                    throw new ValidationError(
                        "Signature validation failed. SAML Response rejected",
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

    /**
     * Checks if the Status is success
     *
     * @param \DOMDocument $document
     * @throws $statusExceptionMsg If status is not success
     */
    public function checkStatus(\DOMDocument $document)
    {
        $status = AuthResponseParser::getStatus($document);

        if (isset($status['code']) && $status['code'] !== Constants::STATUS_SUCCESS) {
            $explodedCode = explode(':', $status['code']);
            $printableCode = array_pop($explodedCode);

            $statusExceptionMsg = 'The status code of the Response was not Success, was '.$printableCode;
            if (!empty($status['msg'])) {
                $statusExceptionMsg .= ' -> '.$status['msg'];
            }
            throw new ValidationError(
                $statusExceptionMsg,
                ValidationError::STATUS_CODE_IS_NOT_SUCCESS
            );
        }
    }

    /**
     * Verifies that the document only contains a single Assertion (encrypted or not).
     *
     * @param \DOMDocument $document
     * @param \DOMDocument $decryptedDocument
     * @return bool TRUE if the document passes.
     */
    public function validateNumAssertions(\DOMDocument $document, \DOMDocument $decryptedDocument = null)
    {
        $encryptedAssertionNodes = $document->getElementsByTagName('EncryptedAssertion');
        $assertionNodes = $document->getElementsByTagName('Assertion');

        $valid = $assertionNodes->length + $encryptedAssertionNodes->length == 1;

        if ($decryptedDocument) {
            $assertionNodes = $decryptedDocument->getElementsByTagName('Assertion');
            $valid = $valid && $assertionNodes->length == 1;
        }

        return $valid;
    }
}
