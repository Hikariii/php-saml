<?php

namespace Saml\Message\Xml;

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
     * @param $id
     */
    public function buildLogoutRequest($uniqueRequestId)
    {
        $spData = $this->samlSettings->getSPData();
        $idpData = $this->samlSettings->getIdPData();
        $security = $this->samlSettings->getSecurityData();

        $issueInstant = Utils::parseTime2SAML(time());

        $cert = null;
        if (isset($security['nameIdEncrypted']) && $security['nameIdEncrypted']) {
            $existsMultiX509Enc = isset($idpData['x509certMulti']) && isset($idpData['x509certMulti']['encryption']) && !empty($idpData['x509certMulti']['encryption']);

            if ($existsMultiX509Enc) {
                $cert = $idpData['x509certMulti']['encryption'][0];
            } else {
                $cert = $idpData['x509cert'];
            }
        }

        if (!empty($nameId)) {
            if (empty($nameIdFormat)) {
                $nameIdFormat = $spData['NameIDFormat'];
            }
            $spNameQualifier = null;
        } else {
            $nameId = $idpData['entityId'];
            $nameIdFormat = Constants::NAMEID_ENTITY;
            $spNameQualifier = $spData['entityId'];
        }

        $nameIdObj = Utils::generateNameId(
            $nameId,
            $spNameQualifier,
            $nameIdFormat,
            $cert
        );

        $sessionIndexStr = isset($sessionIndex) ? "<samlp:SessionIndex>{$sessionIndex}</samlp:SessionIndex>" : "";

        $spEntityId = htmlspecialchars($spData['entityId'], ENT_QUOTES);
        return <<<LOGOUTREQUEST
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{$uniqueRequestId}"
    Version="2.0"
    IssueInstant="{$issueInstant}"
    Destination="{$idpData['singleLogoutService']['url']}">
    <saml:Issuer>{$spEntityId}</saml:Issuer>
    {$nameIdObj}
    {$sessionIndexStr}
</samlp:LogoutRequest>
LOGOUTREQUEST;
    }
}