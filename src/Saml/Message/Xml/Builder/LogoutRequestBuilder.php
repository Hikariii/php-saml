<?php

namespace Saml\Message\Xml\Builder;

use Saml\Constants;
use Saml\Message\Xml\Builder;
use Saml\Settings;
use Saml\Utils;

class LogoutRequestBuilder
{
    /**
     * @param $uniqueRequestId
     * @param Settings $samlSettings
     * @return string
     */
    public function buildLogoutRequest($uniqueRequestId, Settings $samlSettings)
    {
        $spData = $samlSettings->getSPData();
        $idpData = $samlSettings->getIdPData();
        $security = $samlSettings->getSecurityData();

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

        $nameIdObj = Builder::generateNameId(
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
