<?php

namespace Saml\Message\Xml\Parser;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use Saml\Exception\Error;
use Saml\Exception\ValidationError;
use Saml\Message\Xml\Parser;

class AuthResponseParser
{
    /**
     * Gets Status from a Response.
     *
     * @param \DOMDocument $dom The Response as XML
     *
     * @return array $status The Status, an array with the code and a message.
     *
     * @throws ValidationError
     */
    public static function getStatus(\DOMDocument $dom)
    {
        $status = array();

        $statusEntry = Parser::query($dom, '/samlp:Response/samlp:Status');
        if ($statusEntry->length != 1) {
            throw new ValidationError(
                "Missing Status on response",
                ValidationError::MISSING_STATUS
            );
        }

        $codeEntry = Parser::query($dom, '/samlp:Response/samlp:Status/samlp:StatusCode', $statusEntry->item(0));
        if ($codeEntry->length != 1) {
            throw new ValidationError(
                "Missing Status Code on response",
                ValidationError::MISSING_STATUS_CODE
            );
        }
        $code = $codeEntry->item(0)->getAttribute('Value');
        $status['code'] = $code;

        $status['msg'] = '';
        $messageEntry = Parser::query($dom, '/samlp:Response/samlp:Status/samlp:StatusMessage', $statusEntry->item(0));
        if ($messageEntry->length == 0) {
            $subCodeEntry = Parser::query($dom, '/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode', $statusEntry->item(0));
            if ($subCodeEntry->length == 1) {
                $status['msg'] = $subCodeEntry->item(0)->getAttribute('Value');
            }
        } else if ($messageEntry->length == 1) {
            $msg = $messageEntry->item(0)->textContent;
            $status['msg'] = $msg;
        }

        return $status;
    }
}
