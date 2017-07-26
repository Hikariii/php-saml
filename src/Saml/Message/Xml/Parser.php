<?php

namespace Saml\Message\Xml;

use Saml\Constants;

class Parser
{
    /**
     * Extracts nodes from the DOMDocument.
     *
     * @param \DOMDocument $dom     The DOMDocument
     * @param string      $query   Xpath Expresion
     * @param \DomElement  $context Context Node (DomElement)
     *
     * @return \DOMNodeList The queried nodes
     */
    public static function query(\DomDocument $dom, $query, \DOMElement $context = null)
    {
        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('samlp', Constants::NS_SAMLP);
        $xpath->registerNamespace('saml', Constants::NS_SAML);
        $xpath->registerNamespace('ds', Constants::NS_DS);
        $xpath->registerNamespace('xenc', Constants::NS_XENC);
        $xpath->registerNamespace('xsi', Constants::NS_XSI);
        $xpath->registerNamespace('xs', Constants::NS_XS);
        $xpath->registerNamespace('md', Constants::NS_MD);

        if (isset($context)) {
            $res = $xpath->query($query, $context);
        } else {
            $res = $xpath->query($query);
        }
        return $res;
    }
}
