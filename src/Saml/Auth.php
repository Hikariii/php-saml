<?php

namespace Saml;


class Auth
{

    /**
     * Initializes the SP SAML instance.
     *
     * @param Settings|null $settings Setting data
     */
    public function __construct(Settings $settings = null)
    {
        $this->_settings = $settings;
    }
}