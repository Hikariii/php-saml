<?php

namespace Saml\Message\Validator;

use Saml\Settings;

class AbstractValidator
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

}
