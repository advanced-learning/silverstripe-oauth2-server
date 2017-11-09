<?php

namespace AdvancedLearning\Oauth2Server\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class Scope implements ScopeEntityInterface
{
    use EntityTrait;

    /**
     * Scope constructor.
     *
     * @param string $name The name of the scope.
     */
    public function __construct(string $name)
    {
        $this->setIdentifier($name);
    }

    /**
     * Get the scope in a format suitable for json.
     *
     * @return mixed
     */
    public function jsonSerialize()
    {
        return $this->getIdentifier();
    }
}
