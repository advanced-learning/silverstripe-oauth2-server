<?php

namespace AdvancedLearning\Oauth2Server\Entities;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;
use SilverStripe\Security\Member;

class User implements UserEntityInterface
{
    use EntityTrait;

    /**
     * Get the Member associated with this Client.
     *
     * @return \SilverStripe\Security\Member
     */
    public function getMember()
    {
        return Member::get()->byID($this->getIdentifier());
    }
}
