<?php

namespace AdvancedLearning\Oauth2Server\Entities;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;
use SilverStripe\Security\Member;

class UserEntity implements UserEntityInterface
{
    use EntityTrait;

    protected $member;

    public function __construct(Member $member)
    {
        $this->member = $member;
    }

    /**
     * Get the Member associated with this ClientEntity.
     *
     * @return Member
     */
    public function getMember()
    {
        return $this->member;
    }
}
