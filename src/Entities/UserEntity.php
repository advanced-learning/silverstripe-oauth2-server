<?php

namespace AdvancedLearning\Oauth2Server\Entities;

use AdvancedLearning\Oauth2Server\Extensions\GroupExtension;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

class UserEntity implements UserEntityInterface
{
    use EntityTrait;

    protected $member;

    public function __construct(Member $member)
    {
        $this->member = $member;
        $this->setIdentifier($member->Email);
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

    /**
     * Checks whether the member has a scope. Only works if the GroupExtension has been configured.
     *
     * @param string $scope
     * @return bool
     */
    public function hasScope(string $scope): bool
    {
        // always return true if extensions not configured
        return !Group::create()->hasExtension(GroupExtension::class) || $this->getMember()->Groups()->filter([
            'Scopes.Name' => $scope
        ])->count() > 0;
    }
}
