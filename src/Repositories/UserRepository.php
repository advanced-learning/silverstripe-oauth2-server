<?php

namespace AdvancedLearning\Oauth2Server\Repositories;


use AdvancedLearning\Oauth2Server\Entities\UserEntity;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

class UserRepository implements UserRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        ClientEntityInterface $clientEntity
    ) {
        $member = Member::get()->filter(['Email' => $username])->first();
        /**
         * @var ValidationResult $result
         */
        $result = Injector::inst()->get(MemberAuthenticator::class)->checkPassword($member, $password);

        return $result->isValid() ? new UserEntity($member) : null;
    }

    /**
     * Gets a UserEntity by their identifier (Member->Email).
     *
     * @param string $userIdentifier
     * @return UserEntity
     */
    public function getUserEntityByIdentifier(string $userIdentifier): UserEntity
    {
        return new UserEntity(Member::get()->filter(['Email' => $userIdentifier])->first());
    }

}
