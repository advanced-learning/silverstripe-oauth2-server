<?php

namespace AdvancedLearning\Oauth2Server\Services;

use SilverStripe\Security\Member;

class ScopeService
{
    /**
     * Checks whether the member has the specified scope.
     *
     * @param string $name
     * @param Member $member
     *
     * @return bool
     */
    public function hasScope(string $name, Member $member): bool
    {
        return $member->Groups()->filter([
            'Scopes.Name' => $name
        ])->count() > 0;
    }
}