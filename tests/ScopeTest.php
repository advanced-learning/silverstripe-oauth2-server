<?php

namespace AdvancedLearning\Oauth2Server\Tests;

use AdvancedLearning\Oauth2Server\Extensions\GroupExtension;
use AdvancedLearning\Oauth2Server\Services\ScopeService;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

class ScopeTest extends SapphireTest
{
    protected static $fixture_file = 'tests/OAuthFixture.yml';

    /**
     * Setup test environment.
     */
    public function setUp()
    {
        // add GroupExtension for scopes
        Config::forClass(Group::class)->merge('extensions', [GroupExtension::class]);

        parent::setUp();
    }

    public function testHasScope()
    {
        $service = new ScopeService();
        $member = $this->objFromFixture(Member::class, 'member1');

        $this->assertTrue($service->hasScope('scope1', $member, 'Member should have scope1'));
        $this->assertFalse($service->hasScope('scope2', $member, 'Member should have scope2'));
    }
}
