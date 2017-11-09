<?php

namespace AdvancedLearning\Admin;

use AdvancedLearning\Oauth2Server\Models\AccessToken;
use AdvancedLearning\Oauth2Server\Models\Client;
use AdvancedLearning\Oauth2Server\Models\Scope;
use SilverStripe\Admin\ModelAdmin;

class OauthAdmin extends ModelAdmin
{
    private static $url_segment = 'oauth';

    private static $menu_title = 'OAuth';

    private static $managed_models = [
        Client::class,
        AccessToken::class,
        Scope::class
    ];
}
