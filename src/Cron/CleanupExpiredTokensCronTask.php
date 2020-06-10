<?php

namespace AdvancedLearning\Cron;

use AdvancedLearning\Oauth2Server\Repositories\AccessTokenRepository;
use Carbon\Carbon;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\CronTask\Interfaces\CronTask;
use SilverStripe\ORM\DB;

class CleanupExpiredTokensCronTask implements CronTask
{
    use Configurable;

    /**
     * Number of days to delete expired tokens.
     *
     * @var int
     */
    private static $age = 7;

    /**
     * Run at 1am every day.
     *
     * @return string
     */
    public function getSchedule()
    {
        return '0 1 * * *';
    }

    /**
     * Delete tokens which have expired more than $age days.
     */
    public function process()
    {
        $this->getTokenRepository()->deleteExpiredTokens(self::config()->get('age'));
    }

    /**
     * Get the repository for managing access tokens.
     *
     * @return AccessTokenRepository
     */
    protected function getTokenRepository(): AccessTokenRepository
    {
        return Injector::inst()->get(AccessTokenRepository::class);
    }
}
