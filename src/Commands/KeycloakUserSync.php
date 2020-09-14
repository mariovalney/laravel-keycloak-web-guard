<?php

namespace Vizir\KeycloakWebGuard\Commands;

use DateTime;
use DateTimeZone;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Vizir\KeycloakWebGuard\Services\KeycloakService;

class KeycloakUserSync extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'keycloak:sync';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Syncronization of the Keycloak Users to local database';

    /* @var KeycloakService */
    protected $keycloakService;

    /**
     * Command Constructor
     */
    public function __construct(KeycloakService $keycloakService) {
        parent::__construct();
        $this->keycloakService = $keycloakService;
    }
    
    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        DB::beginTransaction();
        $now = new DateTime('now', new DateTimeZone(config('app.timezone')));
        foreach($this->keycloakService->getUsers(config('keycloak-web.admin.username'), config('keycloak-web.admin.password')) as $keyCloakUser) {
            $data = [
                'keycloak_id' => $keyCloakUser['id'],
                'email' => $keyCloakUser['email'],
                'email_verified_at' => $keyCloakUser['emailVerified'] ? $now : null,
                'name' => join(' ', array_filter([$keyCloakUser['firstName'], $keyCloakUser['lastName']])),
                'created_at' => DateTime::createFromFormat('U', intval($keyCloakUser['createdTimestamp'] / 1000)),
                'updated_at' => $now
            ];

            DB::table('users')->updateOrInsert(['keycloak_id' => $keyCloakUser['id']], $data);
        }
        DB::commit();

        return 0;
    }

}