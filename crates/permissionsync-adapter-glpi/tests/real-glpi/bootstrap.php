<?php
/**
 * Disposable, ephemeral GLPI bootstrap for the permissionsync real-GLPI
 * integration suite (ADR 0009 "Two-layer test policy").
 *
 * This script runs INSIDE the disposable GLPI container (via
 * `docker compose exec glpi php bootstrap.php`) after GLPI's base
 * install/HTTP readiness is proven, and BEFORE the V1 apirest.php API is
 * exercised by any adapter test. It provisions everything the real suite
 * needs using GLPI's own PHP object API rather than raw SQL, so that
 * token storage goes through the same encryption GLPI performs for any
 * real deployment:
 *
 *   - GLPIKey::encrypt() is invoked transparently by
 *     User::prepareInputForAdd()/prepareInputForUpdate() and by
 *     APIClient's own input preparation whenever a token field is present
 *     in the array passed to add()/update(). A raw `INSERT ... app_token =
 *     '<plaintext>'` (as this repository's prior bootstrap did) stores a
 *     value GLPI never encrypted itself, which GLPI's own decryption path
 *     cannot be trusted to accept.
 *
 * It provisions:
 *
 *   1. the V1 REST API configuration (enable_api,
 *      enable_api_login_external_token) via Config, not raw SQL;
 *   2. a dedicated, least-privilege service-account Profile granting only
 *      the rights ADR 0009 requires (find/create users, read/create/delete
 *      Profile_User) -- not Super-Admin;
 *   3. a dedicated ephemeral service-account User with an encrypted
 *      api_token, complete Profile_User visibility over the root entity
 *      (recursive), and login-with-password left disabled;
 *   4. a dedicated APIClient application token restricted to that
 *      account's usage.
 *
 * The generated PLAINTEXT App-Token and User-Token are printed to stdout
 * (as `APP_TOKEN=...` / `USER_TOKEN=...` lines) for the calling shell
 * script to capture -- this is the only place the plaintext value ever
 * exists outside GLPI's own encrypted storage.
 *
 * NOTE: this script has NOT been executed against a real GLPI 11.0.9
 * container in this environment (Docker is unavailable here). The exact
 * bootstrap entrypoint (`inc/includes.php`), the exact `Profile` rights
 * bitmask constants used below, and the exact `User`/`APIClient` field
 * names are derived from GLPI 11.0.x upstream source
 * (src/User.php, src/GLPIKey.php, src/APIClient.php, src/Profile.php) but
 * MUST be verified against an actual running container before this is
 * relied upon in CI. If GLPI 11.0.9's bootstrap entrypoint or field names
 * differ from what is used here, this script will fail loudly (GLPI class
 * autoloading/instantiation errors), not silently produce wrong output.
 */

// GLPI's own front controllers (public/index.php, public/apirest.php) all
// bootstrap through this legacy-compatible include. GLPI 10/11 still ship
// it for CLI scripts and plugins even though most first-party code moved
// to src/ with Composer autoloading.
define('GLPI_ROOT', '/var/www/html');
chdir(GLPI_ROOT);
require_once GLPI_ROOT . '/inc/includes.php';

function bootstrap_fail(string $message): void
{
    fwrite(STDERR, "bootstrap.php: {$message}\n");
    exit(1);
}

// A CLI/administrative session is required for User::add()/Profile::add()
// authorization checks. GLPI's own `bin/console` commands establish an
// internal privileged session the same way.
Session::start();
if (!Session::loadGroups()) {
    // loadGroups() is harmless if it fails before a real session exists;
    // the actual privilege escalation below is what matters.
}
$_SESSION['glpi_use_mode'] = Session::NORMAL_MODE;
$_SESSION['glpiactive_entity'] = 0;
$_SESSION['glpiactive_entity_recursive'] = true;
$_SESSION['glpiactiveentities'] = [0];
$_SESSION['glpiactiveentities_string'] = '0';
$_SESSION['glpiname'] = 'permissionsync-bootstrap';
$_SESSION['glpiID'] = 2; // GLPI's seeded super-admin user id, CLI-only, never used by the adapter itself.
$_SESSION['glpiactiveprofile'] = Profile_User::getForUser(2, true)[0] ?? null;
if (!$_SESSION['glpiactiveprofile']) {
    bootstrap_fail('could not establish an administrative bootstrap session');
}
$_SESSION['glpiactiveprofile'] = Profile::getProfileWithRights($_SESSION['glpiactiveprofile']['profiles_id'] ?? 4);

// 1. Enable the V1 REST API surface through Config, matching what the
//    GLPI setup UI itself would write.
Config::setConfigurationValues('core', [
    'enable_api' => 1,
    'enable_api_login_external_token' => 1,
]);

// 2. Dedicated, least-privilege profile: only User read/create and
//    Profile_User (assign_user) read/create/delete, per ADR 0009
//    ("only the GLPI rights needed to find/create users and manage their
//    Profile_User assignments").
$profile = new Profile();
$profile_id = $profile->add([
    'name'              => 'permissionsync-service-account',
    'interface'         => 'central',
    'is_default'        => 0,
]);
if (!$profile_id) {
    bootstrap_fail('failed to create the dedicated service-account profile');
}
$profile->update([
    'id'                       => $profile_id,
    'user'                     => READ | CREATE,
    'user_authtype'            => READ,
    'assign_user'              => READ | CREATE | DELETE | PURGE,
    'entity'                   => READ,
    'profile'                  => READ,
]);

// 3. Dedicated ephemeral service-account user. `password` is intentionally
//    omitted (no login-with-password); `api_token` is generated through
//    User::add()'s own token-preparation path so GLPIKey encrypts it
//    exactly the way a real deployment's token would be encrypted.
$user = new User();
$service_username = 'permissionsync-service-' . bin2hex(random_bytes(6));
$user_id = $user->add([
    'name'          => $service_username,
    '_useremails'   => [],
    'is_active'     => 1,
    'api_token'     => User::getUniqueToken('api_token'),
]);
if (!$user_id) {
    bootstrap_fail('failed to create the dedicated service-account user');
}
// Reload to obtain the plaintext token GLPI generated/encrypted for us:
// GLPI exposes the plaintext value transiently via getFromDB()+getAuthToken()
// immediately after creation, before any additional round trip.
$user->getFromDB($user_id);
$user_token_plaintext = $user->getAuthToken('api_token');
if (!$user_token_plaintext) {
    bootstrap_fail('failed to read back the generated user api_token');
}

// Complete Profile_User visibility over the root entity, recursive, using
// the dedicated least-privilege profile (not Super-Admin).
$profile_user = new Profile_User();
$profile_user_id = $profile_user->add([
    'users_id'      => $user_id,
    'profiles_id'   => $profile_id,
    'entities_id'   => 0,
    'is_recursive'  => 1,
]);
if (!$profile_user_id) {
    bootstrap_fail('failed to grant the dedicated service-account its Profile_User assignment');
}

// 4. Dedicated APIClient application token, generated the same way
//    (App::getUniqueToken triggers GLPIKey encryption on add()).
$api_client = new APIClient();
$api_client_id = $api_client->add([
    'name'          => 'permissionsync-real-integration',
    'is_active'     => 1,
    'entities_id'   => 0,
    'is_recursive'  => 1,
    'ipv4_range_start' => null,
    'ipv4_range_end'   => null,
    'app_token'     => APIClient::getUniqueToken('app_token'),
]);
if (!$api_client_id) {
    bootstrap_fail('failed to create the dedicated API client');
}
$api_client->getFromDB($api_client_id);
$app_token_plaintext = $api_client->getAuthToken();
if (!$app_token_plaintext) {
    bootstrap_fail('failed to read back the generated app_token');
}

echo "APP_TOKEN={$app_token_plaintext}\n";
echo "USER_TOKEN={$user_token_plaintext}\n";
echo "SERVICE_USERNAME={$service_username}\n";
