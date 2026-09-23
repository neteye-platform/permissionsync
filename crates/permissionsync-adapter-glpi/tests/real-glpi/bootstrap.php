<?php
/**
 * Provision the disposable GLPI instance used by the real adapter suite.
 *
 * This is deliberately run through GLPI's normal CLI bootstrap and a real
 * administrative Auth login. It does not manufacture a PHP session. The
 * installed GLPI dataset creates the temporary ``glpi``/``glpi`` administrator
 * (install/empty_data.php); Auth::login() establishes its complete session.
 * Docker is unavailable locally, so the real suite has not been executed here.
 */

define('GLPI_ROOT', '/var/www/html');
chdir(GLPI_ROOT);
require_once GLPI_ROOT . '/inc/includes.php';

function bootstrap_fail(string $message): void
{
    fwrite(STDERR, "bootstrap.php: {$message}\n");
    exit(1);
}

function add_profile_or_fail(string $name, array $rights = []): int
{
    $profile = new Profile();
    $profile_id = $profile->add(array_merge([
        'name'       => $name,
        'interface'  => 'central',
        'is_default' => 0,
    ], $rights));
    if (!$profile_id) {
        bootstrap_fail("failed to create profile {$name}");
    }
    return (int) $profile_id;
}

Session::destroy();
Session::start();
$auth = new Auth();
if (!$auth->login('glpi', 'glpi', true)) {
    bootstrap_fail('the disposable GLPI administrator login failed');
}
if (!Session::haveRight('profile', UPDATE) || !Session::haveRight('config', UPDATE)) {
    bootstrap_fail('the disposable GLPI administrator lacks the required rights');
}

Config::setConfigurationValues('core', [
    'enable_api'                      => 1,
    'enable_api_login_external_token' => 1,
]);

// Blank target profiles are strictly below the service profile: GLPI 11.0.9
// Profile::currentUserHaveMoreRightThan() compares every profile right, so the
// service-only grants below make each zero-right target legitimately assignable.
$target_profiles = [];
foreach (['a', 'b', 'c'] as $suffix) {
    $target_profiles[$suffix] = add_profile_or_fail("permissionsync-target-{$suffix}");
}
// Keep a deterministic pool large enough for the deferred >50-row pagination
// scenario without giving adapter payloads any built-in GLPI profile.
for ($index = 1; $index <= 60; ++$index) {
    add_profile_or_fail(sprintf('permissionsync-pagination-target-%02d', $index));
}

// Profile_User has no independent "assign_user" right in GLPI 11.0.9. Its
// canCreateItem() requires User READ, entity visibility, and a strictly lower
// target profile. These are the only service grants needed by this suite.
$service_profile_id = add_profile_or_fail('permissionsync-service-account', [
    'user'    => READ | CREATE | UPDATE | DELETE | PURGE,
    'entity'  => READ,
    'profile' => READ,
]);

$service_username = 'permissionsync-service-' . bin2hex(random_bytes(6));
$service_user = new User();
$service_user_id = $service_user->add([
    'name'          => $service_username,
    'is_active'     => 1,
    'profiles_id'   => $service_profile_id,
    '_profiles_id'  => $service_profile_id,
    '_entities_id'  => 0,
    '_is_recursive' => 1,
    '_useremails'   => [],
]);
if (!$service_user_id) {
    bootstrap_fail('failed to create the dedicated service-account user');
}

// User::getToken() is GLPI's supported API-token generation path. It saves via
// User::update(), which encrypts api_token; read the stored field through the
// same GLPIKey::decrypt() path used by User::getFromDBbyToken() (11.0.9
// src/User.php and src/GLPIKey.php), never by raw SQL.
$generated_user_token = User::getToken((int) $service_user_id, 'api_token');
if (!is_string($generated_user_token) || $generated_user_token === '') {
    bootstrap_fail('failed to generate the service-account API token');
}
if (!$service_user->getFromDB((int) $service_user_id)) {
    bootstrap_fail('failed to reload the dedicated service-account user');
}
$user_token_plaintext = (new GLPIKey())->decrypt($service_user->fields['api_token'] ?? null);
if (!is_string($user_token_plaintext) || $user_token_plaintext === '' || $user_token_plaintext !== $generated_user_token) {
    bootstrap_fail('failed to decrypt the stored service-account API token');
}

// APIClient::prepareInputForUpdate() creates and encrypts app_token only when
// _reset_app_token is set. This is the GLPI 11.0.9 supported creation flow;
// getUniqueAppToken() is deliberately left to that method rather than copied.
$api_client = new APIClient();
$api_client_id = $api_client->add([
    'name'             => 'permissionsync-real-integration',
    'is_active'        => 1,
    'entities_id'      => 0,
    'is_recursive'     => 1,
    'ipv4_range_start' => null,
    'ipv4_range_end'   => null,
    '_reset_app_token' => 1,
]);
if (!$api_client_id || !$api_client->getFromDB((int) $api_client_id)) {
    bootstrap_fail('failed to create the dedicated API client');
}
$app_token_plaintext = (new GLPIKey())->decrypt($api_client->fields['app_token'] ?? null);
if (!is_string($app_token_plaintext) || $app_token_plaintext === '') {
    bootstrap_fail('failed to decrypt the stored application token');
}

echo "APP_TOKEN={$app_token_plaintext}\n";
echo "USER_TOKEN={$user_token_plaintext}\n";
echo "SERVICE_USERNAME={$service_username}\n";
echo "TARGET_PROFILE_A=permissionsync-target-a\n";
echo "TARGET_PROFILE_B=permissionsync-target-b\n";
echo "TARGET_PROFILE_C=permissionsync-target-c\n";
