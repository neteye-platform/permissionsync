<?php
/**
 * Provision the disposable GLPI instance used by the real adapter suite.
 *
 * This is deliberately run through GLPI's normal CLI bootstrap and a real
 * administrative Auth login. It does not manufacture a PHP session. The
 * installed GLPI dataset creates the temporary ``glpi``/``glpi`` administrator
 * (install/empty_data.php); Auth::login() establishes its complete session.
 * Docker is unavailable locally, so the real suite has not been executed here.
 *
 * GLPI 11.x bootstrap note: unlike pre-11 releases, `inc/includes.php` no
 * longer boots the framework. As of 11.0.9 that file (verified against
 * https://github.com/glpi-project/glpi/blob/11.0.9/inc/includes.php) only
 * emits back-compat deprecation warnings for legacy globals; it performs no
 * autoloading, DB connection, or constant setup. The supported CLI/script
 * bootstrap is Composer's autoloader plus `Glpi\Kernel\Kernel::boot()`,
 * exactly as GLPI's own `tests/bootstrap.php` and `bin/console` do it
 * (https://github.com/glpi-project/glpi/blob/11.0.9/tests/bootstrap.php,
 * https://github.com/glpi-project/glpi/blob/11.0.9/src/Glpi/Kernel/Kernel.php).
 * `GLPI_ROOT` itself is defined automatically by the Composer-autoloaded
 * `src/autoload/constants.php` file as soon as the autoloader below runs, so
 * it must not be predefined here (that would collide with GLPI's own
 * `define()` and fatal).
 */

const GLPI_INSTALL_ROOT = '/var/www/glpi';
$glpi_vendor_autoload = GLPI_INSTALL_ROOT . '/vendor/autoload.php';

// Fail fast with a clear, non-secret diagnostic if the expected Composer
// autoloader is missing, e.g. because docker-compose.yml's bootstrap.php bind
// mount no longer matches the image's real installation root.
if (!is_file($glpi_vendor_autoload)) {
    fwrite(
        STDERR,
        "bootstrap.php: expected Composer autoloader not found at {$glpi_vendor_autoload}; " .
        "confirm docker-compose.yml mounts bootstrap.php under the glpi/glpi image's " .
        "installation root (" . GLPI_INSTALL_ROOT . ")\n"
    );
    exit(1);
}

chdir(GLPI_INSTALL_ROOT);
require_once $glpi_vendor_autoload;

use Glpi\Kernel\Kernel;

$kernel = new Kernel();
$kernel->boot();

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

// Full-coverage entity visibility topology (ADR 0009
// changeActiveEntities fix). The dedicated service account below holds three
// separate non-recursive Profile_User rows: Root and each of its two child
// branches. Together they cover every entity in this disposable database, so
// omitting `entities_id` selects "all" entities and enables
// `glpishowallentities`, despite the account having no recursive grant.
//
// The Root row deliberately remains non-recursive. GLPI rejects a numeric Root
// request with `is_recursive => true` for this account, so this topology also
// distinguishes the omitted-field "all" contract from a literal
// `entities_id => "all"` request that PHP would coerce to Root.
$branch_one = new Entity();
$branch_one_id = $branch_one->add([
    'name'        => 'permissionsync-topology-branch-one',
    'entities_id' => 0,
]);
if (!$branch_one_id) {
    bootstrap_fail('failed to create topology sibling entity one');
}
$branch_two = new Entity();
$branch_two_id = $branch_two->add([
    'name'        => 'permissionsync-topology-branch-two',
    'entities_id' => 0,
]);
if (!$branch_two_id) {
    bootstrap_fail('failed to create topology sibling entity two');
}

$topology_username = 'permissionsync-topology-service-' . bin2hex(random_bytes(6));
$topology_user = new User();
$topology_user_id = $topology_user->add([
    'name'          => $topology_username,
    'is_active'     => 1,
    'profiles_id'   => $service_profile_id,
    '_profiles_id'  => $service_profile_id,
    '_entities_id'  => (int) $branch_one_id,
    '_is_recursive' => 0,
    '_useremails'   => [],
]);
if (!$topology_user_id) {
    bootstrap_fail('failed to create the dedicated topology service-account user');
}
$topology_profile_user = new Profile_User();
$topology_root_profile_user_id = $topology_profile_user->add([
    'users_id'     => (int) $topology_user_id,
    'profiles_id'  => $service_profile_id,
    'entities_id'  => 0,
    'is_recursive' => 0,
]);
if (!$topology_root_profile_user_id) {
    bootstrap_fail('failed to grant the topology service account access to Root entity');
}
$topology_profile_user = new Profile_User();
$topology_profile_user_id = $topology_profile_user->add([
    'users_id'     => (int) $topology_user_id,
    'profiles_id'  => $service_profile_id,
    'entities_id'  => (int) $branch_two_id,
    'is_recursive' => 0,
]);
if (!$topology_profile_user_id) {
    bootstrap_fail('failed to grant the topology service account access to sibling branch two');
}

$expected_topology_profile_user_rows = [
    "{$topology_user_id}:{$service_profile_id}:0:0",
    "{$topology_user_id}:{$service_profile_id}:{$branch_one_id}:0",
    "{$topology_user_id}:{$service_profile_id}:{$branch_two_id}:0",
];
$actual_topology_profile_user_rows = [];
foreach ($DB->request([
    'SELECT' => ['users_id', 'profiles_id', 'entities_id', 'is_recursive'],
    'FROM'   => $topology_profile_user->getTable(),
    'WHERE'  => [
        'users_id'    => (int) $topology_user_id,
        'profiles_id' => $service_profile_id,
    ],
]) as $profile_user_row) {
    $actual_topology_profile_user_rows[] = sprintf(
        '%d:%d:%d:%d',
        $profile_user_row['users_id'],
        $profile_user_row['profiles_id'],
        $profile_user_row['entities_id'],
        $profile_user_row['is_recursive']
    );
}
sort($expected_topology_profile_user_rows);
sort($actual_topology_profile_user_rows);
if ($actual_topology_profile_user_rows !== $expected_topology_profile_user_rows) {
    bootstrap_fail('topology service-account Profile_User grants do not match the expected entities');
}

$topology_generated_user_token = User::getToken((int) $topology_user_id, 'api_token');
if (!is_string($topology_generated_user_token) || $topology_generated_user_token === '') {
    bootstrap_fail('failed to generate the topology service-account API token');
}
if (!$topology_user->getFromDB((int) $topology_user_id)) {
    bootstrap_fail('failed to reload the topology service-account user');
}
$topology_user_token_plaintext = (new GLPIKey())->decrypt($topology_user->fields['api_token'] ?? null);
if (
    !is_string($topology_user_token_plaintext)
    || $topology_user_token_plaintext === ''
    || $topology_user_token_plaintext !== $topology_generated_user_token
) {
    bootstrap_fail('failed to decrypt the stored topology service-account API token');
}

echo "APP_TOKEN={$app_token_plaintext}\n";
echo "USER_TOKEN={$user_token_plaintext}\n";
echo "SERVICE_USERNAME={$service_username}\n";
echo "TARGET_PROFILE_A=permissionsync-target-a\n";
echo "TARGET_PROFILE_B=permissionsync-target-b\n";
echo "TARGET_PROFILE_C=permissionsync-target-c\n";
echo "TOPOLOGY_USER_TOKEN={$topology_user_token_plaintext}\n";
echo "TOPOLOGY_BRANCH_TWO=Root entity > permissionsync-topology-branch-two\n";
