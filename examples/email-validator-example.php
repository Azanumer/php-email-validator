<?php
// Demo: syntax + MX + disposable + role-account checks.
require __DIR__ . '/../src/EmailValidator.php';

$samples = array(
    'user@gmail.com',
    'not-an-email',
    'user@mailinator.com',
    'admin@example.com',
    'user@this-domain-definitely-does-not-exist-xyz123.com',
);

$strict = new EmailValidator(array('blockRoleAccounts' => true));

foreach ($samples as $email) {
    $report = $strict->validateWithReport($email);
    printf(
        "%-55s %s %s\n",
        $email,
        $report['valid'] ? 'VALID  ' : 'INVALID',
        $report['valid'] ? '' : ('(' . implode(', ', $report['errors']) . ')')
    );
}

// Note: MX checks need working DNS. On servers without outbound DNS
// (e.g. locked-down sandboxes), pass ['checkMx' => false].
