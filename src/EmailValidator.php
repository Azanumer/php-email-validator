<?php
/**
 * EmailValidator — dependency-free email validation with deliverability checks.
 *
 * Beyond syntax it verifies the domain actually receives mail (MX records),
 * flags disposable/temporary addresses, and can reject role-based accounts
 * (admin@, info@, …) that bounce or never convert.
 *
 *     $v = new EmailValidator();
 *     if ($v->validate('user@example.com')) { ... }
 *
 *     $report = $v->validateWithReport('user@mailinator.com');
 *     // ['valid' => false, 'errors' => ['disposable-domain']]
 */

class EmailValidator
{
    /** @var bool Check MX (and fallback A/AAAA) records for the domain. */
    private $checkMx;

    /** @var bool Reject known disposable/temporary email domains. */
    private $blockDisposable;

    /** @var bool Reject role-based local parts (admin@, support@, …). */
    private $blockRoleAccounts;

    /** @var string[] Extra disposable domains to block, beyond the built-in list. */
    private $extraDisposable;

    /** @var string[] */
    private static $disposableDomains = array(
        'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com',
        'temp-mail.org', 'throwawaymail.com', 'yopmail.com', 'getnada.com',
        'maildrop.cc', 'trashmail.com', 'dispostable.com', 'mailnesia.com',
        'sharklasers.com', 'spamgourmet.com', 'mytemp.email', 'tempinbox.com',
        'fakeinbox.com', 'inboxkitten.com', 'burnermail.io', 'mohmal.com',
        'emailondeck.com', 'mintemail.com', 'spambox.us', 'harakirimail.com',
        'mailcatch.com', 'guerrillamailblock.com', 'pokemail.net', 'spam4.me',
        'mailexpire.com', 'deadaddress.com', 'sogetthis.com', 'eelmail.com',
        'jetable.org', 'kasmail.com', 'zippymail.info', 'anonymbox.com',
        'tempemail.net', 'temporary-email.com', 'disposablemail.com',
    );

    /** @var string[] */
    private static $roleAccounts = array(
        'admin', 'administrator', 'webmaster', 'hostmaster', 'postmaster',
        'info', 'support', 'sales', 'contact', 'help', 'service', 'billing',
        'noreply', 'no-reply', 'mailer-daemon', 'abuse', 'security', 'careers',
        'jobs', 'hr', 'press', 'marketing', 'feedback', 'newsletter',
    );

    public function __construct(array $options = array())
    {
        $this->checkMx          = isset($options['checkMx']) ? (bool) $options['checkMx'] : true;
        $this->blockDisposable  = isset($options['blockDisposable']) ? (bool) $options['blockDisposable'] : true;
        $this->blockRoleAccounts = isset($options['blockRoleAccounts']) ? (bool) $options['blockRoleAccounts'] : false;
        $this->extraDisposable  = isset($options['disposableList']) ? (array) $options['disposableList'] : array();
    }

    /**
     * Quick check: true when the address passes every enabled check.
     */
    public function validate($email)
    {
        $report = $this->validateWithReport($email);
        return $report['valid'];
    }

    /**
     * Full check with a machine-readable error list.
     *
     * @return array{valid: bool, errors: string[]}
     */
    public function validateWithReport($email)
    {
        $errors = array();
        $email = is_string($email) ? trim($email) : '';

        if ($email === '' || strlen($email) > 254) {
            $errors[] = 'invalid-format';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'invalid-format';
        } else {
            list($local, $domain) = explode('@', $email, 2);
            $domain = strtolower($domain);

            // Local part must not be empty or absurdly long (RFC 5321: 64 octets).
            if ($local === '' || strlen($local) > 64) {
                $errors[] = 'invalid-local-part';
            }

            // Domain labels: 1–63 chars, alnum + hyphen, no leading/trailing hyphen.
            $labelsOk = true;
            foreach (explode('.', $domain) as $label) {
                $len = strlen($label);
                if ($len < 1 || $len > 63 || !preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/', $label)) {
                    $labelsOk = false;
                    break;
                }
            }
            if (!$labelsOk) {
                $errors[] = 'invalid-domain';
            }

            if ($this->checkMx && empty($errors)) {
                if (!checkdnsrr($domain, 'MX') && !checkdnsrr($domain, 'A') && !checkdnsrr($domain, 'AAAA')) {
                    $errors[] = 'no-mx-record';
                }
            }

            if ($this->blockDisposable && empty($errors)) {
                $blocked = array_merge(self::$disposableDomains, array_map('strtolower', $this->extraDisposable));
                if (in_array($domain, $blocked, true)) {
                    $errors[] = 'disposable-domain';
                }
            }

            if ($this->blockRoleAccounts && empty($errors)) {
                if (in_array(strtolower($local), self::$roleAccounts, true)) {
                    $errors[] = 'role-account';
                }
            }
        }

        return array('valid' => empty($errors), 'errors' => $errors);
    }

    /**
     * Convenience one-liner with default options.
     */
    public static function isValid($email)
    {
        $v = new self();
        return $v->validate($email);
    }
}
