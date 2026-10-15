# PHP Email Validator

Dependency-free email validation that goes beyond `filter_var()` — it checks that
the domain actually receives mail, blocks disposable/temporary addresses, and can
reject role-based accounts.

## Usage

```php
require 'src/EmailValidator.php';

$v = new EmailValidator();            // sensible defaults
var_dump($v->validate('user@gmail.com'));      // true
var_dump($v->validate('user@mailinator.com')); // false (disposable)

// Machine-readable report
print_r($v->validateWithReport('user@no-such-domain-xyz.com'));
// ['valid' => false, 'errors' => ['no-mx-record']]

// Stricter signup form config
$strict = new EmailValidator(array(
    'checkMx'           => true,   // MX (fallback A/AAAA) must exist
    'blockDisposable'   => true,  // reject temp-mail domains
    'blockRoleAccounts' => true,   // reject admin@, info@, noreply@, …
    'disposableList'    => array('example-temp.com'), // your own additions
));

// One-liner with defaults
EmailValidator::isValid('a@b.com');
```

## Error codes

| Code | Meaning |
|---|---|
| `invalid-format` | Fails `filter_var()` or is over 254 chars |
| `invalid-local-part` | Empty or > 64 chars before the `@` |
| `invalid-domain` | Bad domain labels (length or characters) |
| `no-mx-record` | No MX/A/AAAA record — mail can't be delivered |
| `disposable-domain` | Known temporary-email provider (40+ built-in) |
| `role-account` | admin@, support@, noreply@, … (only when enabled) |

MX checks need working DNS — on locked-down servers pass `['checkMx' => false]`.

Requires PHP 7.4+. MIT licensed.
