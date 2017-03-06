# Django-bcrypt

This package simply adds prefix that django uses to determine hashing algorithm.

# Installation && usage

## Composer

Pull this package in through Composer (development/latest version `dev-master`)

```
{
    "require": {
        "kyslik/django-bcrypt": "0.0.*"
    }
}
```

    $ composer update

In `config/app.php` comment out original hashing service provider

```
Illuminate\Hashing\HashServiceProvider::class,
```

and add django-bcrypt service provider

```
Kyslik\Django\Hashing\HashServiceProvider::class,
```

## Examples

Original implementation produces:

```
$2y$10$.vt2G66F1.DMx4docxG9BO9Jy0HgCYCWIe35AdFAhb/PmX0GcjGoa
```

This implementation produces:
```
bcrypt_sha256$$2b$12$xtQ8jSPiQidofTWrA6BtV.TK89Slcm9CYBz8Mfwa96SMCWNC8.ZWC
```
