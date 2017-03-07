<?php
namespace Kyslik\Django\Hashing;

use Illuminate\Hashing\BcryptHasher as OriginalHasher;

class BcryptHasher extends OriginalHasher
{

    /**
     * Default crypt cost factor (django default).
     *
     * @var int
     */
    protected $rounds = 12;

    protected $prefix = 'bcrypt_sha256$';


    /**
     * Hash the given value.
     *
     * @param  string $value
     * @param  array  $options
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    public function make($value, array $options = []): string
    {
        return $this->prefix.parent::make(hash('sha256', $value), $options);
    }


    /**
     * Check the given plain value against a hash.
     *
     * @param  string $value
     * @param  string $hashedValue
     * @param  array  $options
     *
     * @return bool
     */
    public function check($value, $hashedValue, array $options = []): bool
    {
        if (strlen($hashedValue) === 0) {
            return false;
        }

        if ($this->hasPrefix($hashedValue)) {
            $value = hash('sha256', $value);
        }

        return password_verify($value, $this->removePrefix($hashedValue));
    }


    /**
     * Check if string has prefix
     *
     * @param string $string
     *
     * @return bool
     */
    private function hasPrefix(string $string): bool
    {
        return (bool)strpos($string, $this->prefix);
    }


    /**
     * Removes prefix from string
     *
     * @param string $hashedValue
     *
     * @return string
     */
    private function removePrefix(string $hashedValue): string
    {
        if ($this->hasPrefix($hashedValue)) {
            $hashedValue = substr($hashedValue, strlen($this->prefix));
        }

        return $hashedValue;
    }


    /**
     * Check if the given hash has been hashed using the given options.
     *
     * @param  string $hashedValue
     * @param  array  $options
     *
     * @return bool
     */
    public function needsRehash($hashedValue, array $options = []): bool
    {
        if ( ! $this->hasPrefix($hashedValue)) {
            return true;
        }

        return parent::needsRehash($this->removePrefix($hashedValue), $options);
    }

}