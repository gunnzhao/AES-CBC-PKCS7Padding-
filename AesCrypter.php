<?php

class AesCrypter {

    private $key = 'php1234567890';
    private $algorithm;
    private $mode;

    public function __construct($key = '', $algorithm = MCRYPT_RIJNDAEL_128,
        $mode = MCRYPT_MODE_CBC) {
        if (!empty($key)) {
            $this->key = $key;
        }
        $this->key = hash('sha256', $this->key, true);
        $this->algorithm = $algorithm;
        $this->mode = $mode;
    }

    public function encrypt($orig_data) {
        $encrypter = mcrypt_module_open($this->algorithm, '',
            $this->mode, '');
        $orig_data = $this->pkcs7padding(
            $orig_data, mcrypt_enc_get_block_size($encrypter)
        );
        mcrypt_generic_init($encrypter, $this->key, substr($this->key, 0, 16));
        $ciphertext = mcrypt_generic($encrypter, $orig_data);
        mcrypt_generic_deinit($encrypter);
        mcrypt_module_close($encrypter);
        return base64_encode($ciphertext);
    }

    public function decrypt($ciphertext) {
        $encrypter = mcrypt_module_open($this->algorithm, '',
            $this->mode, '');
        $ciphertext = base64_decode($ciphertext);
        mcrypt_generic_init($encrypter, $this->key, substr($this->key, 0, 16));
        $orig_data = mdecrypt_generic($encrypter, $ciphertext);
        mcrypt_generic_deinit($encrypter);
        mcrypt_module_close($encrypter);
        return $this->pkcs7unPadding($orig_data);
    }

    public function pkcs7padding($data, $blocksize) {
        $padding = $blocksize - strlen($data) % $blocksize;
        $padding_text = str_repeat(chr($padding), $padding);
        return $data . $padding_text;
    }

    public function pkcs7unPadding($data) {
        $length = strlen($data);
        $unpadding = ord($data[$length - 1]);
        return substr($data, 0, $length - $unpadding);
    }

}

