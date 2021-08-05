<?php 
require __DIR__.'/../vendor/firebase/php-jwt/src/JWT.php';
require __DIR__.'/../vendor/firebase/php-jwt/src/ExpiredException.php';
require __DIR__.'/../vendor/firebase/php-jwt/src/SignatureInvalidException.php';
require __DIR__.'/../vendor/firebase/php-jwt/src/BeforeValidException.php';

use \Firebase\JWT\JWT;

class JwtHandler {
    protected $jwt_secret;
    protected $token;
    protected $issuedAt;
    protected $expire;
    protected $jwt;

    public function __constructor() {
        date_default_timezone_set('Europe/Poland');
        $this->issuedAt + 3600;

        $this->expire = $this->issuedAt + 3600;

        $this->jwt_secret = "E5FEB55D546492CA5903C647BD6C73E3D04F2BA1B4CDD5517D34765C2C0E426C";
    }

        public function _jwt_encode_data($iss,$data){

        $this->token = array(
            //Adding the identifier to the token (who issue the token)
            "iss" => $iss,
            "aud" => $iss,
            // Adding the current timestamp to the token, for identifying that when the token was issued.
            "iat" => $this->issuedAt,
            // Token expiration
            "exp" => $this->expire,
            // Payload
            "data"=> $data
        );

        $this->jwt = JWT::encode($this->token, $this->jwt_secret);
        return $this->jwt;
    }

    protected function _errMsg($msg){
        return [
            "auth" => 0,
            "message" => $msg
        ];
    }

    public function _jwt_decode_data($jwt_token) {
        try {
            $decode = JWT::decode($jwt_token, $this->jwt_secret, array('HS256'));
            return [
                "auth" => 1,
                "data" => $decode->data
            ]; 
        } 
        
        catch(\Firebase\JWT\ExpiredException $e){
            return $this->_errMsg($e->getMessage());
        }
        catch(\Firebase\JWT\SignatureInvalidException $e){
            return $this->_errMsg($e->getMessage());
        }
        catch(\Firebase\JWT\BeforeValidException $e){
            return $this->_errMsg($e->getMessage());
        }
        catch(\DomainException $e){
            return $this->_errMsg($e->getMessage());
        }
        catch(\InvalidArgumentException $e){
            return $this->_errMsg($e->getMessage());
        }
        catch(\UnexpectedValueException $e){
            return $this->_errMsg($e->getMessage());
        }
    }

}

?>