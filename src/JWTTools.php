<?php

declare(strict_types=1);

namespace Dersonsena\JWTTools;

use DateInterval;
use DateTime;
use Exception;
use Firebase\JWT\JWT;
use InvalidArgumentException;
use stdClass;
use yii\db\ActiveRecord;
use yii\helpers\BaseStringHelper;

final class JWTTools
{
    /**
     * @var ActiveRecord
     */
    private $model;

    /**
     * @var string
     */
    private $algorithm = 'HS256';

    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var mixed int
     */
    private $expiration;

    /**
     * @var JWTPayload
     */
    private $payload;

    private function __construct(string $secretKey, array $options = [])
    {
        $this->secretKey = $secretKey;

        if (isset($options['algorithm'])) {
            $this->algorithm = $options['algorithm'];
        }

        if (isset($options['expiration'])) {
            $this->expiration = (int)$options['expiration'];

            $options['exp'] = (new DateTime())
                ->add(new DateInterval("PT{$this->expiration}S"))
                ->getTimestamp();
        }

        $this->payload = JWTPayload::build($options);
    }

    /**
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * @return string
     */
    public function getSecretKey()
    {
        return $this->secretKey;
    }

    /**
     * @return int
     */
    public function getExpiration()
    {
        return $this->expiration;
    }

    /**
     * @return JWTPayload
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param  string $secretKey
     * @param  array  $options
     * @return JWTTools
     */
    public static function build(string $secretKey, array $options = [])
    {
        return new self($secretKey, $options);
    }

    /**
     * @param  ActiveRecord $model
     * @param  array $attributes
     * @return $this
     * @throws InvalidArgumentException
     */
    public function withModel(ActiveRecord $model, array $attributes = [])
    {
        $this->model = $model;
        $this->payload->setSub($this->model->getPrimaryKey());

        if (empty($attributes)) {
            return $this;
        }

        foreach ($attributes as $attr) {
            if (!$this->model->hasAttribute($attr)) {
                throw new InvalidArgumentException("Attribute '{$attr}' doesn't exists in model class '" . get_class($this->model) . "' .");
            }

            $this->payload->addExtraAttribute($attr, $this->model->getAttribute($attr));
        }

        return $this;
    }

    /**
     * @return string
     * @throws Exception
     */
    public function getJWT()
    {
        return JWT::encode($this->payload->getData(), $this->secretKey, $this->algorithm, $this->payload->get('sub'));
    }

    /**
     * @param  string $token
     * @return stdClass
     */
    public function decodeToken(string $token)
    {
        return JWT::decode($token, $this->secretKey, [$this->algorithm]);
    }

    /**
     * @param  string $token
     * @return bool
     */
    public function signatureIsValid(string $token)
    {
        list($header, $payload, $signatureProvided) = explode(".", $token);

        $signature = hash_hmac('sha256', "{$header}.{$payload}", $this->secretKey, true);
        $signature = str_replace("=", "", BaseStringHelper::base64UrlEncode($signature));

        if ($signatureProvided !== $signature) {
            return false;
        }

        return true;
    }

    /**
     * @param  string $token
     * @return bool
     * @throws Exception
     */
    public function tokenIsExpired(string $token)
    {
        $decodedToken = $this->decodeToken($token);
        $now = new DateTime();
        $expiration = new DateTime("@{$decodedToken->exp}");

        if ($now > $expiration) {
            return true;
        }

        return false;
    }
}
