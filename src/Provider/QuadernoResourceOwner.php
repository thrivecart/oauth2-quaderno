<?php
namespace marcfowler\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class StripeResourceOwner implements ResourceOwnerInterface
{
    /**
     * Raw response
     *
     * @var array
     */
    protected $response;

    /**
     * Set response
     *
     * @param array $response
     */
    public function __construct(array $response)
    {
        $this->response = $response;
    }

    /**
     * Get Quaderno account id
     *
     * @return string
     */
    public function getAccountId()
    {
        return $this->response['account_id'];
    }

    /**
     * Return all of the account details available as an array
     *
     * @return array
     */
    public function toArray()
    {
        return $this->response;
    }
}