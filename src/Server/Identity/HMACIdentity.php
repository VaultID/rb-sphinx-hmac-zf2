<?php
/*
 * Script criado em 17/05/2017.
 */
namespace RB\Sphinx\Hmac\Zend\Server\Identity;

use RB\Sphinx\Hmac\Zend\Server\HMACAbstractAdapter;

/**
 * Description of HMACIdentity
 *
 * @author Guilherme Alves <guilherme.alves@solutinet.com.br>
 */
class HMACIdentity
{

    /**
     * HMACAdapter
     * @var HMACAbstractAdapter
     */
    private $hmacAdapter;

    /**
     * RBSphinxHmacAdapterIdentity
     * @var mixed
     */
    private $hmacIdentity;

    public function __invoke($container)
    {
        return $this;
    }

    public function setHmacAdapter(HMACAbstractAdapter $hmacAdapter)
    {
        $this->hmacAdapter = $hmacAdapter;

        return $this;
    }

    public function getHmacAdapter()
    {
        return $this->hmacAdapter;
    }

    public function getHmacIdentity()
    {
        return $this->hmacIdentity;
    }

    public function setHmacIdentity($hmacIdentity)
    {
        $this->hmacIdentity = $hmacIdentity;
        return $this;
    }
}
