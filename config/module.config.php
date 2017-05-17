<?php

use RB\Sphinx\Hmac\Zend\Server\Identity\HMACIdentity;
use RB\Sphinx\Hmac\Zend\Server\HMACListener;

return array(
    'service_manager' => array(
        'invokables' => array(
            HMACListener::class => HMACListener::class,
        ),
        'factories' => [
            HMACIdentity::class => HMACIdentity::class
        ]
    ),
    'controller_plugins' => array(
        'invokables' => array(
            'HMACKeyId' => 'RB\Sphinx\Hmac\Zend\Server\Plugin\HMACKeyId',
            'HMACAdapter' => 'RB\Sphinx\Hmac\Zend\Server\Plugin\HMACAdapter'
        )
    )
);
