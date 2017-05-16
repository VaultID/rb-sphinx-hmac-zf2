<?php
namespace RB\Sphinx\Hmac\Zend;

use Zend\ModuleManager\Feature\AutoloaderProviderInterface;
use Zend\ModuleManager\Feature\ConfigProviderInterface;
use Zend\Mvc\MvcEvent;
use Zend\Mvc\ModuleRouteListener;

class Module implements AutoloaderProviderInterface, ConfigProviderInterface
{

    public function getAutoloaderConfig()
    {
        return array(
            'Zend\Loader\ClassMapAutoloader' => array(
                __DIR__ . '/autoload_classmap.php'
            ),
            'Zend\Loader\StandardAutoloader' => array(
                'namespaces' => array(
                    __NAMESPACE__ => __DIR__ . '/src/'
                )
            )
        );
    }

    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }

    /**
     * {@inheritDoc}
     */
    public function onBootstrap($e)
    {
        $app = $e->getApplication();
        $services = $app->getServiceManager();
        $em = $app->getEventManager();

        /**
         * Baixa prioridade, para avaliar necessidade de autenticação HMAC após todas as operações de rota
         */
        // Adiciona listener HMACListener no eventManager do ZF
        $services->get('RB\Sphinx\Hmac\Zend\Server\HMACListener')->attach($em);

        $sharedEvents = $em->getSharedManager();
        $services->get('RB\Sphinx\Hmac\Zend\Server\HMACListener')->attachShared($sharedEvents);
    }
}
