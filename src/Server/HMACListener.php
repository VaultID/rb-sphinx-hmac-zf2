<?php
namespace RB\Sphinx\Hmac\Zend\Server;

use RB\Sphinx\Hmac\Exception\HMACAdapterInterruptException;
use RB\Sphinx\Hmac\Exception\HMACException;
use Zend\Authentication\Result;
use Zend\EventManager\EventManagerInterface;
use Zend\EventManager\ListenerAggregateInterface;
use Zend\EventManager\ListenerAggregateTrait;
use Zend\EventManager\SharedEventManagerInterface;
use Zend\Http\Request;
use Zend\Mvc\MvcEvent;
use Zend\Router\RouteMatch;
use ZF\ApiProblem\ApiProblem;
use ZF\ApiProblem\ApiProblemResponse;
use ZF\Rest\ResourceEvent;
use ZF\Rest\RestController;

class HMACListener implements ListenerAggregateInterface
{

    use ListenerAggregateTrait;

    protected $_debugCount = 0;

    /**
     *
     * @var HMACAbstractAdapter
     */
    protected $adapter = NULL;

    /**
     *
     * @var string
     */
    protected $adapterClass = NULL;

    /**
     * Seletor do serviço da AbstratcFactory que irá instanciar o HMAC
     *
     * @var string
     */
    protected $selector = NULL;

    /**
     * 
     * @var array
     */
    protected $restParams = array();

    protected function _debug($msg)
    {
        $this->_debugCount++;
        //file_put_contents('/tmp/rest.log', $this->_debugCount . ': ' . $msg . "\n", FILE_APPEND);
    }

    /**
     * @param  EventManagerInterface $events
     */
    public function attach(EventManagerInterface $events, $priority = 1)
    {
        $this->listeners[] = $events->attach(MvcEvent::EVENT_ROUTE, [$this, '__invoke'], -1000);
    }

    /**
     * Listener para EVENT_ROUTE
     *
     * @param MvcEvent $e        	
     */
    public function __invoke(MvcEvent $e)
    {

        $this->_debug('__invoke');

        /**
         * Só tratar requisições HTTP(S)
         */
        $request = $e->getRequest();
        if (!method_exists($request, 'getHeaders')) {
            return;
        }

        /**
         * Guardar objetos necessários para validação APIGILITY REST
         */
        $app = $e->getApplication();
        $services = $app->getServiceManager();
        $config = $services->get('Config');

        $this->restParams['config'] = $config;
        $this->restParams['request'] = $e->getRequest();
        $this->restParams['serviceManager'] = $e->getApplication()->getServiceManager();

        /**
         * Verificar configuração de autenticação HMAC
         * $this->selector será definido a partir da configuração
         */
        try {
            /**
             * Se não requer autenticação HMAC, retornar silenciosamente
             */
            if (!$this->_checkConfig($e))
                return;

            /**
             * Executar autenticação com Adapter definido na configuração
             */
            $adapter = __NAMESPACE__ . '\\' . $this->adapterClass;
            if ($adapter::canHandle($request)) {
                /**
                 * Autenticar a requisição
                 */
                $this->adapter = new $adapter ();

                /**
                 * Registrar Adapter para disponibilizar ao Controller via Plugin
                 */
                $e->setParam('RBSphinxHmacAdapter', $this->adapter);


                $result = $this->adapter->authenticate($request, $this->selector, $e->getApplication()->getServiceManager(), $e);
            } else {
                $result = new Result(Result::FAILURE, null, array(
                    'HMAC Authentication required'
                ));
            }
        } catch (HMACAdapterInterruptException $exception) {
            /**
             * Se o Adapter interromper a requisição, devolver imediatamente a resposta
             *
             * TARGET: Zend\Mvc\Controller\AbstractActionController
             */
            return $e->getTarget()->getResponse();
        } catch (HMACException $exception) {
            $result = new Result(Result::FAILURE, null, array(
                'HMAC ERROR: ' . $exception->getMessage()
            ));
        }

        /**
         * Verificar resultado da autenticação HMAC
         */
        if (!$result->isValid()) {

            /**
             * TARGET: Zend\Mvc\Controller\AbstractActionController
             */
            $response = $e->getTarget()->getResponse();

            /**
             * PREPARAR RESPOSTA DE ERRO
             */
            $response->getHeaders()->addHeaderLine('Content-Type', 'application/problem+json');

            $resposta = array(
                'type' => 'https://github.com/reinaldoborges/rb-sphinx-hmac-zf2/wiki',
                'title' => 'Unauthorized',
                'status' => 401,
                'detail' => implode("\n", $result->getMessages()),
                'instance' => $request->getUriString()
            );

            /**
             * Informar descrição do HMAC na mensagem de erro
             */
            if ($this->adapter !== NULL) {
                $description = $this->adapter->getHmacDescription();
                if ($description !== NULL) {
                    $resposta ['hmac'] = $description;
                    $resposta ['version'] = $this->adapter->getVersion();
                }
            }

            $response->setContent(json_encode($resposta));
            $response->setStatusCode(401);

            return $response;
        }

        /**
         * Registrar identidade autenticada para que fique acessível ao Controller
         */
        $e->setParam('RBSphinxHmacAdapterIdentity', $result->getIdentity());
    }

    /**
     * Retrieve the identifier, if any
     *
     * Attempts to see if an identifier was passed in either the URI or the
     * query string, returning it if found. Otherwise, returns a boolean false.
     *
     * @param  RouteMatch $routeMatch
     * @param  Request $request
     * @return false|mixed
     */
    protected function getIdentifier($controller, $routeMatch, $request)
    {
        $identifier = $controller->getIdentifierName();
        $id = $routeMatch->getParam($identifier, false);
        if ($id !== false) {
            return $id;
        }

        $id = $request->getQuery()->get($identifier, false);
        if ($id !== false) {
            return $id;
        }

        return false;
    }

    protected function resolveAction(MvcEvent $e)
    {
        /* @var $controller RestController */
        $controller = $e->getTarget();
        $request = $e->getRequest();
        $routeMatch = $e->getRouteMatch();
        // RESTful methods
        $method = strtolower($request->getMethod());


        switch ($method) {
            // Custom HTTP methods (or custom overrides for standard methods)
            case (isset($this->customHttpMethodsMap[$method])):
                $action = $method;
                break;
            // DELETE
            case 'delete':
                $id = $this->getIdentifier($controller, $routeMatch, $request);

                if ($id !== false) {
                    $action = 'delete';
                    break;
                }

                $action = 'deleteList';
                break;
            // GET
            case 'get':
                $id = $this->getIdentifier($controller, $routeMatch, $request);
                if ($id !== false) {
                    $action = 'get';
                    break;
                }
                $action = 'getList';
                break;
            // HEAD
            case 'head':
                $id = $this->getIdentifier($controller, $routeMatch, $request);
                if ($id === false) {
                    $id = null;
                }
                $action = 'head';
                break;
            // OPTIONS
            case 'options':
                $action = 'options';
                break;
            // PATCH
            case 'patch':
                $id = $this->getIdentifier($controller, $routeMatch, $request);

                if ($id !== false) {
                    $action = 'patch';
                    break;
                }

                $action = 'patchList';
                break;
            // POST
            case 'post':
                $action = 'create';
                break;
            // PUT
            case 'put':
                $id = $this->getIdentifier($controller, $routeMatch, $request);

                if ($id !== false) {
                    $action = 'update';
                    break;
                }

                $action = 'replaceList';
                break;
        }
        return $action;
    }

    /**
     * Checa configuração de autenticação HMAC para Controller/Action
     *
     * @param MvcEvent $e        	
     * @return boolean - Aplicar autenticação HMAC
     */
    protected function _checkConfig(MvcEvent $e = null, $config = null)
    {
        $this->_debug('_checkConfig');

        /**
         * Recuperar configuração salva em __invoke()
         */
        if ($config == null) {
            $config = $this->restParams['config'];
        }

        /**
         * Se configuração não existir para o Controller, retornar silenciosamente
         */
        if (!isset($config ['rb_sphinx_hmac_server']) || !isset($config ['rb_sphinx_hmac_server'] ['controllers'])) {
            return false;
        }

        /**
         * Identificação do Controller/Action
         */
        if (isset($this->restParams['controller'])) {
            $controller = $this->restParams['controller'];
        } elseif(is_null($e)) {
            $controller = null;
        } else {
            $params = $e->getRouteMatch()->getParams();
            $controller = $params['controller'];
        }


        /**
         * Apigility REST não tem Action
         */
        if (isset($this->restParams['restEvent'])) {
            $action = $this->restParams['restEvent'];
        } elseif (isset($params['action'])) {
            $action = $params['action'];
        } else {
            /**
             * Popular dados necessários para processamento no evento do REST.
             * e escutar esse evento
             */
            $this->restParams['controller'] = $controller;

            /**
             * Registrar LISTENER para events APIGILITY REST
             */
            //$e->getApplication ()->getServiceManager ()->get('SharedEventManager')->attachAggregate($this);

            /**
             * Não tentar validar HMAC agora
             */
            return false;
        }

        /**
         * Se Controller não está na lista, retornar sem autenticação HMAC
         */
        if (!array_key_exists($controller, $config ['rb_sphinx_hmac_server'] ['controllers'])) {
            return false;
        }

        /**
         * Verificar se há filtro de actions na configuração do controller.
         */
        if (isset($config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions']) && is_array($config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'])) {

            /**
             * Se não existir a chave, ou se o valor for FALSE ou NULL, não tratar este Action com o HMAC
             */
            if (!array_key_exists($action, $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions']) || $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action] === FALSE || $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action] === NULL) {
                return false;
            }
        }

        /**
         * Selector é obrigatório
         */
        $selector = $this->_getActionConfig($config, $controller, $action, 'selector');
        if ($selector === NULL || $selector === '') {
            throw new HMACException('HMAC SELECTOR não definido para Controller ' . $controller);
        }

        /**
         * Verificar se Selector está definido
         */
        if (!isset($config ['rb_sphinx_hmac_server'] ['selectors']) || !is_array($config ['rb_sphinx_hmac_server'] ['selectors']) || !array_key_exists($selector, $config ['rb_sphinx_hmac_server'] ['selectors'])) {
            throw new HMACException('HMAC SELECTOR não definido na configuração: ' . $selector);
        }

        /**
         * Verificar mapeamento do Selector para Serviço da AbstractFactory
         */
        $selectorMap = $config ['rb_sphinx_hmac_server'] ['selectors'] [$selector];
        if ($selectorMap === NULL || $selectorMap === '') {
            throw new HMACException('HMAC SELECTOR não mapeado para ' . $selector);
        }
        $this->selector = $selectorMap;

        /**
         * Adapter é obrigatório
         */
        $adapter = $this->_getActionConfig($config, $controller, $action, 'adapter');
        if ($adapter === NULL || $adapter === '') {
            throw new HMACException('HMAC ADAPTER não definido para Controller ' . $controller);
        }

        /**
         * Verificar se Adapter está definido
         */
        if (class_exists($adapter)) {
            throw new HMACException('HMAC ADAPTER não definido: ' . $adapter);
        }
        $this->adapterClass = $adapter;

        return true;
    }

    /**
     * Recuperar configuração
     */
    protected function _getActionConfig($config, $controller, $action, $configKey)
    {
        $value = NULL;

        /**
         * Verificar se há filtro de actions na configuração do controller.
         */
        if (isset($config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions']) && is_array($config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'])) {

            /**
             * Verificar se há $configKey específico para a action
             */
            if (isset($config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action]) && is_array($config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action])) {
                if (array_key_exists($configKey, $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action])) {
                    $value = $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action] [$configKey];
                }
            }
        }

        /**
         * Verificar $configKey específico para o controller
         */
        if ($value === NULL && isset($config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] [$configKey])) {
            $value = $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] [$configKey];
        }

        /**
         * Verificar $configKey padrão para todos os controller's
         */
        if ($value === NULL && isset($config ['rb_sphinx_hmac_server'] ['default_' . $configKey])) {
            $value = $config ['rb_sphinx_hmac_server'] ['default_' . $configKey];
        }

        return $value;
    }

    /**
     * Listener para EVENT_FINISH acrescentar assinatura HMAC na resposta
     *
     * @param MvcEvent $e        	
     * @throws HMACException
     */
    public function onFinish(MvcEvent $e)
    {
        $this->_debug('onFinish');

        /**
         * Verificar no evento a necessidade de resposta com assinatura HMAC
         */
        if ($this->adapter !== NULL) {
            $this->_debug(' Sign');
            $this->adapter->signResponse($e);
        }
    }

    /**
     * @var \Zend\Stdlib\CallbackHandler[]
     */
    protected $sharedListeners = array();

    /**
     * (non-PHPdoc)
     * @see \Zend\EventManager\SharedListenerAggregateInterface::attachShared()
     */
    public function attachShared(SharedEventManagerInterface $events)
    {
        $listener = $events->attach(
            RestController::class, MvcEvent::EVENT_DISPATCH, [$this, 'onRestEvent'], 100
        );
        if (!$listener) {
            $listener = [$this, 'onRestEvent'];
        }
        $this->sharedListeners[] = $listener;
    }

    /**
     * Listener para eventos APIGILITY REST
     * @param ResourceEvent $e
     * @return void|ApiProblem
     */
    public function onRestEvent(MvcEvent $e)
    {

        $controller = $e->getTarget();

        if (!$controller instanceof RestController) {
            return;
        }
        
        $this->_debug('onRestEvent');

        $sessionStart = false;

        /**
         * Guardar nome do evento REST
         */
        $this->restParams['restEvent'] = $this->resolveAction($e);
        
        /**
         * Verificar configuração de autenticação HMAC
         * $this->selector será definido a partir da configuração
         */
        try {
            if (!$this->_checkConfig(null, $this->restParams['config']))
                return;

            /**
             * Executar autenticação com Adapter definido
             */
            $adapter = __NAMESPACE__ . '\\' . $this->adapterClass;

            if ($adapter::canHandle($this->restParams['request'])) {
                /**
                 * Autenticar a requisição
                 */
                $this->adapter = new $adapter ();
                $result = $this->adapter->authenticate($this->restParams['request'], $this->selector, $this->restParams['serviceManager']);
            } else {
                $result = new Result(Result::FAILURE, null, array(
                    'HMAC Authentication required'
                ));
            }
        } catch (HMACAdapterInterruptException $exception) {
            /**
             * Se o Adapter interromper a requisição, indica início de sessão
             */
            $sessionStart = true;
        } catch (HMACException $exception) {
            $result = new Result(Result::FAILURE, null, array(
                'HMAC ERROR: ' . $exception->getMessage()
            ));
        }

        /**
         * Verificar resultado da autenticação HMAC
         */
        if (!$sessionStart && !$result->isValid()) {
            $e->stopPropagation(true);
            $descricao = implode(" ", $result->getMessages());
            if ($this->adapter !== null)
                $descricao .= " (" . $this->adapter->getHmacDescription() . ' v' . $this->adapter->getVersion() . ")";
            
            return new ApiProblemResponse(new ApiProblem(401, $descricao));
        } else {
            /**
             * Registrar Adapter para disponibilizar ao Controller via Plugin
             */
            $e->setParam('RBSphinxHmacAdapter', $this->adapter);

            /**
             * Salvar Identity no ResourceEvent para que o Resource possa utiliza-lo
             */
            if (!$sessionStart)
                $e->setParam('RBSphinxHmacAdapterIdentity', $result->getIdentity());
        }

        if ($sessionStart) {
            $this->_debug('StopProg');
            $e->stopPropagation(true);
        }
    }

    /**
     * Detach all previously attached listeners
     *
     * @param SharedEventManagerInterface $events
     */
    public function detachShared(SharedEventManagerInterface $events)
    {
        foreach ($this->sharedListeners as $index => $listener) {
            if ($events->detach('ZF\Rest\Resource', $listener)) {
                unset($this->sharedListeners[$index]);
            }
        }
    }
}
