<?php

namespace Scyllaly\HCaptcha;

use Symfony\Component\HttpFoundation\Request;
use GuzzleHttp\Client;

class HCaptcha
{
    const CLIENT_API = 'https://hcaptcha.com/1/api.js';
    const VERIFY_URL = 'https://hcaptcha.com/siteverify';

    /**
     * The hCaptcha secret key.
     *
     * @var string
     */
    protected $secret;

    /**
     * The hCaptcha sitekey key.
     *
     * @var string
     */
    protected $sitekey;

    /**
     * @var \GuzzleHttp\Client
     */
    protected $http;

    /**
     * The cached verified responses.
     *
     * @var array
     */
    protected $verifiedResponses = [];

    /**
     * @var null
     * lastScore
     */
    protected $lastScore = null;

    /**
     * Whether to use hCaptcha or not.
     *
     * @var bool
     */
    protected $enabled;

    /**
     * Cache of response verifications with timestamps
     * @var array
     */
    protected $responseCache = [];

    /**
     * Cache duration in seconds
     * @var int
     */
    protected $cacheDuration = 120;


    /**
     * HCaptcha constructor.
     *
     * @param string $secret
     * @param string $sitekey
     * @param array  $options
     * @param bool   $enabled
     */
    public function __construct($secret, $sitekey, $options = [], $enabled = true)
    {
        $this->secret = $secret;
        $this->sitekey = $sitekey;
        $this->http = new Client($options);
        $this->enabled = $enabled;
    }
    
    /**
     * Get the hCaptcha verification details for a given response
     *
     * @param string $response
     * @param string|null $clientIp
     * @return array
     */
    public function getResponseDetails(string $response, $clientIp = null): array
    {
        if (!$this->enabled) {
            return [
                'success' => true,
                'challenge_ts' => date('Y-m-d\TH:i:s\Z'),
                'hostname' => $_SERVER['HTTP_HOST'] ?? 'unknown',
            ];
        }

        if (empty($response)) {
            return [
                'success' => false,
                'challenge_ts' => date('Y-m-d\TH:i:s\Z'),
                'hostname' => $_SERVER['HTTP_HOST'] ?? 'unknown',
                'error-codes' => ['missing-input-response']
            ];
        }

        $verifyResponse = $this->getVerificationResponse($response, $clientIp, true);

        // Store verification state if needed
        if (isset($verifyResponse['success']) && $verifyResponse['success'] === true) {
            $this->lastScore = $verifyResponse['score'] ?? null;
            $this->verifiedResponses[] = $response;
        }

        return $verifyResponse;
    }

    /**
     * Verify hCaptcha response.
     *
     * @param string $response
     * @param string $clientIp
     *
     * @return bool
     */
    public function verifyResponse($response, $clientIp = null)
    {
        if (!$this->enabled) {
            return true; // Always true if hCaptcha is disabled
        }

        if (empty($response)) {
            return false;
        }

        // Return true if response already verified before.
        if (in_array($response, $this->verifiedResponses)) {
            return true;
        }

        $verifyResponse = $this->getVerificationResponse($response, $clientIp);

        // First check: success must be true
        if (!isset($verifyResponse['success']) || $verifyResponse['success'] !== true) {
            return false;
        }

        $this->lastScore = isset($verifyResponse['score']) ? $verifyResponse['score'] : null;

        // Score verification if enabled
        $isScoreVerificationEnabled = config('HCaptcha.score_verification_enabled', false);
        if ($isScoreVerificationEnabled) {
            if (!array_key_exists('score', $verifyResponse)) {
                throw new \RuntimeException('Score Verification is an exclusive Enterprise feature! Moreover, make sure you are sending the remoteip in your request payload!');
            }

            $score = (float) $verifyResponse['score'];

            if ($score > config('HCaptcha.score_threshold', 0.7)) {
                return false;
            }
        }

        $this->verifiedResponses[] = $response;
        return true;
    }

    /**
     * Verify hCaptcha response by Symfony Request.
     *
     * @param Request $request
     *
     * @return bool
     */
    public function verifyRequest(Request $request)
    {
        return $this->verifyResponse(
            $request->get('h-captcha-response'),
            $request->getClientIp()
        );
    }

    /**
     * Send verify request.
     *
     * @param array $query
     *
     * @return array
     * @throws \RuntimeException
     */
    protected function sendRequestVerify(array $query = [])
    {
        try {
            $response = $this->http->request('POST', static::VERIFY_URL, [
                'form_params' => $query,
                'timeout' => 5.0
            ]);

            $result = json_decode($response->getBody(), true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \RuntimeException('Invalid JSON response from hCaptcha');
            }

            return $result;

        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to verify hCaptcha response');
        }
    }

    /**
     * Get the score from the last successful hCaptcha verification.
     *
     * @return float|null The score of the last verification or null if not available.
     */
    public function getScoreFromLastVerification()
    {
        return $this->lastScore;
    }

    /**
     * Render HTML captcha.
     *
     * @param array $attributes
     *
     * @return string
     */
    public function display($attributes = [])
    {
        if (!$this->enabled) {
            return '';
        }

        $attributes = $this->prepareAttributes($attributes);
        return '<div' . $this->buildAttributes($attributes) . '></div>';
    }

    /**
     * @see display()
     */
    public function displayWidget($attributes = [])
    {
        return $this->display($attributes);
    }

    /**
     * Display a Invisible hCaptcha by embedding a callback into a form submit button.
     *
     * @param string $formIdentifier the html ID of the form that should be submitted.
     * @param string $text           the text inside the form button
     * @param array  $attributes     array of additional html elements
     *
     * @return string
     */
    public function displaySubmit($formIdentifier, $text = 'submit', $attributes = [])
    {
        if (!$this->enabled) {
            return sprintf('<button%s><span>%s</span></button>', $this->buildAttributes($attributes), $text);
        }

        $javascript = '';
        if (!isset($attributes['data-callback'])) {
            $functionName = 'onSubmit' . str_replace(['-', '=', '\'', '"', '<', '>', '`'], '', $formIdentifier);
            $attributes['data-callback'] = $functionName;
            $javascript = sprintf(
                '<script>function %s(){document.getElementById("%s").submit();}</script>',
                $functionName,
                $formIdentifier
            );
        }

        $attributes = $this->prepareAttributes($attributes);
        $button = sprintf('<button%s><span>%s</span></button>', $this->buildAttributes($attributes), $text);

        return $button . $javascript;
    }

    /**
     * Render js source
     *
     * @param null   $lang
     * @param bool   $callback
     * @param string $onLoadClass
     *
     * @return string
     */
    public function renderJs($lang = null, $callback = false, $onLoadClass = 'onloadCallBack')
    {
        if (!$this->enabled) {
            return '';
        }

        return '<script src="' . $this->getJsLink($lang, $callback, $onLoadClass) . '" async defer></script>' . "\n";
    }

    /**
     * Get hCaptcha js link.
     *
     * @param string  $lang
     * @param boolean $callback
     * @param string  $onLoadClass
     *
     * @return string
     */
    public function getJsLink($lang = null, $callback = false, $onLoadClass = 'onloadCallBack')
    {
        if (!$this->enabled) {
            return '';
        }

        $client_api = static::CLIENT_API;
        $params = [];

        $callback ? $this->setCallBackParams($params, $onLoadClass) : false;
        $lang ? $params['hl'] = $lang : null;

        return $client_api . '?' . http_build_query($params);
    }

    /**
     * @param $params
     * @param $onLoadClass
     */
    protected function setCallBackParams(&$params, $onLoadClass)
    {
        $params['render'] = 'explicit';
        $params['onload'] = $onLoadClass;
    }

    /**
     * Prepare HTML attributes and assure that the correct classes and attributes for captcha are inserted.
     *
     * @param array $attributes
     *
     * @return array
     */
    protected function prepareAttributes(array $attributes)
    {
        $attributes['data-sitekey'] = $this->sitekey;
        if (!isset($attributes['class'])) {
            $attributes['class'] = '';
        }
        $attributes['class'] = trim('h-captcha ' . $attributes['class']);

        return $attributes;
    }

    /**
     * Build HTML attributes.
     *
     * @param array $attributes
     *
     * @return string
     */
    protected function buildAttributes(array $attributes)
    {
        $html = [];

        foreach ($attributes as $key => $value) {
            $html[] = $key . '="' . $value . '"';
        }

        return count($html) ? ' ' . implode(' ', $html) : '';
    }

    /**
     * Get cached response if valid, or null if not found/expired
     *
     * @param string $response
     * @return array|null
     */
    private function getCachedResponse(string $response): ?array
    {
        if (isset($this->responseCache[$response])) {
            $cached = $this->responseCache[$response];
            if (time() - $cached['timestamp'] < $this->cacheDuration) {
                return $cached['response'];
            }
            // Remove expired cache entry
            unset($this->responseCache[$response]);
        }
        return null;
    }

    /**
     * Cache a verification response
     *
     * @param string $response
     * @param array $verifyResponse
     * @return void
     */
    private function cacheResponse(string $response, array $verifyResponse): void
    {
        $this->responseCache[$response] = [
            'timestamp' => time(),
            'response' => $verifyResponse
        ];
    }

    /**
     * Get verification response, either from cache or fresh API call
     *
     * @param string $response
     * @param string|null $clientIp
     * @param bool $includeSitekey
     * @return array
     */
    private function getVerificationResponse(string $response, ?string $clientIp, bool $includeSitekey = false): array
    {
        // Try to get from cache first
        $cachedResponse = $this->getCachedResponse($response);
        if ($cachedResponse !== null) {
            return $cachedResponse;
        }
        
        $params = [
            'secret'   => $this->secret,
            'response' => $response,
            'remoteip' => $clientIp,
        ];

        if ($includeSitekey) {
            $params['sitekey'] = $this->sitekey;
        }
        
        $verifyResponse = $this->sendRequestVerify($params);

        // Cache the response
        $this->cacheResponse($response, $verifyResponse);

        return $verifyResponse;
    }

}
