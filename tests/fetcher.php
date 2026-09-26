<?php
namespace ulrischa;
// Deterministic transport boundary tests maintained by Uli Schäffler.
require __DIR__ . '/../vendor/autoload.php';

$responses = [];
$requests = [];
function dns_get_record($host, $type)
{
    return $host === 'mixed.test' ? [['ip'=>'1.1.1.1'], ['ipv6'=>'::1']] : [['ip'=>'1.1.1.1']];
}
function curl_init($url)
{
    global $responses;
    return (object) ['url'=>$url, 'response'=>array_shift($responses)];
}
function curl_setopt_array($handle, $settings)
{
    global $requests;
    $handle->settings = $settings;
    $requests[] = $handle;
    return true;
}
function curl_exec($handle)
{
    foreach ($handle->response['headers'] ?? [] as $line) {
        if (($handle->settings[CURLOPT_HEADERFUNCTION])($handle, $line) !== strlen($line)) {
            return false;
        }
    }
    $body = $handle->response['body'] ?? '';
    return ($handle->settings[CURLOPT_WRITEFUNCTION])($handle, $body) === strlen($body);
}
function curl_getinfo($handle, $key)
{
    return $key === CURLINFO_HTTP_CODE ? $handle->response['status'] : ($handle->response['type'] ?? 'text/html');
}
function curl_close($handle) {}
function expect_fetch($condition, $message)
{
    if (!$condition) {
        throw new \RuntimeException($message);
    }
}
function reject_fetch($url, $limit = 1048576)
{
    try {
        (new HtmlFetcher($limit))->fetch($url);
    } catch (\Exception $e) {
        return;
    }
    throw new \RuntimeException('Unsafe fetch was allowed.');
}
$responses = [['status'=>302, 'headers'=>['Location: /article']], ['status'=>200, 'body'=>'<p>Hello</p>']];
$page = (new HtmlFetcher())->fetch('https://public.test/start');
expect_fetch($page['url'] === 'https://public.test/article', 'Resolve relative redirect');
expect_fetch(count($requests) === 2 && $requests[1]->settings[CURLOPT_RESOLVE] === ['public.test:443:1.1.1.1'], 'Pin each validated DNS result');
expect_fetch($requests[0]->settings[CURLOPT_PROXY] === '' && $requests[0]->settings[CURLOPT_FOLLOWLOCATION] === false, 'Disable proxy and automatic redirects');
$responses = [['status'=>302, 'headers'=>['Location: http://127.0.0.1/private']]];
$requests = [];
reject_fetch('https://public.test/');
expect_fetch(count($requests) === 1, 'Block redirect before contacting private target');
$requests = [];
reject_fetch('https://mixed.test/');
expect_fetch(count($requests) === 0, 'Reject mixed public/private DNS answers');
$responses = [['status'=>200, 'body'=>str_repeat('x', 20)]];
reject_fetch('https://public.test/', 10);
$responses = [['status'=>200, 'headers'=>[str_repeat('x', 65537)]]];
reject_fetch('https://public.test/');
$responses = array_fill(0, 6, ['status'=>302, 'headers'=>['Location: /loop']]);
reject_fetch('https://public.test/');
$responses = [['status'=>200, 'body'=>'{}', 'type'=>'application/json']];
reject_fetch('https://public.test/');
$responses = [['status'=>200, 'body'=>"<p>Gr\xfc\xdfe</p>", 'type'=>'text/html; charset=ISO-8859-1']];
$page = (new HtmlFetcher())->fetch('https://public.test/');
expect_fetch($page['html'] === '<p>Grüße</p>', 'Decode declared source encoding');
echo "Fetcher boundary checks passed.\n";
