<?php
// Real HTTP integration checks maintained by Uli Schäffler.
$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
if (!$socket) {
    throw new RuntimeException($error);
}
$address = stream_socket_get_name($socket, false);
fclose($socket);
$log = tmpfile();
$command = [PHP_BINARY];
if (php_ini_loaded_file()) {
    $command[] = '-c';
    $command[] = php_ini_loaded_file();
}
$command = array_merge($command, ['-S', $address, '-t', __DIR__ . '/fixtures']);
$process = proc_open($command, [0 => ['pipe', 'r'], 1 => $log, 2 => $log], $pipes);
if (!is_resource($process)) {
    throw new RuntimeException('Could not start the PHP test server.');
}
function request_page(string $address, string $accept, string $case = '', string $method = 'GET'): array
{
    $ch = curl_init('http://' . $address . '/page.php?case=' . $case);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 5, CURLOPT_PROXY => '', CURLOPT_HTTPHEADER => ['Accept: ' . $accept], CURLOPT_CUSTOMREQUEST => $method, CURLOPT_NOBODY => $method === 'HEAD']);
    $response = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    return [$status, strtolower(substr((string) $response, 0, $size)), substr((string) $response, $size)];
}
function expect_http(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}
try {
    for ($attempt = 0; $attempt < 50; $attempt++) {
        $ready = @stream_socket_client('tcp://' . $address, $errno, $error, 0.1);
        if ($ready) {
            fclose($ready);
            break;
        }
        usleep(20000);
    }
    foreach (['text/html', '*/*', 'text/html, text/markdown'] as $accept) {
        [$status, $headers, $body] = request_page($address, $accept);
        expect_http($status === 200 && strpos($body, '<main>') !== false && strpos($headers, "vary: accept\r") !== false, 'HTML unchanged and Vary present');
    }
    foreach (['text/markdown', 'text/html;q=0.2,text/markdown;q=0.8'] as $accept) {
        [$status, $headers, $body] = request_page($address, $accept);
        expect_http($status === 200 && strpos($headers, 'content-type: text/markdown; charset=utf-8') !== false, 'Markdown content type');
        expect_http($body === "## Article\n\nContent\n", 'Only selected content');
        expect_http(strpos($headers, 'etag:') === false && strpos($headers, 'vary: accept-encoding') !== false && strpos($headers, "vary: accept\r") !== false, 'Clear stale validator and preserve Vary');
    }
    [$status, $headers, $body] = request_page($address, 'text/markdown', '', 'HEAD');
    expect_http($status === 200 && $body === '' && strpos($headers, 'text/markdown') !== false, 'HEAD metadata without body');
    [$status, $headers, $body] = request_page($address, 'application/json');
    expect_http($status === 406, 'Unsupported representation');
    foreach (['missing', 'large'] as $case) {
        [$status, $headers, $body] = request_page($address, 'text/markdown', $case);
        expect_http($status === 500 && $body === "Markdown conversion failed.\n" && strpos($headers, 'no-store') !== false, 'Fail closed: ' . $case);
    }
    [$status, $headers, $body] = request_page($address, 'text/markdown', 'chunks');
    expect_http($status === 200 && substr_count($body, 'x') === 10000 && strpos($body, '<main>') === false, 'Convert across buffer chunks');
    [$status, $headers, $body] = request_page($address, 'text/markdown', 'json');
    expect_http($status === 200 && $body === '{"ok":true}' && strpos($headers, 'application/json') !== false, 'JSON passthrough');
    [$status, $headers, $body] = request_page($address, 'text/markdown', 'error');
    expect_http($status === 403 && $body === 'Forbidden', 'Authorization error preserved');
    [$status, $headers, $body] = request_page($address, 'text/markdown', 'redirect');
    expect_http($status === 302 && strpos($headers, 'location: /target') !== false, 'Redirect preserved');
    [$status, $headers, $body] = request_page($address, 'text/markdown', 'empty');
    expect_http($status === 204 && $body === '', 'Bodyless status preserved');
    [$status, $headers, $body] = request_page($address, 'text/markdown', '', 'POST');
    expect_http($status === 200 && strpos($body, '<main>') !== false, 'POST unchanged');
    echo "HTTP integration checks passed.\n";
} finally {
    proc_terminate($process);
    proc_close($process);
    fclose($log);
}
