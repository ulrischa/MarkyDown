<?php
// HTTP regression fixture; do not deploy tests.
require __DIR__ . '/../../vendor/autoload.php';
$case = $_GET['case'] ?? '';
header('Vary: Accept-Encoding');
ulrischa\MarkdownResponse::start(['selector' => $case === 'missing' ? '#missing' : 'main'], 20000);
header('Vary: Accept-Encoding');
header('ETag: "html-only"');
if ($case === 'json') {
    header('Content-Type: application/json');
    echo '{"ok":true}';
    return;
}
if ($case === 'redirect') {
    header('Location: /target', true, 302);
    return;
}
if ($case === 'error') {
    http_response_code(403);
    echo 'Forbidden';
    return;
}
if ($case === 'empty') {
    http_response_code(204);
    return;
}
echo '<h1>Outside</h1><main><h2>Article</h2><p>Content</p>';
if ($case === 'large') {
    echo str_repeat('x', 25000);
}
if ($case === 'chunks') {
    echo str_repeat('x', 10000);
}
echo '</main>';
