<?php
require __DIR__ . '/../vendor/autoload.php';

ulrischa\MarkdownResponse::start([
    'selector' => '#content',
    'selector_type' => 'css',
    'exclude' => '.advertisement',
    'base_url' => 'https://example.com/article',
]);
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Example article</title></head>
<body>
<nav>This navigation is HTML-only.</nav>
<main id="content">
    <h1>One URL, two representations</h1>
    <p>Browsers receive HTML. Clients requesting Markdown receive this article.</p>
    <p class="advertisement">This advertisement is excluded from Markdown.</p>
    <p><a href="/about">About this site</a></p>
</main>
</body>
</html>
