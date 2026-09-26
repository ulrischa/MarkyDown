<?php
// Regression tests maintained by Uli Schäffler. Run: php tests/run.php
require __DIR__ . '/../vendor/autoload.php';

use ulrischa\ContentNegotiation;
use ulrischa\HtmlFetcher;
use ulrischa\MarkyDown;

$checks = 0;
function check(bool $condition, string $message): void
{
    global $checks;
    $checks++;
    if (!$condition) {
        throw new RuntimeException($message);
    }
}
function rejects(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Exception $e) {
        check(true, $message);
        return;
    }
    check(false, $message);
}

$converter = new MarkyDown();
$html = '<h1>Outside</h1><main><header><h2>Grüße</h2></header><p>One <strong>bold</strong>.</p><p class="ad" data-label="a,b">Ad</p><section><p>Nested</p></section><pre><code>&lt;div&gt;example&lt;/div&gt;\n\n\nend</code></pre><a href="../next?q=1">Link</a></main><article>Second</article>';
$markdown = $converter->convertHtml($html, ['selector' => 'main, main section, article', 'exclude' => '[data-label="a,b"]', 'base_url' => 'https://example.org/docs/page']);
check(strpos($markdown, 'Outside') === false, 'Do not prepend headings outside the selection');
check(strpos($markdown, 'Grüße') !== false, 'Preserve UTF-8 and article headers');
check(substr_count($markdown, 'Nested') === 1 && strpos($markdown, 'Second') !== false, 'All matches without nested duplication');
check(strpos($markdown, 'Ad') === false, 'CSS attribute selectors containing commas');
check(strpos($markdown, '<div>example</div>') !== false, 'Preserve literal HTML in code');
check(strpos($markdown, 'https://example.org/next?q=1') !== false, 'Resolve relative links');
check(strpos($converter->convertHtml($html, ['selector' => '//main', 'selector_type' => 'xpath', 'exclude' => '//section | //*[@class="ad"]']), 'Nested') === false, 'XPath selection and exclusions');
check($converter->convertHtml('<h2>Selected</h2>', ['selector' => 'h2']) === '## Selected', 'Preserve selected element itself');
check(strpos($converter->convert(null, '<main><p>Works</p></main>', 'main'), 'Works') !== false, 'Legacy API');
check(strpos($converter->convertHtml('<main><script>alert(1)</script><p onclick="alert(1)">Safe</p><a href="javascript:alert(1)">Link</a></main>', ['selector'=>'main']), 'alert') === false, 'Remove active content');
check(strpos($converter->convertHtml('<main><table><tr><th>Name</th></tr><tr><td>Uli</td></tr></table></main>', ['selector'=>'main']), '|') !== false, 'Markdown tables');
foreach (['#missing', '[[['] as $selector) {
    rejects(function () use ($converter, $html, $selector) { $converter->convertHtml($html, ['selector'=>$selector]); }, 'Reject missing or invalid selection');
}
rejects(function () use ($converter, $html) { $converter->convertHtml($html, ['selector'=>'//p/text()', 'selector_type'=>'xpath']); }, 'Reject non-element XPath');
rejects(function () use ($converter, $html) { $converter->convertHtml($html, ['selector'=>'count(//p)', 'selector_type'=>'xpath']); }, 'Reject scalar XPath');
rejects(function () { (new MarkyDown(4))->convertHtml('12345'); }, 'Bound input');
rejects(function () use ($converter) { $converter->convertHtml("\xff"); }, 'Reject invalid UTF-8');
rejects(function () use ($converter) { $converter->convertHtml('<p>x</p>', ['typo'=>true]); }, 'Reject unknown options');
check($converter->convertHtml('<p>Plain</p>', ['readability'=>false]) === 'Plain', 'Explicit full document conversion');
check(strpos($converter->convertHtml('<p><a href="relative">Fresh</a></p>', ['readability'=>false]), 'example.org') === false, 'No base URL state leaked between calls');
foreach ([
    'text/html;charset=utf-8;q=0,text/html;q=1,text/markdown;q=0.5'=>'text/markdown',
    'text/markdown;charset=utf-8;q=0,text/markdown;q=1,text/html;q=0.5'=>'text/html',
    ''=>'text/html', '*/*'=>'text/html', 'text/*'=>'text/html',
    'text/markdown'=>'text/markdown', 'text/html, text/markdown'=>'text/html',
    'text/html;q=0.4, text/markdown;q=0.9'=>'text/markdown',
    'text/markdown;q=0, */*;q=1'=>'text/html',
    'text/html;q=0, text/*;q=1'=>'text/markdown',
    'text/markdown;q=0.2, text/*;q=0.8'=>'text/html',
    'text/markdown;q=broken, text/html'=>'text/html',
    'application/json'=>null, 'text/html;q=0,text/markdown;q=0'=>null,
    'TEXT/MARKDOWN; charset=UTF-8'=>'text/markdown',
] as $accept=>$expected) {
    check(ContentNegotiation::negotiate($accept) === $expected, 'Accept: ' . $accept);
}
foreach (['127.0.0.1','10.0.0.1','172.16.0.1','192.168.1.1','169.254.169.254','100.64.0.1','0.0.0.0','192.0.2.1','198.18.0.1','224.0.0.1','255.255.255.255','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::1','2002:7f00:1::'] as $ip) {
    check(!HtmlFetcher::isPublicIp($ip), 'Reject non-public IP: ' . $ip);
}
foreach (['1.1.1.1','8.8.8.8','2606:4700:4700::1111'] as $ip) {
    check(HtmlFetcher::isPublicIp($ip), 'Allow public IP: ' . $ip);
}
foreach (['file:///etc/passwd','http://127.0.0.1','http://[::1]/','http://example.org:8080','http://user:pass@example.org/','http://2130706433/'] as $url) {
    rejects(function () use ($url) { (new HtmlFetcher())->fetch($url); }, 'Reject unsafe URL');
}
check($converter->convertHtml('<nav><a href="//[">Broken</a></nav><main><p>Article</p></main>', ['selector'=>'main', 'base_url'=>'https://example.com/article']) === 'Article', 'Malformed link outside selection does not abort conversion');
check(strpos($converter->convertHtml('<main><a href="//[">Article</a></main>', ['selector'=>'main', 'base_url'=>'https://example.com/article']), 'Article') !== false, 'Malformed selected link preserves text');
echo "Passed $checks checks.\n";
