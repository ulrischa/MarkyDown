# MarkyDown

Convert HTML into clean Markdown, either through the included web interface or directly in PHP. Add HTTP content negotiation to an existing PHP page so the **same URL** serves HTML to browsers and Markdown to clients requesting it.

- Select content using **CSS selectors or XPath**.
- Include all matches in document order, without repeating nested matches.
- Exclude navigation, advertisements or other selected elements.
- Preserve headings, links, lists, code blocks and Markdown tables.
- Use automatic article extraction when no content selector is supplied to the converter.
- Fetch public HTML pages with bounded responses and protection against internal-network requests.

## Requirements and installation

PHP **7.4 or later**, Composer 2, and the `curl`, `dom`, `mbstring` and `xml` extensions. A currently supported PHP release is recommended; PHP 7.4 compatibility is retained for existing installations.

```sh
git clone https://github.com/ulrischa/MarkyDown.git
cd MarkyDown
composer install --no-dev --no-plugins --no-scripts --prefer-dist
```

The committed lockfile pins versions compatible with PHP 7.4. Composer's platform setting keeps dependency updates compatible with that minimum. It does not replace installing the required PHP extensions.

For an existing Composer application, add this repository to its `repositories` configuration and require the package:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/ulrischa/MarkyDown" }
    ],
    "require": {
        "ulrischa/markydown": "dev-main"
    }
}
```

Then run `composer update ulrischa/markydown`. Commit your application's lockfile to pin the exact revision. You do not need to expose MarkyDown's web interface when using it as a library.

## Add Markdown negotiation to a PHP page

Put this **before any output**, preferably in your shared bootstrap or template entry point:

```php
<?php
require __DIR__ . '/vendor/autoload.php';

ulrischa\MarkdownResponse::start([
    'selector' => '#content',
    'selector_type' => 'css',
    'exclude' => '.advertisement, .share-buttons',
    'base_url' => 'https://example.com/articles/example',
]);
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Example</title></head>
<body>
<nav>Site navigation</nav>
<main id="content">
    <h1>Example article</h1>
    <p>This paragraph is available as HTML and Markdown.</p>
    <p class="advertisement">Excluded from Markdown.</p>
</main>
</body>
</html>
```

`base_url` is optional. Supply the page's canonical absolute URL to resolve relative links and images. Derive it from trusted application configuration, not an unchecked Host header. MarkyDown does **not** refetch the page and does not change its authentication flow.

For XPath, change the options to:

```php
ulrischa\MarkdownResponse::start([
    'selector_type' => 'xpath',
    'selector' => '//main[@id="content"]',
    'exclude' => '//aside | //*[@class="advertisement"]',
]);
```

Test the same URL:

```sh
curl -i -H 'Accept: text/html' https://example.com/article.php
curl -i -H 'Accept: text/markdown' https://example.com/article.php
curl -I -H 'Accept: text/markdown' https://example.com/article.php
```

A runnable example is in [`examples/page.php`](examples/page.php).

### Negotiation behavior

| Request | Result |
| --- | --- |
| Missing `Accept`, `*/*` or `text/*` | HTML |
| `Accept: text/markdown` | Markdown |
| `Accept: text/html, text/markdown` | HTML wins the tie |
| `Accept: text/html;q=0.5, text/markdown;q=1` | Markdown |
| `Accept: text/markdown;q=0, */*` | HTML |
| Neither supported representation acceptable | HTTP 406 for an otherwise successful HTML page |

Specific media ranges override wildcard ranges. `q=0` excludes a representation. Markdown responses use `Content-Type: text/markdown; charset=UTF-8` and `X-Content-Type-Options: nosniff`. Both representations vary on `Accept`, preserving existing `Vary` fields. Stale HTML validators and lengths are removed when a response is converted. Other cache directives remain under your application's control.

The integration handles GET and HEAD; HEAD has no response body. POST and other methods are untouched. Redirects, error responses, non-HTML content and downloads are not converted.

### Integration limits

- The default selector is `main`. Missing matches, empty output, invalid configuration or an oversized page produce a generic HTTP 500 with `Cache-Control: no-store`. There is no fallback exposing the whole page.
- The default HTML limit is **1 MiB**. Change it with the second argument: `MarkdownResponse::start($options, 2 * 1024 * 1024)`.
- Call `start()` once. Let PHP close its output buffer at the end of the request. Do not flush headers/output early, clean or close MarkyDown's buffer, or use this integration for streaming responses.
- Apply compression **after** conversion, such as at the web server. Already compressed PHP output is not converted.
- Existing conditional-response logic must distinguish HTML and Markdown before returning 304. This helper does not implement conditional requests, ranges or a Markdown cache. Do not reuse an HTML ETag for Markdown.
- Caches/CDNs must honor `Vary: Accept`. Personalized pages still need appropriate private/no-store policies.
- Static HTML files and non-PHP applications need a server-side adapter. A browser script alone cannot implement HTTP negotiation. JavaScript-generated content is not rendered by this library.

## Use the converter directly

```php
$converter = new ulrischa\MarkyDown();

$markdown = $converter->convertHtml($html, [
    'selector' => 'article > .body',
    'exclude' => ['.ads', '[data-label="share, print"]'],
    'base_url' => 'https://example.com/articles/example',
]);

$markdown = $converter->convertUrl('https://example.com/article', [
    'selector_type' => 'xpath',
    'selector' => '//article',
]);
```

| Option | Default | Meaning |
| --- | --- | --- |
| `selector` | `null` | CSS/XPath expression identifying content elements |
| `selector_type` | `css` | `css` or `xpath`; also applies to exclusions |
| `exclude` | `null` | One selector expression or an array of expressions |
| `base_url` | `null` | Absolute HTTP(S) URL for resolving relative links/images |
| `readability` | `true` | Automatically extract an article when no selector is supplied |

Use `['readability' => false]` without a selector to convert the full document. The HTTP helper instead defaults to `main`. An explicit selector always takes precedence over Readability. XPath expressions must return elements, not attributes, text nodes or scalars. CSS support follows Symfony CssSelector, not every browser-only pseudo-class.

`convertHtml()` and `convertUrl()` throw exceptions on invalid input, fetch failures and unmatched selectors. A selected but empty fragment can produce an empty string. The HTTP helper treats empty Markdown as an error.

The legacy API remains available and returns `''` on failure:

```php
$markdown = $converter->convert($url, null, 'main', '.ads, .sidebar');
$markdown = $converter->convert(null, $html, '#content');
```

Pass exactly one input. HTML strings must be UTF-8. URL fetching recognizes a charset declared in the HTTP Content-Type. Legacy pages without a correct charset may require decoding before `convertHtml()`.

## Web interface

For local use:

```sh
php -S 127.0.0.1:8080
```

Open `http://127.0.0.1:8080/`, choose URL or pasted HTML, select CSS or XPath, and optionally specify content and exclusions. Copy or download the result. Clipboard access requires HTTPS or localhost; manual text selection remains available.

For deployment, use a normal PHP web server with HTTPS. Restrict access to the converter UI or enforce server-side rate limits. The five-second session cooldown is a convenience, not protection against distributed abuse. Do not expose `.git`, `tests`, Composer metadata or `vendor` as downloadable files. The PHP development server is for local testing only.

## Security and fetching

Only public HTTP(S) targets on ports 80/443 are accepted. URL credentials are rejected. Every redirect is validated again; all returned DNS addresses must pass a conservative public-IP policy. The selected address is pinned to prevent DNS rebinding. Private, loopback, link-local, reserved, multicast and mapped/transition IPv6 ranges are blocked. Some unusual public IPv6 destinations are deliberately rejected.

Fetching uses TLS verification, a five-redirect limit, a 30-second request budget, a 64 KiB response-header limit and a 1 MiB body limit by default. DNS resolution depends on the system resolver and can exceed the request budget. Ambient proxies, cookies and credentials are not forwarded. Proxy-only environments need an explicitly reviewed network adapter; do not disable address validation to make them work.

Active HTML elements are removed and HTML Purifier sanitizes content before conversion. Markdown is **not** a universal XSS-safe output format: if you render the resulting Markdown as HTML elsewhere, sanitize that renderer's output too. Local files and external XML entities are not loaded by the HTML parser.

## Tests and dependencies

```sh
composer validate --strict
composer test
composer audit
```

Tests include extraction, exclusions, Unicode, code and tables, Accept negotiation, unsafe targets and real HTTP integration. The HTTP tests start an ephemeral localhost PHP server and require `proc_open` and cURL.

Dependencies remain on PHP-7.4-compatible lines: Readability 3.x, Symfony CssSelector 5.4, League URI 6.x and HTML-to-Markdown 5.x. Newer major lines may require newer PHP versions or API changes; they are not silently substituted. Dependency versions are recorded in `composer.lock`.

See [CHANGELOG.md](CHANGELOG.md) for behavior changes when upgrading.
