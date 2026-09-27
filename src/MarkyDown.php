<?php
namespace ulrischa;

use League\HTMLToMarkdown\HtmlConverter;
use League\HTMLToMarkdown\Converter\TableConverter;
use League\Uri\Http;
use League\Uri\UriResolver;
use Symfony\Component\CssSelector\CssSelectorConverter;
use fivefilters\Readability\Configuration;
use fivefilters\Readability\Readability;

/** HTML extraction and Markdown conversion */
class MarkyDown
{
    private $css;
    private $purifier;
    private $converter;
    private $maxHtmlSize;

    public function __construct(int $maxHtmlSize = 1048576)
    {
        if ($maxHtmlSize < 1) {
            throw new \InvalidArgumentException('The HTML size limit must be positive.');
        }
        $this->maxHtmlSize = $maxHtmlSize;
        $this->css = new CssSelectorConverter();
    }

    /** Legacy API: returns an empty string on failure; selectors are CSS. */
    public function convert(?string $url, ?string $html, ?string $mainSelector = null, ?string $excludeSelectors = null): string
    {
        try {
            if ($url && $html) {
                throw new \InvalidArgumentException('Provide either a URL or HTML, not both.');
            }
            $options = ['selector' => $mainSelector, 'exclude' => $excludeSelectors];
            return $url ? $this->convertUrl($url, $options) : $this->convertHtml($html ?? '', $options);
        } catch (\Exception $e) {
            // Do not log submitted URLs or page contents, which may contain secrets.
            error_log('MarkyDown conversion failed: ' . get_class($e));
            return '';
        }
    }

    /** Fetch a public HTTP(S) page and use its final URL to resolve relative links. */
    public function convertUrl(string $url, array $options = []): string
    {
        $page = (new HtmlFetcher($this->maxHtmlSize))->fetch($url);
        $options['base_url'] = $page['url'];
        return $this->convertHtml($page['html'], $options);
    }

    /**
     * Options: selector, selector_type (css|xpath), exclude, base_url, readability.
     * Selectors must come from trusted configuration: syntax validation is not a CPU sandbox.
     * Explicit selection includes all matching elements, without nested duplicates.
     * Throws on invalid input or selection; never broadens an explicit selection.
     */
    public function convertHtml(string $html, array $options = []): string
    {
        $unknown = array_diff(array_keys($options), ['selector', 'selector_type', 'exclude', 'base_url', 'readability']);
        if ($unknown) {
            throw new \InvalidArgumentException('Unknown conversion option.');
        }
        $options += ['selector' => null, 'selector_type' => 'css', 'exclude' => null, 'base_url' => null, 'readability' => true];
        foreach (['selector', 'base_url'] as $key) {
            if ($options[$key] !== null && !is_string($options[$key])) {
                throw new \InvalidArgumentException('Selector and base URL must be strings.');
            }
        }
        if (!in_array($options['selector_type'], ['css', 'xpath'], true) || !is_bool($options['readability'])) {
            throw new \InvalidArgumentException('Invalid selector type or readability option.');
        }
        if (trim($html) === '' || strlen($html) > $this->maxHtmlSize || !mb_check_encoding($html, 'UTF-8')) {
            throw new \InvalidArgumentException('HTML must be non-empty UTF-8 within the configured size limit.');
        }
        $dom = HtmlParser::parse($html);
        $xpath = new \DOMXPath($dom);
        $exclude = $options['exclude'];
        if ($exclude !== null && !is_string($exclude) && !is_array($exclude)) {
            throw new \InvalidArgumentException('Exclusions must be a selector string or array of selectors.');
        }
        foreach (is_array($exclude) ? $exclude : [$exclude] as $selector) {
            if ($selector === null || $selector === '') {
                continue;
            }
            if (!is_string($selector)) {
                throw new \InvalidArgumentException('Each exclusion must be a string.');
            }
            foreach ($this->select($xpath, $selector, $options['selector_type']) as $node) {
                if ($node->parentNode) {
                    $node->parentNode->removeChild($node);
                }
            }
        }
        // Resolve links consistently, including explicitly selected content.
        if ($options['base_url'] !== null) {
            $base = Http::createFromString($options['base_url']);
            if (!in_array($base->getScheme(), ['http', 'https'], true) || $base->getHost() === '') {
                throw new \InvalidArgumentException('Base URL must be an absolute HTTP(S) URL.');
            }
            foreach ($xpath->query('//*[@href or @src]') as $node) {
                foreach (['href', 'src'] as $attribute) {
                    if ($node->hasAttribute($attribute)) {
                        $value = trim($node->getAttribute($attribute));
                        if ($value !== '' && !preg_match('/^[a-z][a-z0-9+.-]*:/i', $value)) {
                            try {
                                $node->setAttribute($attribute, (string) UriResolver::resolve(Http::createFromString($value), $base));
                            } catch (\League\Uri\Exceptions\SyntaxError $e) {
                                // A broken link must not discard otherwise usable page content.
                                $node->removeAttribute($attribute);
                            }
                        }
                    }
                }
            }
        }
        $selector = $options['selector'];
        if ($selector !== null && trim($selector) !== '') {
            $nodes = $this->select($xpath, $selector, $options['selector_type']);
            if (!$nodes) {
                throw new \RuntimeException('The content selector matched no elements.');
            }
            $selected = new \SplObjectStorage();
            foreach ($nodes as $node) {
                $selected->attach($node);
            }
            $content = '';
            foreach ($nodes as $node) {
                for ($parent = $node->parentNode; $parent && !$selected->contains($parent); $parent = $parent->parentNode) {
                }
                if (!$parent) {
                    $content .= $dom->saveHTML($node) . "\n";
                }
            }
        } elseif ($options['readability']) {
            $reader = new Readability(new Configuration(['OriginalURL' => $options['base_url'] ?? '', 'fixRelativeURLs' => false]));
            $reader->parse($dom->saveHTML());
            $content = $reader->getContent();
        } else {
            $content = $dom->saveHTML();
        }
        // Strip active elements before sanitizing; preserve article headers and footers.
        $fragment = HtmlParser::parse($content);
        $query = new \DOMXPath($fragment);
        foreach ($query->query('//script|//style|//iframe|//object|//embed|//form|//template|//noscript') as $node) {
            $node->parentNode->removeChild($node);
        }
        if (!$this->purifier) {
            $config = \HTMLPurifier_Config::createDefault();
            $config->set('Cache.DefinitionImpl', null);
            $config->set('URI.AllowedSchemes', ['http' => true, 'https' => true, 'mailto' => true]);
            $this->purifier = new \HTMLPurifier($config);
            $this->converter = new HtmlConverter(['strip_tags' => true, 'hard_break' => true, 'header_style' => 'atx']);
            $this->converter->getEnvironment()->addConverter(new TableConverter());
        }
        $clean = $this->purifier->purify($fragment->saveHTML());
        // Never strip_tags() Markdown: it destroys literal HTML inside code blocks.
        return trim($this->converter->convert($clean));
    }

    private function select(\DOMXPath $xpath, string $selector, string $type): array
    {
        if (strlen($selector) > 4096 || trim($selector) === '') {
            throw new \InvalidArgumentException('Selector must contain 1–4096 bytes.');
        }
        try {
            $expression = $type === 'css' ? $this->css->toXPath($selector) : $selector;
            $previous = libxml_use_internal_errors(true);
            try {
                $result = $xpath->query($expression);
            } finally {
                libxml_clear_errors();
                libxml_use_internal_errors($previous);
            }
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('Invalid selector.', 0, $e);
        }
        if ($result === false) {
            throw new \InvalidArgumentException('Invalid XPath expression.');
        }
        $nodes = [];
        foreach ($result as $node) {
            if (!$node instanceof \DOMElement) {
                throw new \InvalidArgumentException('Selectors must select elements, not attributes or text.');
            }
            $nodes[] = $node;
        }
        return $nodes;
    }
}
