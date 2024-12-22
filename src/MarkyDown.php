<?php
// src/MarkyMark.php
namespace ulrischa;

use Symfony\Component\CssSelector\CssSelectorConverter;
use League\HTMLToMarkdown\HtmlConverter;
use HTMLPurifier;
use HTMLPurifier_Config;
use fivefilters\Readability\Readability;
use fivefilters\Readability\Configuration;
use fivefilters\Readability\ParseException;

/**
 * Class MarkyDown
 *
 * Converts HTML content from a specified URL or pasted HTML into Markdown.
 * Utilizes Readability to extract the main content, reducing unwanted elements.
 * Allows optional CSS selectors for content extraction and exclusion.
 * Implements various security measures to prevent vulnerabilities.
 */
class MarkyDown
{
    private $submittedURL;
    private $submittedHTML;
    private $cssSelectorConverter;
    private $domDocument; // Added property to store DOMDocument instance

    public function __construct()
    {
        // Initialize the CSS selector converter
        $this->cssSelectorConverter = new CssSelectorConverter();
    }

    /**
     * @var array List of forbidden hostnames or IP addresses to prevent SSRF attacks.
     */
    private $forbiddenHosts = [
        'localhost',
        '127.0.0.1',
        '::1',
        '0.0.0.0',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '169.254.0.0/16',
        '::ffff:127.0.0.0/104',
        'fe80::/10'
    ];

    /**
     * @var string User-Agent string to be used in HTTP requests.
     */
    private $userAgent = 'MarkyDown/1.0';

    /**
     * @var int Maximum allowed URL length.
     */
    private $maxUrlLength = 2048; // 2KB

    /**
     * @var int Maximum allowed HTML content size in bytes.
     */
    private $maxHtmlSize = 1048576; // 1MB

    /**
     * @var string Path to HTMLPurifier.auto.php
     */
    private $purifierConfig = __DIR__ . '/../vendor/ezyang/htmlpurifier/library/HTMLPurifier.auto.php';

    /**
     * Converts the content of the provided URL or pasted HTML into Markdown.
     * Allows optional CSS selectors for main content and exclusions.
     *
     * @param string|null $url The URL to load (via GET or POST).
     * @param string|null $html The pasted HTML content (only via POST).
     * @param string|null $mainSelector Optional CSS selector for the main content area.
     * @param string|null $excludeSelectors Optional comma-separated CSS selectors to exclude.
     * @return string Returns the converted content as Markdown. Returns an empty string in case of an error.
     */
    public function convert(?string $url, ?string $html, ?string $mainSelector = null, ?string $excludeSelectors = null): string
    {
        try {
            if ($url) {
                $url = trim($url);
                if (!$this->isValidUrl($url)) {
                    return '';
                }

                // Limit URL length to 2048 characters
                if (strlen($url) > $this->maxUrlLength) {
                    error_log("URL exceeds the maximum allowed length.");
                    return '';
                }

                $htmlContent = $this->fetchHtml($url);
                if (empty($htmlContent)) {
                    return '';
                }
                
                $this->submittedURL = $url;

             
            } elseif ($html) {
                $htmlContent = trim($html);
                if (empty($htmlContent)) {
                    return '';
                }

                // Limit HTML size to 1MB
                if (strlen($htmlContent) > $this->maxHtmlSize) { // 1MB in bytes
                    error_log("HTML content exceeds the maximum allowed size.");
                    return '';
                }
                $this->submittedHTML = $htmlContent;
            } else {
                return '';
            }
            
            // Load HTML into DOMDocument once
            libxml_use_internal_errors(true);
            $this->domDocument = new \DOMDocument();
            $loaded = $this->domDocument->loadHTML(mb_convert_encoding($htmlContent, 'HTML-ENTITIES', 'UTF-8'), LIBXML_NONET);
            libxml_clear_errors();

            if (!$loaded) {
                error_log("Failed to load HTML into DOMDocument.");
                return '';
            }

            // Remove exclusion selectors if provided
            if ($excludeSelectors) {
                $htmlContent = $this->removeExclusions($excludeSelectors);
                if (empty($htmlContent)) {
                    error_log("HTML content is empty after removing exclusions.");
                    return '';
                }
            }

             // Extract <h1> element
            $h1Content = $this->extractH1();

            // Extract main content using selector or Readability
            if ($mainSelector) {
                $contentHtml = $this->extractContentBySelector($mainSelector);
            } else {
                $contentHtml = $this->extractMainContent($htmlContent);
            }

            if (empty($contentHtml)) {
                return '';
            }

            // Purify HTML using HTML Purifier
            $cleanHtml = $this->purifyHtml($contentHtml);
            if (empty($cleanHtml)) {
                return '';
            }

            // Convert HTML to Markdown with strip_tags enabled
            $converter = new HtmlConverter([
                'strip_tags' => true, // Enable tag stripping within the converter
                'hard_break' => true,
                'remove_nodes' => 'script style iframe embed form nav footer header object'
            ]);

            // Convert purified HTML to Markdown
            $markdown = $converter->convert($cleanHtml);

             // Check and insert <h1> if not present in Markdown
            if ($h1Content && strpos($markdown, $h1Content) === false) {
                $markdown = "# " . $h1Content . "\n\n" . $markdown;
            }

            // Optionally, remove excessive blank lines
            $markdown = preg_replace("/\n{3,}/", "\n\n", $markdown);
            
            // Lastly remove any remaining HTML tags
            $markdown = strip_tags($markdown);

            return $markdown;
        } catch (\Exception $e) {
            error_log("Conversion Error: " . $e->getMessage());
            return '';
        }
    }

    /**
     * Extracts the content of the first <h1> element from the DOMDocument.
     *
     * @return string|null The content of the <h1> tag or null if not found.
     */
    private function extractH1(): ?string
    {
        $xpath = new \DOMXPath($this->domDocument);
        $h1Node = $xpath->query("//h1")->item(0);

        return $h1Node ? trim($h1Node->nodeValue) : null;
    }


    /**
     * Removes elements based on exclusion selectors from the DOMDocument.
     *
     * @param string $excludeSelectors Comma-separated CSS selectors to exclude.
     * @return string The HTML content with excluded elements removed.
     */
    private function removeExclusions(string $excludeSelectors): string
    {
        $xpath = new \DOMXPath($this->domDocument);
        $selectors = array_map('trim', explode(',', $excludeSelectors));

        foreach ($selectors as $selector) {
            if ($this->isValidSelector($selector)) {
                $xpathQuery = $this->cssToXPath($selector);
                if (!empty($xpathQuery)) {
                    $nodes = $xpath->query($xpathQuery);
                    if ($nodes !== false) {
                        foreach ($nodes as $node) {
                            $node->parentNode->removeChild($node);
                        }
                    }
                }
            } else {
                error_log("Invalid exclusion selector: $selector");
            }
        }

        return $this->domDocument->saveHTML();
    }

    /**
     * Extracts content based on a CSS selector from the DOMDocument.
     *
     * @param string $selector CSS selector for the content area.
     * @return string The extracted HTML content.
     */
    private function extractContentBySelector(string $selector): string
    {
        $xpath = new \DOMXPath($this->domDocument);
        $xpathQuery = $this->cssToXPath($selector);
        if (empty($xpathQuery)) {
            error_log("Invalid main content selector: $selector");
            return '';
        }

        $nodes = $xpath->query($xpathQuery);
        if ($nodes === false || $nodes->length === 0) {
            error_log("No elements found for main content selector: $selector");
            return '';
        }

        $node = $nodes->item(0);
        if (!$node) {
            error_log("Failed to retrieve the first node for selector: $selector");
            return '';
        }

        // Extract inner HTML
        $innerHTML = '';
        foreach ($node->childNodes as $child) {
            $innerHTML .= $this->domDocument->saveHTML($child);
        }

        if (empty(trim($innerHTML))) {
            error_log("Extracted content is empty for selector: $selector");
            return '';
        }

        return $innerHTML;
    }

    /**
     * Extracts the main content from HTML using Readability.
     *
     * @param string $html The complete HTML content.
     * @return string The extracted main HTML content.
     */
    private function extractMainContent(string $html): string
    {
        $configuration = new Configuration([
            'fixRelativeURLs' => true,
            'OriginalURL' =>  $this->submittedURL ?? ''
        ]);

        $readability = new Readability($configuration);
        try {
            $readability->parse($html);
            return $readability->getContent();
        } catch (ParseException $e) {
            error_log('Error processing text: ' . $e->getMessage());
            return '';
        }
    }

    /**
     * Cleans HTML using HTML Purifier with default configuration.
     *
     * @param string $html The HTML to clean.
     * @return string The cleaned HTML.
     */
    private function purifyHtml(string $html): string
    {
        require_once $this->purifierConfig;
        $config = HTMLPurifier_Config::createDefault();
        $purifier = new HTMLPurifier($config);
        $clean_html = $purifier->purify($html);
        return $clean_html;
    }

    /**
     * Validates if a URL is syntactically correct, uses an allowed protocol,
     * and does not resolve to a forbidden host or IP.
     *
     * @param string $url The URL to validate.
     * @return bool Returns true if the URL is valid and allowed, otherwise false.
     */
    private function isValidUrl(string $url): bool
    {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            error_log("Invalid URL format: $url");
            return false;
        }

        $allowedSchemes = ['http', 'https'];
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (!in_array(strtolower($scheme), $allowedSchemes, true)) {
            error_log("Disallowed URL scheme ($scheme): $url");
            return false;
        }

        $host = parse_url($url, PHP_URL_HOST);
        $ip = gethostbyname($host);

        if ($this->isForbiddenIp($ip)) {
            error_log("Forbidden IP address ($ip) for URL: $url");
            return false;
        }

        if ($this->isForbiddenHost($host)) {
            error_log("Forbidden host ($host) for URL: $url");
            return false;
        }

        return true;
    }

    /**
     * Checks if the given IP address is within forbidden ranges.
     *
     * @param string $ip The IP address to check.
     * @return bool Returns true if the IP is forbidden, otherwise false.
     */
    private function isForbiddenIp(string $ip): bool
    {
        foreach ($this->forbiddenHosts as $forbidden) {
            if ($this->ipInRange($ip, $forbidden)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given hostname is explicitly forbidden.
     *
     * @param string $host The hostname to check.
     * @return bool Returns true if the hostname is forbidden, otherwise false.
     */
    private function isForbiddenHost(string $host): bool
    {
        return in_array(strtolower($host), array_map('strtolower', $this->forbiddenHosts), true);
    }

    /**
     * Determines if an IP address is within a specified range or matches exactly.
     *
     * @param string $ip The IP address to check.
     * @param string $range The IP or CIDR range to compare against.
     * @return bool Returns true if the IP is within the range, otherwise false.
     */
    private function ipInRange(string $ip, string $range): bool
    {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        list($range, $netmask) = explode('/', $range, 2);
        $netmask = (int)$netmask;

        if ($netmask < 0 || $netmask > 32) {
            error_log("Invalid netmask: $netmask in range: $range/$netmask");
            return false;
        }

        $ip_decimal = ip2long($ip);
        $range_decimal = ip2long($range);

        if ($ip_decimal === false || $range_decimal === false) {
            error_log("ip2long conversion failed for IP: $ip or Range: $range");
            return false;
        }

        if ($netmask === 0) {
            return true;
        }

        $mask = ($netmask === 32) ? 0xFFFFFFFF : (~((1 << (32 - $netmask)) - 1) & 0xFFFFFFFF);
        $range_min = $range_decimal & $mask;
        $range_max = $range_min + (~$mask & 0xFFFFFFFF);

        return ($ip_decimal >= $range_min) && ($ip_decimal <= $range_max);
    }

    /**
     * Fetches the HTML content of a URL using cURL with enhanced security settings.
     *
     * @param string $url The URL to fetch.
     * @return string The HTML content as a string. Returns an empty string in case of an error.
     */
    private function fetchHtml(string $url): string
    {
        $ch = curl_init($url);
        if (!$ch) {
            error_log("cURL Initialization Failed for URL: $url");
            return '';
        }

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->userAgent);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_MAXFILESIZE, 1048576);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            error_log("cURL Error (" . curl_errno($ch) . "): " . curl_error($ch) . " for URL: $url");
            curl_close($ch);
            return '';
        }

        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);

        if ($http_code >= 200 && $http_code < 300) {
            if (strpos($content_type, 'text/html') !== false) {
                return $response;
            } else {
                error_log("Invalid Content-Type ($content_type) for URL: $url");
            }
        } else {
            error_log("Unexpected HTTP Code ($http_code) for URL: $url");
        }

        return '';
    }

    /**
     * Converts a CSS selector to an XPath expression using Symfony's CssSelector.
     *
     * @param string $selector The CSS selector.
     * @return string The corresponding XPath expression.
     */
    private function cssToXPath(string $selector): string
    {
        try {
            // Convert CSS selector to XPath
            return $this->cssSelectorConverter->toXPath($selector);
        } catch (\Exception $e) {
            error_log("Invalid CSS Selector: " . $e->getMessage());
            return '';
        }
    }

    /**
     * Validates if a CSS selector is valid (Element, Class, ID, Attribute, etc.).
     *
     * @param string $selector The selector to validate.
     * @return bool Returns true if the selector is valid, otherwise false.
     */
    private function isValidSelector(string $selector): bool
    {
        // Allows simple and complex selectors while preventing malicious patterns
        return preg_match('/^([a-zA-Z][a-zA-Z0-9]*)?(#[a-zA-Z0-9\-_]+)?(\.[a-zA-Z0-9\-_]+)*(\[[a-zA-Z0-9\-_:]+(=[a-zA-Z0-9\-_]+)?\])*$/', $selector);
    }
}
