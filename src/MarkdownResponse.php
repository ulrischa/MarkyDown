<?php
namespace ulrischa;

/** Optional PHP output integration. Maintainer: Uli Schäffler. */
class MarkdownResponse
{
    private static $started = false;

    /** Call before page output. Authentication and page generation still run normally. */
    public static function start(array $options = [], int $maxHtmlSize = 1048576): void
    {
        if (self::$started) {
            throw new \LogicException('MarkdownResponse can only start once per request.');
        }
        if (headers_sent()) {
            throw new \LogicException('Start MarkdownResponse before sending output.');
        }
        if ($maxHtmlSize < 1) {
            throw new \InvalidArgumentException('The HTML size limit must be positive.');
        }
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if (!in_array($method, ['GET', 'HEAD'], true)) {
            return;
        }
        self::$started = true;
        self::varyAccept();
        $representation = ContentNegotiation::negotiate($_SERVER['HTTP_ACCEPT'] ?? '');
        if ($representation === 'text/html') {
            // Preserve Vary even when the application sets other Vary fields later.
            ob_start(static function (string $chunk): string {
                if (!headers_sent()) {
                    self::varyAccept();
                }
                return $chunk;
            }, 8192);
            return;
        }
        // Buffer in bounded chunks; never perform another HTTP request to this page.
        $buffer = '';
        $tooLarge = false;
        ob_start(static function (string $chunk, int $phase) use (&$buffer, &$tooLarge, $options, $maxHtmlSize, $method, $representation): string {
            if ($phase & PHP_OUTPUT_HANDLER_CLEAN) {
                $buffer = '';
                $tooLarge = false;
                return '';
            }
            if (!$tooLarge) {
                if (strlen($buffer) + strlen($chunk) > $maxHtmlSize) {
                    $tooLarge = true;
                    $buffer = '';
                } else {
                    $buffer .= $chunk;
                }
            }
            if (!($phase & PHP_OUTPUT_HANDLER_FINAL)) {
                return '';
            }
            if (!headers_sent()) {
                self::varyAccept();
            }
            $status = http_response_code() ?: 200;
            $headers = headers_list();
            $type = 'text/html';
            $encoded = false;
            $attachment = false;
            foreach ($headers as $header) {
                if (stripos($header, 'Content-Type:') === 0) {
                    $type = strtolower(trim(explode(';', substr($header, 13))[0]));
                }
                $encoded = $encoded || (stripos($header, 'Content-Encoding:') === 0 && strtolower(trim(substr($header, 17))) !== 'identity');
                $attachment = $attachment || stripos($header, 'Content-Disposition:') === 0;
            }
            // Do not transform redirects, errors, downloads, JSON or compressed data.
            if ($status !== 200 || $type !== 'text/html' || $encoded || $attachment) {
                if ($tooLarge) {
                    return self::failure(500, $method);
                }
                return $method === 'HEAD' || in_array($status, [204, 304], true) ? '' : $buffer;
            }
            if (headers_sent()) {
                error_log('MarkyDown: output was flushed before conversion completed.');
                return '';
            }
            self::varyAccept();
            if ($representation === null) {
                return self::failure(406, $method);
            }
            if ($tooLarge) {
                return self::failure(500, $method);
            }
            try {
                // Default to the full document only when explicitly configured by the site.
                $markdown = (new MarkyDown($maxHtmlSize))->convertHtml($buffer, $options + ['selector' => 'main']);
                if ($markdown === '') {
                    throw new \RuntimeException('Empty Markdown output.');
                }
            } catch (\Throwable $e) {
                error_log('MarkyDown response conversion failed: ' . get_class($e));
                return self::failure(500, $method);
            }
            self::clearRepresentationHeaders();
            header('Content-Type: text/markdown; charset=UTF-8');
            header('X-Content-Type-Options: nosniff');
            return $method === 'HEAD' ? '' : $markdown . "\n";
        }, 8192);
    }

    private static function varyAccept(): void
    {
        foreach (headers_list() as $header) {
            if (stripos($header, 'Vary:') === 0) {
                foreach (explode(',', substr($header, 5)) as $field) {
                    if (in_array(strtolower(trim($field)), ['accept', '*'], true)) {
                        return;
                    }
                }
            }
        }
        header('Vary: Accept', false);
    }

    private static function clearRepresentationHeaders(): void
    {
        foreach (['Content-Length', 'ETag', 'Last-Modified', 'Content-MD5', 'Digest', 'Content-Digest', 'Repr-Digest', 'Accept-Ranges'] as $name) {
            header_remove($name);
        }
    }

    private static function failure(int $status, string $method): string
    {
        self::clearRepresentationHeaders();
        header_remove('Content-Encoding');
        header_remove('Content-Disposition');
        header_remove('Content-Range');
        http_response_code($status);
        header('Content-Type: text/plain; charset=UTF-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        return $method === 'HEAD' ? '' : ($status === 406 ? "No acceptable representation available.\n" : "Markdown conversion failed.\n");
    }
}
