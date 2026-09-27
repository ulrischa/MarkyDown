<?php
namespace ulrischa;

use League\Uri\Http;
use League\Uri\UriResolver;

/** Bounded public-page fetcher */
class HtmlFetcher
{
    private $maxBytes;

    public function __construct(int $maxBytes = 1048576)
    {
        if ($maxBytes < 1) {
            throw new \InvalidArgumentException('The response size limit must be positive.');
        }
        $this->maxBytes = $maxBytes;
    }

    public function fetch(string $url): array
    {
        $deadline = microtime(true) + 30;
        for ($redirect = 0; $redirect <= 5; $redirect++) {
            $parts = $this->validateUrl($url);
            $host = trim($parts['host'], '[]');
            $addresses = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : $this->resolveHost($host);
            if (!$addresses) {
                throw new \RuntimeException('Could not resolve the page host.');
            }
            foreach ($addresses as $address) {
                if (!self::isPublicIp($address)) {
                    throw new \InvalidArgumentException('Only public Internet addresses are allowed.');
                }
            }
            $remaining = (int) (($deadline - microtime(true)) * 1000);
            if ($remaining <= 0) {
                throw new \RuntimeException('Page fetch timed out.');
            }
            $body = '';
            $location = null;
            $headerBytes = 0;
            $ch = curl_init($url);
            $port = $parts['port'] ?? ($parts['scheme'] === 'https' ? 443 : 80);
            $ip = strpos($addresses[0], ':') !== false ? '[' . $addresses[0] . ']' : $addresses[0];
            $settings = [
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
                CURLOPT_PROXY => '',
                CURLOPT_CONNECTTIMEOUT_MS => min(10000, $remaining),
                CURLOPT_TIMEOUT_MS => $remaining,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT => 'MarkyDown/2',
                CURLOPT_HTTPHEADER => ['Accept: text/html', 'Accept-Encoding: identity'],
                CURLOPT_WRITEFUNCTION => function ($handle, string $chunk) use (&$body): int {
                    if (strlen($body) + strlen($chunk) > $this->maxBytes) {
                        return 0;
                    }
                    $body .= $chunk;
                    return strlen($chunk);
                },
                CURLOPT_HEADERFUNCTION => function ($handle, string $line) use (&$location, &$headerBytes): int {
                    $headerBytes += strlen($line);
                    if ($headerBytes > 65536) {
                        return 0;
                    }
                    if (stripos($line, 'Location:') === 0) {
                        $location = trim(substr($line, 9));
                    }
                    return strlen($line);
                },
            ];
            if (!filter_var($host, FILTER_VALIDATE_IP)) {
                // Pin the validated address: a second DNS lookup would permit rebinding.
                $settings[CURLOPT_RESOLVE] = [$host . ':' . $port . ':' . $ip];
            }
            curl_setopt_array($ch, $settings);
            try {
                $success = curl_exec($ch);
                $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?: '';
            } finally {
                curl_close($ch);
            }
            if ($success === false) {
                throw new \RuntimeException('Could not fetch the page within the connection and size limits.');
            }
            if (in_array($status, [301, 302, 303, 307, 308], true) && $location !== null) {
                $url = (string) UriResolver::resolve(Http::createFromString($location), Http::createFromString($url));
                continue;
            }
            if ($status < 200 || $status >= 300 || strtolower(trim(explode(';', $type)[0])) !== 'text/html') {
                throw new \RuntimeException('The URL must return a successful HTML response.');
            }
            if (preg_match('/charset\s*=\s*["\']?([a-z0-9_-]+)/i', $type, $match)) {
                try {
                    $body = mb_convert_encoding($body, 'UTF-8', $match[1]);
                } catch (\Throwable $e) {
                    throw new \RuntimeException('Unsupported page character encoding.', 0, $e);
                }
            }
            if (strlen($body) > $this->maxBytes) {
                throw new \RuntimeException('Decoded HTML exceeds the size limit.');
            }
            return ['html' => $body, 'url' => $url];
        }
        throw new \RuntimeException('Too many page redirects.');
    }

    private function validateUrl(string $url): array
    {
        $parts = parse_url($url);
        if (strlen($url) > 2048 || preg_match('/[\x00-\x20\x7f\\\\]/', $url)
            || !filter_var($url, FILTER_VALIDATE_URL) || !$parts
            || !in_array($parts['scheme'] ?? '', ['http', 'https'], true)
            || isset($parts['user']) || isset($parts['pass'])
            || (isset($parts['port']) && !in_array($parts['port'], [80, 443], true))) {
            throw new \InvalidArgumentException('Use an HTTP(S) URL without credentials on port 80 or 443.');
        }
        return $parts;
    }

    private function resolveHost(string $host): array
    {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        $addresses = [];
        foreach ($records ?: [] as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;
            if ($address !== null) {
                $addresses[] = $address;
            }
        }
        return array_values(array_unique($addresses));
    }

    /** Conservative global-unicast policy, including IPv4-mapped IPv6 rejection. */
    public static function isPublicIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
        if (strpos($ip, ':') !== false) {
            $packed = inet_pton($ip);
            return (ord($packed[0]) & 0xe0) === 0x20
                && !self::inRange($ip, '2001::', 23)
                && !self::inRange($ip, '2001:db8::', 32)
                && !self::inRange($ip, '2002::', 16)
                && !self::inRange($ip, '3fff::', 20);
        }
        foreach ([['0.0.0.0', 8], ['100.64.0.0', 10], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]] as $range) {
            if (self::inRange($ip, $range[0], $range[1])) {
                return false;
            }
        }
        return true;
    }

    private static function inRange(string $ip, string $network, int $bits): bool
    {
        $address = inet_pton($ip);
        $base = inet_pton($network);
        $bytes = intdiv($bits, 8);
        $remaining = $bits % 8;
        return substr($address, 0, $bytes) === substr($base, 0, $bytes)
            && ($remaining === 0 || (ord($address[$bytes]) & (0xff << (8 - $remaining))) === ord($base[$bytes]));
    }
}
