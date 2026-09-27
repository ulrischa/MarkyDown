<?php
namespace ulrischa;

/** HTTP Accept selection */
class ContentNegotiation
{
    /** HTML wins ties and wildcard-only requests. Null means neither is acceptable. */
    public static function negotiate(string $accept): ?string
    {
        if (trim($accept) === '') {
            return 'text/html';
        }
        $ranges = [];
        foreach (explode(',', $accept) as $item) {
            $parts = array_map('trim', explode(';', strtolower($item)));
            $type = array_shift($parts);
            if (!in_array($type, ['text/html', 'text/markdown', 'text/*', '*/*'], true)) {
                continue;
            }
            $quality = 1.0;
            $supported = true;
            $specificity = 0;
            foreach ($parts as $parameter) {
                if (preg_match('/^q\s*=\s*(.*)$/', $parameter, $match)) {
                    $quality = preg_match('/^(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/', $match[1]) ? (float) $match[1] : 0.0;
                    break;
                }
                // Media-type parameters before q must match our representation.
                if ($parameter !== '' && !preg_match('/^charset\s*=\s*"?utf-8"?$/', $parameter)) {
                    $supported = false;
                    break;
                }
                if ($parameter !== '') {
                    $specificity = 1;
                }
            }
            if (!$supported) {
                continue;
            }
            if (!isset($ranges[$type]) || $specificity > $ranges[$type]['specificity']
                || ($specificity === $ranges[$type]['specificity'] && $quality > $ranges[$type]['quality'])) {
                $ranges[$type] = ['specificity' => $specificity, 'quality' => $quality];
            }
        }
        $html = $ranges['text/html']['quality'] ?? $ranges['text/*']['quality'] ?? $ranges['*/*']['quality'] ?? 0.0;
        $markdown = $ranges['text/markdown']['quality'] ?? $ranges['text/*']['quality'] ?? $ranges['*/*']['quality'] ?? 0.0;
        if ($html <= 0 && $markdown <= 0) {
            return null;
        }
        return $markdown > $html ? 'text/markdown' : 'text/html';
    }
}
