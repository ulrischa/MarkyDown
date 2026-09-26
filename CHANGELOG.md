# Changelog

## Unreleased

### Added
- Optional PHP page integration with HTML/Markdown content negotiation, quality weights, HEAD support and cache variation.
- Direct XPath selection, multiple CSS/XPath matches and exclusions without duplicate nested content.
- Explicit `convertHtml()` and `convertUrl()` APIs with actionable exceptions.
- Markdown table conversion, canonical base URL support, integration example and regression tests.

### Fixed
- Pasted HTML is converted as HTML rather than being escaped before parsing.
- Complex CSS selectors and selectors containing commas are parsed by the selector library.
- Literal HTML inside Markdown code blocks is no longer removed after conversion.
- Converter instances no longer retain a previous page's URL or HTML state.
- The form honors the chosen input method even when the other input still contains text.
- Session locks are released before remote requests; clipboard errors are handled explicitly.

### Security
- Validate and pin public DNS destinations for every redirect; reject internal and reserved IPv4/IPv6 ranges, URL credentials and nonstandard ports.
- Bound downloaded bodies and headers, redirects and request time; keep TLS verification enabled.
- Validate form input types, use secure session options and nonce-based script CSP, and avoid logging submitted URLs or HTML.
- Fail closed on HTTP conversion errors instead of broadening an explicit content selection.

### Changed
- Explicit selectors now include **all matches**, including the selected element itself, instead of only the first match's children.
- Headings outside the selected content are no longer prepended automatically. Include the desired heading in your selector if necessary.
- Article headers/footers inside the selection are preserved; exclude them explicitly when unwanted.
- The legacy `convert()` signature is retained and still returns an empty string on errors. The new APIs throw exceptions.
- Updated HTML Purifier 4.18.0 → 4.19.1, HTML-to-Markdown 5.1.1 → 5.1.2, HTML5 parser 2.9.0 → 2.11.0 and PHP 8.0 polyfill 1.31.0 → 1.37.0.
- Retained PHP 7.4 compatibility; explicitly declared required extensions and directly used parser/URI dependencies.
