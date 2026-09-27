<?php
// Web interface maintained by Uli Schäffler.
require __DIR__ . '/vendor/autoload.php';

use ulrischa\MarkyDown;

if (!session_start([
    'use_strict_mode' => 1,
    'use_only_cookies' => 1,
    'use_trans_sid' => 0,
    'cookie_httponly' => true,
    'cookie_secure' => filter_var(ini_get('session.cookie_secure'), FILTER_VALIDATE_BOOLEAN)
        || (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'cookie_samesite' => strcasecmp((string) ini_get('session.cookie_samesite'), 'Strict') === 0 ? 'Strict' : 'Lax',
])) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('Session storage is unavailable. Please check the server configuration.');
}
header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
$script_nonce = base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'nonce-$script_nonce'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
header('Cache-Control: no-store');

function post_string(string $name): string
{
    return isset($_POST[$name]) && is_string($_POST[$name]) ? trim($_POST[$name]) : '';
}

/** A deliberately small public-form subset; the library still accepts full CSS. */
function is_simple_css_selector(string $selector): bool
{
    if ($selector === '') {
        return true;
    }
    $parts = explode(',', $selector);
    if (strlen($selector) > 256 || count($parts) > 8) {
        return false;
    }
    foreach ($parts as $part) {
        $part = trim($part);
        if ($part === '' || !preg_match('/^(?:[a-zA-Z_][a-zA-Z0-9_-]*|\*)?(?:[.#][a-zA-Z_][a-zA-Z0-9_-]*)*$/D', $part)) {
            return false;
        }
    }
    return true;
}

$csrf_token = $_SESSION['csrf_token'] ?? bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;
$url_input = post_string('url');
$html_input = post_string('html');
$main_selector = post_string('main_selector');
$exclude_selectors = post_string('exclude_selectors');
$selector_type = post_string('selector_type') ?: 'css';
// Full selector languages can exhaust CPU; only enable them for trusted UI users.
$allow_advanced_selectors = getenv('MARKYDOWN_ALLOW_ADVANCED_SELECTORS') === '1';
$input_type = post_string('input_type') ?: 'url';
$form_handler = (object) ['markdownOutput' => '', 'errorMessage' => ''];
$should_convert = false;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    if (!hash_equals($csrf_token, post_string('csrf_token'))) {
        $form_handler->errorMessage = 'Invalid or expired form token. Please try again.';
    } elseif (time() - ($_SESSION['last_submission_time'] ?? 0) < 5) {
        $form_handler->errorMessage = 'Please wait five seconds between conversions.';
    } elseif ($selector_type === 'xpath' && !$allow_advanced_selectors) {
        $form_handler->errorMessage = 'XPath is disabled in this web interface. Use a CSS selector.';
    } elseif (!$allow_advanced_selectors && (!is_simple_css_selector($main_selector) || !is_simple_css_selector($exclude_selectors))) {
        $form_handler->errorMessage = 'Use simple element, class or ID selectors, optionally separated by commas. Advanced selectors are disabled in this web interface.';
    } elseif (!in_array($selector_type, ['css', 'xpath'], true)) {
        $form_handler->errorMessage = 'Choose CSS or XPath.';
    } else {
        $_SESSION['last_submission_time'] = time();
        $should_convert = true;
    }
}
// Release the session lock before fetching a remote page.
session_write_close();
if ($should_convert) {
    try {
        $converter = new MarkyDown();
        $options = ['selector' => $main_selector, 'selector_type' => $selector_type, 'exclude' => $exclude_selectors];
        if ($input_type === 'url') {
            $form_handler->markdownOutput = $converter->convertUrl($url_input, $options);
            $html_input = '';
        } elseif ($input_type === 'html') {
            $form_handler->markdownOutput = $converter->convertHtml($html_input, $options);
            $url_input = '';
        } else {
            throw new InvalidArgumentException('Invalid input method.');
        }
        if ($form_handler->markdownOutput === '') {
            $form_handler->errorMessage = 'No content could be converted. Try an explicit content selector.';
        }
    } catch (Throwable $e) {
        error_log('MarkyDown form conversion failed: ' . get_class($e));
        $form_handler->errorMessage = 'Conversion failed. Check the input, selector syntax and matching elements. URLs must return public HTML on port 80 or 443; HTML must be UTF-8 and at most 1 MiB.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <title>MarkyDown - HTML to Markdown Converter</title>
    <style>
        /* CSS Variables for Easy Theme Customization */
        :root {
            --primary-color: #4A90E2;
            --secondary-color: #20B3A2;
            --secondary-hover-color: #38c0b4;
            --background-color: #D8D4D3;
            --form-background: #ffffff;
            --text-color: #333333;
            --error-color: #e74c3c;
            --border-color: #dcdcdc;
            --button-hover-color: #357ABD;
        }

        /* Apply box-sizing globally to include padding and borders within the element's total width */
        *, *::before, *::after {
            box-sizing: border-box;
        }

        /* Global Styles */
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--background-color);
            color: var(--text-color);
            margin: 0;
            padding: 0;
        }

        .container {
            max-width: 900px;
            margin: 25px auto;
            padding: 20px;
            overflow: hidden; 
        }

        h1 {
            text-align: center;
            color: var(--primary-color);
            margin-bottom: 10px;
        }

        p {
            text-align: center;
            color: var(--text-color);
            margin-bottom: 30px;
            font-size: 1.1em;
        }

        /* Form Styles */
        form {
            background: var(--form-background);
            padding: 25px 30px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        fieldset {
            border: none;
            margin-bottom: 20px;
        }

        legend {
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
            color: var(--primary-color);
        }

        label {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
            font-weight: 500;
        }

        input[type="radio"] {
            margin-right: 10px;
            accent-color: var(--primary-color);
            transform: scale(1.2);
        }

        /* Ensure input elements fit within their containers */
        select,
        input[type="url"],
        input[type="text"],
        textarea {
            width: 100%;
            padding: 12px 15px;
            margin-top: 5px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 1em;
            transition: border-color 0.3s ease;
            /* box-sizing is already handled globally */
        }

        input[type="url"]:focus,
        input[type="text"]:focus,
        textarea:focus {
            border-color: var(--primary-color);
            outline-offset: 3px;
            box-shadow: 0 0 5px rgba(74, 144, 226, 0.5);
        }

        button[type="submit"] {
            background-color: var(--primary-color);
            color: #ffffff;
            padding: 12px 25px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            transition: background-color 0.3s ease, transform 0.2s ease;
        }

        button[type="submit"]:hover {
            background-color: var(--button-hover-color);
            transform: translateY(-2px);
        }

        button[type="submit"]:active {
            transform: translateY(0);
        }

        /* Output Styles */
        .output {
            background: var(--form-background);
            padding: 20px 25px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            font-family: 'Courier New', Courier, monospace;
            font-size: 1em;
            white-space: pre-wrap;
            word-wrap: break-word;
            margin-bottom: 20px;
        }

        /* Error Message Styles */
        .error {
            background-color: #fdecea;
            color: var(--error-color);
            border: 1px solid var(--error-color);
            padding: 15px 20px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-weight: 500;
        }

        /* Action Buttons Styles */
        .action-buttons {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
        }

        .action-buttons button {
            flex: 1;
            padding: 12px 0;
            background-color: var(--secondary-color);
            color: #ffffff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            transition: background-color 0.3s ease, transform 0.2s ease;
        }

        .action-buttons button:hover {
            background-color: var(--secondary-hover-color);
            transform: translateY(-2px);
        }

        .action-buttons button:active {
            transform: translateY(0);
        }

        /* Help Section Styles */
        details {
            background: #ffffff;
            padding: 15px 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
        }

        summary {
            font-weight: bold;
            font-size: 1.1em;
            cursor: pointer;
            color: var(--primary-color);
            outline-offset: 3px;
        }

        summary::marker {
            color: var(--primary-color);
        }

        details div {
            margin-top: 10px;
            line-height: 1.6;
        }

        .headimg {
            display: block;
            margin-left: auto;
            margin-right: auto;
            width: 50%;
        }



        /* Responsive Design */
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }

            form {
                padding: 20px;
            }

            button[type="submit"],
            .action-buttons button {
                font-size: 0.9em;
                padding: 10px 0;
            }

            .output {
                font-size: 0.95em;
            }

            summary {
                font-size: 1em;
            }
        }

        @media (max-width: 480px) {
            h1 {
                font-size: 1.8em;
            }

            p {
                font-size: 1em;
            }

            summary {
                font-size: 0.95em;
            }


         
        }
    </style>

</head>
<body>
<a style="position:absolute;top:12px;right:12px;" href="https://github.com/ulrischa/MarkyDown">GitHub</a>
<div class="container">
    <a href="index.php"><h1><img src="markydown.jpg" alt="MarkyDown - Scrape it to markdown" class="headimg" />
    </h1></a>
    <form method="post" action="" id="converterForm">
        <!-- Include CSRF Token as a hidden field -->
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">

        <fieldset>
            <legend><strong>Choose Input Method:</strong></legend>
            <label>
                <input type="radio" name="input_type" value="url" <?php if ($input_type !== 'html') echo 'checked'; ?>> Provide URL
            </label>
            <label>
                <input type="radio" name="input_type" value="html" <?php if ($input_type === 'html') echo 'checked'; ?>> Paste HTML
            </label>
        </fieldset>

        <div id="urlInput">
            <label for="url">URL:</label>
            <input type="url" name="url" id="url" placeholder="https://example.com" pattern="https?://.+" title="Please enter a valid URL starting with http:// or https://" <?php if ($url_input) echo 'value="' . htmlspecialchars($url_input, ENT_QUOTES, 'UTF-8') . '"'; ?>>
        </div>

        <div id="htmlInput">
            <label for="html">HTML Content:</label>
            <textarea name="html" id="html" rows="8" placeholder="Paste your HTML here"><?php echo isset($html_input) ? htmlspecialchars($html_input, ENT_QUOTES, 'UTF-8') : ''; ?></textarea>
        </div>

        <?php if ($allow_advanced_selectors): ?>
        <label for="selector_type">Selector type:</label>
        <select id="selector_type" name="selector_type"><option value="css">CSS</option><option value="xpath" <?php if ($selector_type === 'xpath') echo 'selected'; ?>>XPath</option></select>
        <?php else: ?>
        <input type="hidden" name="selector_type" value="css">
        <?php endif; ?>
        <?php if (!$allow_advanced_selectors): ?>
        <p>Use simple selectors such as <code>main</code>, <code>.content</code>, <code>#article</code> or <code>article.story</code>. Comma-separated lists are supported.</p>
        <?php endif; ?>
        <label for="main_selector">Content Selector (optional):</label>
        <input type="text" name="main_selector" id="main_selector" placeholder="e.g., main or .content or #article" maxlength="4096" title="Enter a CSS selector or XPath expression" <?php if (isset($main_selector)) echo 'value="' . htmlspecialchars($main_selector, ENT_QUOTES, 'UTF-8') . '"'; ?>>

        <label for="exclude_selectors">Exclusion Selector (optional; CSS list or XPath union):</label>
        <input type="text" name="exclude_selectors" id="exclude_selectors" placeholder="e.g., .ads, #sidebar" maxlength="4096" title="Enter a CSS list or XPath union" <?php if (isset($exclude_selectors)) echo 'value="' . htmlspecialchars($exclude_selectors, ENT_QUOTES, 'UTF-8') . '"'; ?>>

        <button type="submit">Convert</button>
    </form>

    <?php if (!empty($form_handler->markdownOutput)): ?>
        <h2>Markdown Result:</h2>
        <div class="output" id="markdownOutput"><?php echo htmlspecialchars($form_handler->markdownOutput, ENT_QUOTES, 'UTF-8'); ?></div>
        <div class="action-buttons">
            <button type="button" id="copyMarkdown">Copy to Clipboard</button>
            <button type="button" id="downloadMarkdown">Download as .md</button>
        </div>
    <?php elseif (!empty($form_handler->errorMessage)): ?>
        <p class="error" role="alert"><?php echo htmlspecialchars($form_handler->errorMessage, ENT_QUOTES, 'UTF-8'); ?></p>
    <?php endif; ?>

    <details>
        <summary>Help</summary>
        <div>
            <h2>How to Use</h2>
            <p>This tool converts HTML main content from a specified URL or pasted HTML into Markdown. Without a content selector, Readability attempts to detect the main article. The result is the clean content and not cluttered. You can optionally specify CSS or XPath selectors to refine the content extraction. Then the result is as you defined it.</p>
            
            <h3>Input Methods</h3>
            <ul>
                <li><strong>Provide URL:</strong> Enter the URL of the webpage you want to convert.</li>
                <li><strong>Paste HTML:</strong> Directly paste the HTML content you wish to convert.</li>
            </ul>
            
            <h3>Optional Selectors</h3><p>XPath example: <code>//main</code>. All matching elements are included once. Exclusions use the same selector type. Use a CSS selector list or an XPath union (<code>//nav | //aside</code>) to exclude multiple areas.</p>
            <ul>
                <li><strong>Content Selector:</strong> Define a CSS selector to specify the main content area you want to convert. Examples:
                    <ul>
                        <li><code>main</code> Selects the &lt;main&gt; element.</li>
                        <li><code>.content</code> Selects all elements with the class "content".</li>
                        <li><code>#article</code> Selects the element with the ID "article".</li>
                    </ul>
                </li>
                <li><strong>CSS Selectors to Exclude:</strong> Provide a comma-separated list of CSS selectors to remove unwanted elements before conversion. Examples:
                    <ul>
                        <li><code>.ads</code> Removes all elements with the class "ads".</li>
                        <li><code>#sidebar</code> Removes the element with the ID "sidebar".</li>
                        <li><code>header, footer</code> Removes &lt;header&gt; and &lt;footer&gt; elements.</li>
                    </ul>
                </li>
            </ul>
                    </div>
    </details>

    <?php if (!empty($form_handler->markdownOutput)): ?>

    <script nonce="<?php echo htmlspecialchars($script_nonce, ENT_QUOTES, 'UTF-8'); ?>">
        function copyToClipboard() {
            const markdownText = document.getElementById('markdownOutput').textContent;
            (navigator.clipboard ? navigator.clipboard.writeText(markdownText) : Promise.reject(new Error('Clipboard requires HTTPS. Select and copy the text manually.'))).then(function() {
                alert('Markdown successfully copied to clipboard!');
            }, function(err) {
                alert('Error copying: ' + err);
            });
        }

        function downloadMarkdown() {
            const markdownText = document.getElementById('markdownOutput').textContent;
            const blob = new Blob([markdownText], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'result.md';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        }
        document.getElementById('copyMarkdown').addEventListener('click', copyToClipboard);
        document.getElementById('downloadMarkdown').addEventListener('click', downloadMarkdown);
    </script>
    <?php endif; ?>

    <script nonce="<?php echo htmlspecialchars($script_nonce, ENT_QUOTES, 'UTF-8'); ?>">
        document.addEventListener('DOMContentLoaded', function() {
            const inputTypeRadios = document.getElementsByName('input_type');
            const urlInputDiv = document.getElementById('urlInput');
            const htmlInputDiv = document.getElementById('htmlInput');
            const urlInput = document.getElementById('url');
            const htmlInput = document.getElementById('html');

            function updateInputMode() {
                const useUrl = document.querySelector('input[name="input_type"]:checked').value === 'url';
                urlInputDiv.hidden = !useUrl;
                htmlInputDiv.hidden = useUrl;
                urlInput.disabled = !useUrl;
                htmlInput.disabled = useUrl;
                urlInput.required = useUrl;
                htmlInput.required = !useUrl;
            }
            inputTypeRadios.forEach(radio => radio.addEventListener('change', updateInputMode));
            updateInputMode();
        });
    </script>

</div>
</body>
</html>
