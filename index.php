<?php
require __DIR__ . '/vendor/autoload.php';

use ulrischa\MarkyDown;

// Set Security Headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: no-referrer");

// Initialize variables
$markdownOutput = '';
$errorMessage = '';

// Determine request method and parameters
$requestMethod = $_SERVER['REQUEST_METHOD'];
$urlInput = null;
$htmlInput = null;
$mainSelector = null;
$excludeSelectors = null;

// Handle POST request for URL or HTML input
if ($requestMethod === 'POST') {
    if (isset($_POST['url']) && !empty($_POST['url'])) {
        $urlInput = $_POST['url'];
        $mainSelector = $_POST['main_selector'] ?? null;
        $excludeSelectors = $_POST['exclude_selectors'] ?? null;
    } elseif (isset($_POST['html']) && !empty($_POST['html'])) {
        $htmlInput = $_POST['html'];
        $mainSelector = $_POST['main_selector'] ?? null;
        $excludeSelectors = $_POST['exclude_selectors'] ?? null;
    }
}

try {
    // Process conversion if URL or HTML is provided
    if (($urlInput || $htmlInput) && $requestMethod === 'POST') {
        // Ensure only one input method is used
        if ($urlInput && $htmlInput) {
            $errorMessage = 'Please provide either a URL or HTML content, not both.';
        } else {
            $converter = new MarkyDown();
            $markdownOutput = $converter->convert($urlInput, $htmlInput, $mainSelector, $excludeSelectors);

            if (empty($markdownOutput)) {
                $errorMessage = 'No content could be extracted or converted. Please check your input and selectors.';
            }
        }
    }
} catch (Exception $e) {
    error_log("Page Load Error: " . $e->getMessage());
    $errorMessage = 'An unexpected error occurred. Please try again later.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
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
        --spinner-color: #4A90E2;
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
        outline: none;
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
        outline: none;
    }

    summary::marker {
        color: var(--primary-color);
    }

    details div {
        margin-top: 10px;
        line-height: 1.6;
    }

    /* Loading Overlay Styles */
    .loading-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(255, 255, 255, 0.9);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
        display: none; /* Hidden by default */
    }

    .spinner {
        border: 8px solid #f3f3f3;
        border-top: 8px solid var(--spinner-color);
        border-radius: 50%;
        width: 60px;
        height: 60px;
        animation: spin 1s linear infinite;
    }
    
    .headimg {
        display: block;
        margin-left: auto;
        margin-right: auto;
        width: 50%;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
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

        .spinner {
            width: 50px;
            height: 50px;
            border-width: 6px;
        }
     
    }
</style>

</head>
<body>
<div class="container">
    <a href="index.php"><h1><img src="markydown.jpg" alt="MarkyDown - Scrape it to markdown" class="headimg" />
    </h1></a>
    <form method="post" action="" id="converterForm">
        <fieldset>
            <legend><strong>Choose Input Method:</strong></legend>
            <label>
                <input type="radio" name="input_type" value="url" <?php if (!$htmlInput) echo 'checked'; ?>> Provide URL
            </label>
            <label>
                <input type="radio" name="input_type" value="html" <?php if ($htmlInput) echo 'checked'; ?>> Paste HTML
            </label>
        </fieldset>

        <div id="urlInput">
            <label for="url">URL:</label>
            <input type="url" name="url" id="url" placeholder="https://example.com" pattern="https?://.+" title="Please enter a valid URL starting with http:// or https://" <?php if ($urlInput) echo 'value="' . htmlspecialchars($urlInput, ENT_QUOTES, 'UTF-8') . '"'; ?>>
        </div>

        <div id="htmlInput" style="display:none;">
            <label for="html">HTML Content:</label>
            <textarea name="html" id="html" rows="8" placeholder="Paste your HTML here"><?php echo isset($htmlInput) ? htmlspecialchars($htmlInput, ENT_QUOTES, 'UTF-8') : ''; ?></textarea>
        </div>

        <label for="main_selector">CSS Selector for Main Content (optional):</label>
        <input type="text" name="main_selector" id="main_selector" placeholder="e.g., main or .content or #article" pattern="^[a-zA-Z][a-zA-Z0-9\#\.\-\_\[\]=]+$" title="Please enter a valid CSS selector" <?php if (isset($mainSelector)) echo 'value="' . htmlspecialchars($mainSelector, ENT_QUOTES, 'UTF-8') . '"'; ?>>

        <label for="exclude_selectors">CSS Selectors to Exclude (optional, separated by commas):</label>
        <input type="text" name="exclude_selectors" id="exclude_selectors" placeholder="e.g., .ads, #sidebar" pattern="^[a-zA-Z0-9\#\.\-\_,\s\[\]=]+$" title="Please enter valid CSS exclusion selectors separated by commas" <?php if (isset($excludeSelectors)) echo 'value="' . htmlspecialchars($excludeSelectors, ENT_QUOTES, 'UTF-8') . '"'; ?>>

        <button type="submit">Convert</button>
    </form>

    <?php if (!empty($markdownOutput)): ?>
        <h2>Markdown Result:</h2>
        <div class="output" id="markdownOutput"><?php echo htmlspecialchars($markdownOutput, ENT_QUOTES, 'UTF-8'); ?></div>
        <div class="action-buttons">
            <button onclick="copyToClipboard()">Copy to Clipboard</button>
            <button onclick="downloadMarkdown()">Download as .md</button>
        </div>
    <?php elseif (!empty($errorMessage)): ?>
        <p class="error"><?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?></p>
    <?php endif; ?>

    <details>
        <summary>Help</summary>
        <div>
            <h2>How to Use</h2>
            <p>This tool converts HTML content from a specified URL or pasted HTML into Markdown. You can optionally specify CSS selectors to refine the content extraction.</p>
            
            <h3>Input Methods</h3>
            <ul>
                <li><strong>Provide URL:</strong> Enter the URL of the webpage you want to convert.</li>
                <li><strong>Paste HTML:</strong> Directly paste the HTML content you wish to convert.</li>
            </ul>
            
            <h3>Optional Selectors</h3>
            <ul>
                <li><strong>CSS Selector for Main Content:</strong> Define a CSS selector to specify the main content area you want to convert. Examples:
                    <ul>
                        <li><code>main</code> – Selects the &lt;main&gt; element.</li>
                        <li><code>.content</code> – Selects all elements with the class "content".</li>
                        <li><code>#article</code> – Selects the element with the ID "article".</li>
                    </ul>
                </li>
                <li><strong>CSS Selectors to Exclude:</strong> Provide a comma-separated list of CSS selectors to remove unwanted elements before conversion. Examples:
                    <ul>
                        <li><code>.ads</code> – Removes all elements with the class "ads".</li>
                        <li><code>#sidebar</code> – Removes the element with the ID "sidebar".</li>
                        <li><code>header, footer</code> – Removes &lt;header&gt; and &lt;footer&gt; elements.</li>
                    </ul>
                </li>
            </ul>
            
            <h3>Examples</h3>
            <ul>
                <li>If you just paste the url or html the main content will be extracted with the readability library</li>
                <li>To extract the main content, use the selector <code>main</code>.</li>
                <li>To extract the main content and remove all advertisement areas, use <code>main</code> as the main content selector and <code>.ads</code> as the exclusion selector.</li>
            </ul>
        </div>
    </details>

    <?php if (!empty($markdownOutput)): ?>
    <div class="loading-overlay" id="loadingOverlay">
        <div class="spinner"></div>
    </div>
    <script>
        document.getElementById('converterForm').addEventListener('submit', function() {
            document.getElementById('loadingOverlay').style.display = 'flex';
        });

        function copyToClipboard() {
            const markdownText = document.getElementById('markdownOutput').innerText;
            navigator.clipboard.writeText(markdownText).then(function() {
                alert('Markdown successfully copied to clipboard!');
            }, function(err) {
                alert('Error copying: ' + err);
            });
        }

        function downloadMarkdown() {
            const markdownText = document.getElementById('markdownOutput').innerText;
            const blob = new Blob([markdownText], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'result.md';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    </script>
    <?php endif; ?>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const inputTypeRadios = document.getElementsByName('input_type');
            const urlInputDiv = document.getElementById('urlInput');
            const htmlInputDiv = document.getElementById('htmlInput');
            const urlInput = document.getElementById('url');
            const htmlInput = document.getElementById('html');

            inputTypeRadios.forEach(function(radio) {
                radio.addEventListener('change', function() {
                    if (this.value === 'url') {
                        urlInputDiv.style.display = 'block';
                        htmlInputDiv.style.display = 'none';
                        urlInput.required = true;
                        htmlInput.required = false;
                    } else {
                        urlInputDiv.style.display = 'none';
                        htmlInputDiv.style.display = 'block';
                        urlInput.required = false;
                        htmlInput.required = true;
                    }
                });
            });

            // Initial check based on existing input
            const selectedInputType = document.querySelector('input[name="input_type"]:checked').value;
            if (selectedInputType === 'url') {
                urlInputDiv.style.display = 'block';
                htmlInputDiv.style.display = 'none';
                urlInput.required = true;
                htmlInput.required = false;
            } else {
                urlInputDiv.style.display = 'none';
                htmlInputDiv.style.display = 'block';
                urlInput.required = false;
                htmlInput.required = true;
            }

            // Form validation
            document.getElementById('converterForm').addEventListener('submit', function(e) {
                const inputType = document.querySelector('input[name="input_type"]:checked').value;
                if (inputType === 'url') {
                    const url = urlInput.value.trim();
                    if (!url) {
                        alert('Please enter a valid URL.');
                        e.preventDefault();
                    }
                } else {
                    const html = htmlInput.value.trim();
                    if (!html) {
                        alert('Please paste the HTML content.');
                        e.preventDefault();
                    }
                }
            });
        });
    </script>

</div>
</body>
</html>
