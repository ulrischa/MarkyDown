<?php
namespace ulrischa;

use Masterminds\HTML5\Parser\DOMTreeBuilder;
use Masterminds\HTML5\Parser\Scanner;
use Masterminds\HTML5\Parser\Tokenizer;

/** Bound work while building untrusted HTML, not after it. Maintainer: Uli Schäffler. */
final class HtmlParser
{
    public static function parse(string $html): \DOMDocument
    {
        $builder = new class(false, ['disable_html_ns' => true]) extends DOMTreeBuilder {
            private int $elementCount = 0;

            public function startTag($name, $attributes = [], $selfClosing = false)
            {
                if (++$this->elementCount > 10000) {
                    throw new \InvalidArgumentException('HTML exceeds the 10,000 opening-tag limit.');
                }
                $depth = 0;
                for ($node = $this->current; $node !== null; $node = $node->parentNode) {
                    if (++$depth > 128) {
                        throw new \InvalidArgumentException('HTML exceeds the nesting limit of 128 levels.');
                    }
                }
                return parent::startTag($name, $attributes, $selfClosing);
            }
        };
        $parser = new Tokenizer(new Scanner($html, 'UTF-8'), $builder, Tokenizer::CONFORMANT_HTML);
        $parser->parse();
        return $builder->document();
    }
}
