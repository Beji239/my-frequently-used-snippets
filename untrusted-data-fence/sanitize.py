import re
import unicodedata

FENCE_OPEN  = "<<<UNTRUSTED_SENSOR_DATA>>>"
FENCE_CLOSE = "<<<END_UNTRUSTED_SENSOR_DATA>>>"

MAX_STRING_LEN = 8000

MAX_RESULT_LEN = 120000

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]")

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[@-Z\\-_]")

_BIDI_ZWSP = re.compile(
    "["
    "\u200b-\u200f"
    "\u202a-\u202e"
    "\u2060-\u2064"
    "\u2066-\u2069"
    "\ufeff"
    "]"
)

_VARIATION = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]")
_NEWLINE_LIKE = str.maketrans({"\r": "\n", "\u2028": "\n", "\u2029": "\n",
                               "\x85": "\n"})


def _strip_invisible(text: str) -> str:
    text = _VARIATION.sub("", text)
    if any(unicodedata.category(c) == "Cf" for c in text):
        text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return text


_FENCE_PATTERN = re.compile(
    r"<<<\s*/?\s*(?:END_)?UNTRUSTED_SENSOR_DATA\s*>>>",
    re.IGNORECASE,
)
_OPENERS = "<\u2039\u00ab\u2329\u27e8\u3008"
_CLOSERS = ">\u203a\u00bb\u232a\u27e9\u3009"
_LOOSE_FENCE = re.compile(
    rf"(?<![{_OPENERS}])[{_OPENERS}]{{2,}}(?:[^\w{_OPENERS}]|_)*"
    r"(?:END[\W_]*)?UNTRUSTED[\W_]*SENSOR[\W_]*DATA"
    rf"(?:[^\w{_CLOSERS}]|_)*[{_CLOSERS}]{{2,}}",
    re.IGNORECASE,
)

def scrub_string(value: str, max_len: int = MAX_STRING_LEN) -> str:
    if not isinstance(value, str):
        return value

    cleaned = _ANSI_ESCAPE.sub("", value)
    cleaned = cleaned.replace("\r\n", "\n").translate(_NEWLINE_LIKE)
    cleaned = _CONTROL_CHARS.sub("", cleaned)
    cleaned = _BIDI_ZWSP.sub("", cleaned)
    cleaned = _strip_invisible(cleaned)
    cleaned = _FENCE_PATTERN.sub("[fence-marker-removed]", cleaned)
    folded = unicodedata.normalize("NFKC", cleaned)
    if _LOOSE_FENCE.search(folded):
        cleaned = _LOOSE_FENCE.sub("[fence-marker-removed]", folded)

    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + f"...[truncated {len(cleaned) - max_len} chars]"

    return cleaned


def scrub(obj, _depth: int = 0):
    if _depth > 12:
        return "[max depth exceeded]"

    if isinstance(obj, str):
        return scrub_string(obj)
    if isinstance(obj, dict):
        return {
            scrub_string(str(k), max_len=200): scrub(v, _depth + 1)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [scrub(v, _depth + 1) for v in obj]
    return obj


def cap_result(payload: str, limit: int = None) -> str:
    limit = limit or MAX_RESULT_LEN
    if len(payload) > limit:
        dropped = len(payload) - limit
        payload = (
            payload[:limit] +
            f'\n\n[THIS RESULT WAS CUT AND IS INCOMPLETE. {dropped} of '
            f'{len(payload)} characters are missing from the END. The last '
            f'entry above is a fragment, this is no longer valid JSON, and '
            f'whatever came last in the list is NOT here at all. Do not read '
            f'it as the whole answer. Ask for less at a time, by name or by '
            f'pid, or with a smaller limit.]'
        )
    return payload


def fence(payload: str) -> str:
    return f"{FENCE_OPEN}\n{cap_result(payload)}\n{FENCE_CLOSE}"
