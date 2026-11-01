import json
import re

try:
    from json_repair import repair_json
except ImportError:
    repair_json = None


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def extract_json(text: str):
    """Extrait le premier JSON valide d'une reponse LLM, en tolerant
    fences markdown, texte avant/apres, et JSON legerement casse."""
    if not text:
        raise ValueError("empty response")

    candidates = []

    for m in _FENCE_RE.finditer(text):
        candidates.append(m.group(1).strip())

    candidates.append(text.strip())

    for opener, closer in (("[", "]"), ("{", "}")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    candidates.append(text[start:i + 1])
                    break

    last_err = None
    for c in candidates:
        try:
            return json.loads(c)
        except json.JSONDecodeError as e:
            last_err = e
        if repair_json is not None:
            try:
                return json.loads(repair_json(c))
            except Exception as e:
                last_err = e

    raise ValueError(f"no JSON found: {last_err}")
