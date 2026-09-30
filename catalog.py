"""Filter the gateway-wide catalog to chat candidates on the configured upstream."""
import re

_NON_CHAT = re.compile(r'(?:^|[/_:.-])(embed(?:ding)?s?|image|audio|tts|whisper|dall-e|realtime|moderation|rerank|video|transcribe)(?:$|[/_:.-])', re.I)
_SNAPSHOT = re.compile(r'-\d{4}-?\d{2}-?\d{2}$')


def chat_models(ids, selected):
    # /compat/models is a union of upstream catalogs, including duplicated prefixes and
    # batch-only/non-chat products. A configured OpenRouter route does not imply direct
    # OpenAI/Anthropic wholesale billing is enabled. Stay within that selected upstream.
    upstream = selected.partition('/')[0]
    prefix = upstream + '/'
    candidates = {
        value for value in ids if isinstance(value, str) and value.startswith(prefix)
        and not value.startswith(prefix + prefix) and ':batch' not in value
        and not _NON_CHAT.search(value)
    }
    candidates = {value for value in candidates
                  if not (_SNAPSHOT.search(value) and _SNAPSHOT.sub('', value) in candidates)}
    return [selected] + sorted(candidates - {selected})
