from providers import register_provider
from .provider import profile

register_provider(profile())
