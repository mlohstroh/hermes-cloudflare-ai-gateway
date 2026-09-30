# Hermes Cloudflare AI Gateway

A [Hermes](https://github.com/NousResearch/hermes-agent) plugin for using a **Cloudflare AI
Gateway behind Cloudflare Access**, signed in as yourself — no API keys, no service tokens.

- Works with a stock Hermes install; no extra dependencies.
- Sign in from Hermes Desktop with one click. Your browser handles the Cloudflare login.
- Access tokens renew in the background; if your session ends, sign-in reopens automatically.

## Install

1. Copy this repository to `~/.hermes/plugins/cloudflare-ai-gateway/`.
2. Copy `desktop/plugin.js` to `~/.hermes/desktop-plugins/cloudflare-ai-gateway/plugin.js`.
3. Add to `~/.hermes/config.yaml`:

   ```yaml
   model:
     provider: cloudflare-ai-gateway
     default: openrouter/deepseek/deepseek-v4.1-flash

   providers:
     cloudflare-ai-gateway:
       base_url: https://ai.example.com/compat   # your gateway's OpenAI-compatible endpoint
       model: openrouter/deepseek/deepseek-v4.1-flash

   plugins:
     enabled:
       - cloudflare-ai-gateway
   ```

4. Restart Hermes.

## Use

Click **Cloudflare: sign in** in the bottom-right of Hermes Desktop, sign in in your browser, and
start chatting. The model picker shows the models your gateway offers.

If a message fails because you're signed out, your browser opens the sign-in page — sign in,
then press **Retry**. You can also sign in or out from the command palette (⌘K / Ctrl+K).

## Notes

- Your gateway's domain must be protected by a Cloudflare Access application that accepts the
  user's token as a bearer token.
- How often you sign in depends on your Access session settings: tokens renew silently while
  your Access global session is still valid.
- Only the `/compat` (OpenAI-compatible) endpoint is supported.

## Development

```sh
../hermes-agent/scripts/run_tests.sh "$PWD/tests" -- --import-mode=importlib
```

## License

[MIT](LICENSE)
