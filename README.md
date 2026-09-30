# Hermes Cloudflare AI Gateway

A [Hermes](https://github.com/NousResearch/hermes-agent) plugin for using a **Cloudflare AI
Gateway** as your model provider — including gateways behind **Cloudflare Access**, where you
sign in as yourself instead of managing API keys.

- Works with a stock Hermes install; no extra dependencies.
- Access-protected gateways: one-click sign-in from Hermes Desktop, silent token renewal, and
  automatic sign-in when your session ends. No service tokens.
- Regular gateways: use a Cloudflare API token or a provider key, entered like any other key.

## Install

1. Copy this repository to `~/.hermes/plugins/cloudflare-ai-gateway/`.
2. Copy `desktop/plugin.js` to `~/.hermes/desktop-plugins/cloudflare-ai-gateway/plugin.js`
   (needed for Access sign-in).
3. Add to `~/.hermes/config.yaml`, with the `base_url` for your gateway (see below):

   ```yaml
   model:
     provider: cloudflare-ai-gateway
     default: openrouter/deepseek/deepseek-v4.1-flash

   providers:
     cloudflare-ai-gateway:
       base_url: https://ai.example.com/compat
       model: openrouter/deepseek/deepseek-v4.1-flash

   plugins:
     enabled:
       - cloudflare-ai-gateway
   ```

4. Restart Hermes.

## Gateway behind Cloudflare Access

Use your gateway's custom domain, e.g. `https://ai.example.com/compat`.

Click **Cloudflare: sign in** in the bottom-right of Hermes Desktop, sign in in your browser, and
start chatting. If you send a message while signed out, your browser opens the sign-in page and
the message waits; once you sign in it continues on its own. If you don't finish within about
two minutes, the message fails and you can press **Retry** after signing in. You can also sign
in or out from the command palette (⌘K / Ctrl+K).

Each Hermes profile (including each Desktop bot) has its own sign-in. A profile with its own
copy of the plugin (`~/.hermes/profiles/<name>/plugins/`) loads that copy, so update it too.

Your Access application must accept the user's token as a bearer token. Tokens renew silently
while your Access global session is valid, so session settings decide how often you sign in.

## Gateway without Access

Use the gateway's OpenAI-compatible endpoint:

```
https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/compat
```

Set `CLOUDFLARE_AI_GATEWAY_TOKEN` in **Settings → Providers → Keys** (or `~/.hermes/.env`):

- **Authenticated gateway with stored keys or unified billing:** a Cloudflare API token with
  *AI Gateway Run* permission.
- **Unauthenticated gateway:** your provider's API key.
- **Authenticated gateway, your own provider key:** the provider key, plus the gateway token as
  a header:

  ```yaml
  model:
    extra_headers:
      cf-aig-authorization: Bearer ${CF_AIG_TOKEN}
  ```

Cloudflare-hosted URLs use a token automatically. For a custom domain without Access, add
`auth: token` under `providers.cloudflare-ai-gateway`.

## Notes

- Only the `/compat` (OpenAI-compatible) endpoint is supported. Models are named
  `{provider}/{model}`, e.g. `openai/gpt-5.2`.
- The model picker lists the gateway's models for the upstream in your configured `model` (the
  part before the first `/`).

## Development

```sh
../hermes-agent/scripts/run_tests.sh "$PWD/tests" -- --import-mode=importlib
```

## License

[MIT](LICENSE)
