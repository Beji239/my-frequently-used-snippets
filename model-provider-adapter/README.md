# Model provider adapter

Good for any app that should work with hosted and local language models alike. The conversation is always kept in the OpenAI chat format, and Anthropic's Messages API is translated at the edge, per request. Nothing else in the app needs to know which provider is active.

What it does:

- Reads the API style from the address, or takes it from a setting.
- Fixes up a bare Anthropic address to `/v1/messages`.
- Builds the right auth headers and the models list address.
- Turns a chat history with tool calls into an Anthropic request.
- Turns Anthropic's streamed events back into text, tool call and usage chunks.

The OpenAI style covers Ollama, LM Studio, vLLM, OpenRouter and most gateways.

## Files

- `provider_api.py`

## How I use it

`style = detect_style(url)`, then `normalise_url` and `auth_headers`. For Anthropic, send `to_anthropic_request(...)` and feed each stream event to an `AnthropicStream`. Standard library only.
