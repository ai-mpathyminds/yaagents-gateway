# yaagents-gateway

> Part of the [YAAgents](https://github.com/ai-mpathyminds/yaagents) Agentic REST Profile suite.

The YAAgents Gateway is a lightweight, plugin-driven HTTP reverse proxy that enforces the [YAAgents Agentic REST Profile v0.3](https://github.com/ai-mpathyminds/yaagents/tree/main/spec) for every upstream service it fronts. It injects `X-Correlation-ID`, `X-Request-ID`, `X-Tenant-ID`, and `X-Actor-Principal` headers; validates bearer tokens; and routes requests to backend services via declarative YAML configuration.

## Install

```bash
go install github.com/ai-mpathyminds/yaagents-gateway/cmd/gateway@v0.3.0
```

Or pull the Docker image:

```bash
docker pull ghcr.io/ai-mpathyminds/yaagents-gateway:0.3.0
```

## Quick start

```yaml
# gateway-routes.yaml
routes:
  - path: /campaigns/{id}/optimizations
    upstream: http://localhost:8121
    methods: [POST]
```

```bash
./gateway --routes gateway-routes.yaml --plugins gateway-plugins.yaml
```

See [`examples/campaign-api-go/`](https://github.com/ai-mpathyminds/yaagents/tree/main/examples/campaign-api-go) for a full working example.

## Documentation

Full docs, spec, and SDK quickstarts: https://github.com/ai-mpathyminds/yaagents/tree/main/docs

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [main contributing guide](https://github.com/ai-mpathyminds/yaagents/blob/main/CONTRIBUTING.md).
