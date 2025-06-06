# Exceptions Connector

<!-- status autogenerated section -->
| Status        |           |
| ------------- |-----------|
| Distributions | [contrib], [k8s] |
| Issues        | [![Open issues](https://img.shields.io/github/issues-search/open-telemetry/opentelemetry-collector-contrib?query=is%3Aissue%20is%3Aopen%20label%3Aconnector%2Fexceptions%20&label=open&color=orange&logo=opentelemetry)](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues?q=is%3Aopen+is%3Aissue+label%3Aconnector%2Fexceptions) [![Closed issues](https://img.shields.io/github/issues-search/open-telemetry/opentelemetry-collector-contrib?query=is%3Aissue%20is%3Aclosed%20label%3Aconnector%2Fexceptions%20&label=closed&color=blue&logo=opentelemetry)](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues?q=is%3Aclosed+is%3Aissue+label%3Aconnector%2Fexceptions) |
| Code coverage | [![codecov](https://codecov.io/github/open-telemetry/opentelemetry-collector-contrib/graph/main/badge.svg?component=connector_exceptions)](https://app.codecov.io/gh/open-telemetry/opentelemetry-collector-contrib/tree/main/?components%5B0%5D=connector_exceptions&displayType=list) |
| [Code Owners](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/CONTRIBUTING.md#becoming-a-code-owner)    | [@marctc](https://www.github.com/marctc) |

[alpha]: https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#alpha
[contrib]: https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol-contrib
[k8s]: https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol-k8s

## Supported Pipeline Types

| [Exporter Pipeline Type] | [Receiver Pipeline Type] | [Stability Level] |
| ------------------------ | ------------------------ | ----------------- |
| traces | metrics | [alpha] |
| traces | logs | [alpha] |

[Exporter Pipeline Type]: https://github.com/open-telemetry/opentelemetry-collector/blob/main/connector/README.md#exporter-pipeline-type
[Receiver Pipeline Type]: https://github.com/open-telemetry/opentelemetry-collector/blob/main/connector/README.md#receiver-pipeline-type
[Stability Level]: https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#stability-levels
<!-- end autogenerated section -->

## Overview

Generate metrics and logs from recorded [application exceptions](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/exceptions/exceptions-spans.md/) associated with spans.

Each **metric** and **log** will have _at least_ the following dimensions:
- Service name
- Span name
- Span kind
- Status code

With the provided default config, each **metric** and **log** will also have the following dimensions:
- Exception message
- Exception type

Each log will additionally have the following attributes:
- Exception stacktrace
- Span attributes. If you want to filter out some attributes (like only copying HTTP attributes starting with `http.`) use the [transform processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/transformprocessor/).

## Configurations

If you are not already familiar with connectors, you may find it helpful to first visit the [Connectors README].

The following settings can be optionally configured:
- `dimensions`: the list of dimensions to add together with the default dimensions defined above.
  
  Each additional dimension is defined with a `name` which is looked up in the span's collection of attributes or resource attributes.

  The provided default config includes `exception.type` and `exception.message` as additional dimensions.

- `exemplars`:  Use to configure how to attach exemplars to metrics.
  - `enabled` (default: `false`): enabling will add spans as Exemplars.

## Examples

The following is a simple example usage of the `exceptions` connector.

```yaml
receivers:
  nop:

exporters:
  nop:

connectors:
  exceptions:

service:
  pipelines:
    traces:
      receivers: [nop]
      exporters: [exceptions]
    metrics:
      receivers: [exceptions]
      exporters: [nop]
    logs:
      receivers: [exceptions]
      exporters: [nop]      
```

The following is a more complex example usage of the `exceptions` connector using Prometheus and Loki as exporters.

```yaml
receivers:
  otlp:
    protocols:
      grpc:
      http:

exporters:
  prometheusremotewrite:
    endpoint: http://prometheus:9090/api/v1/write
  loki:
    endpoint: http://loki:3100/loki/api/v1/push

connectors:
  exceptions:

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [exceptions]
    metrics:
      receivers: [exceptions]
      exporters: [prometheusremotewrite]
    logs:
      receivers: [exceptions]
      exporters: [loki]
```

The full list of settings exposed for this connector are documented in [exceptionsconnector/config.go](../../connector/exceptionsconnector/config.go).
### More Examples

For more example configuration covering various other use cases, please visit the [testdata directory](../../connector/exceptionsconnector/testdata).

[Connectors README]:https://github.com/open-telemetry/opentelemetry-collector/blob/main/connector/README.md