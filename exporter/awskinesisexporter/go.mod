module github.com/open-telemetry/opentelemetry-collector-contrib/exporter/awskinesisexporter

go 1.16

require (
	github.com/mattn/go-colorable v0.1.7 // indirect
	github.com/signalfx/opencensus-go-exporter-kinesis v0.6.3
	github.com/stretchr/testify v1.7.0
	go.opentelemetry.io/collector v0.29.1-0.20210701184715-6fe06276e8dc
	go.opentelemetry.io/collector/model v0.0.0-00010101000000-000000000000
	go.uber.org/zap v1.18.1
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
)

replace go.opentelemetry.io/collector/model => go.opentelemetry.io/collector/model v0.0.0-20210701184715-6fe06276e8dc
