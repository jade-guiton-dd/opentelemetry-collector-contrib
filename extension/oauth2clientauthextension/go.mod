module github.com/open-telemetry/opentelemetry-collector-contrib/extension/oauth2clientauthextension

go 1.16

require (
	github.com/stretchr/testify v1.7.0
	go.opentelemetry.io/collector v0.29.1-0.20210630154722-7d0a0398174e
	go.uber.org/zap v1.18.1
	golang.org/x/oauth2 v0.0.0-20210615190721-d04028783cf1
	google.golang.org/grpc v1.39.0
)

replace go.opentelemetry.io/collector/model => go.opentelemetry.io/collector/model v0.0.0-20210630154722-7d0a0398174e
