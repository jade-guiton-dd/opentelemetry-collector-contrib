// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gohai // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/datadog/hostmetadata/gohai"

import (
	"github.com/DataDog/datadog-agent/pkg/opentelemetry-mapping-go/inframetadata/gohai"
	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/datadog/hostmetadata"
	"go.uber.org/zap"
)

type gohaiProvider struct{}

var GohaiProvider hostmetadata.GohaiProvider = gohaiProvider{}

func (gohaiProvider) NewPayload(logger *zap.Logger) gohai.Payload {
	return NewPayload(logger)
}

func (gohaiProvider) NewProcessesPayload(hostname string, logger *zap.Logger) *gohai.ProcessesPayload {
	return NewProcessesPayload(hostname, logger)
}
