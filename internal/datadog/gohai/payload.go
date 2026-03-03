// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(windows && arm64)

package gohai // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/datadog/gohai"

import (
	"github.com/DataDog/datadog-agent/pkg/opentelemetry-mapping-go/inframetadata/gohai"
	"go.uber.org/zap"
)

// NewPayload builds a payload of every metadata collected with gohai except processes metadata.
// Parts of this are based on datadog-agent code
// https://github.com/DataDog/datadog-agent/blob/a09732f39f1936113f0fee6c451b29d7b167d1ce/pkg/gohai/gohai.go#L56
func NewPayload(logger *zap.Logger) gohai.Payload {
	payload := gohai.NewEmpty()
	payload.Gohai.Gohai = newGohai(logger)
	return payload
}
