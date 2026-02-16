// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gohai // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/datadog/hostmetadata/internal/gohai"

import (
	"github.com/DataDog/datadog-agent/pkg/gohai/processes"
	"github.com/DataDog/datadog-agent/pkg/opentelemetry-mapping-go/inframetadata/gohai"
	"go.uber.org/zap"
)

// NewProcessesPayload builds a payload of processes metadata collected from gohai.
func NewProcessesPayload(hostname string, logger *zap.Logger) *gohai.ProcessesPayload {
	// Get processes metadata from gohai
	info, err := processes.CollectInfo()
	if err != nil {
		logger.Warn("Failed to retrieve processes metadata", zap.Error(err))
		return nil
	}

	proc, warnings, err := info.AsJSON()
	if err != nil {
		logger.Warn("Failed to convert process metadata to JSON", zap.Error(err), zap.Strings("warnings", warnings))
		return nil
	}
	if len(warnings) > 0 {
		logger.Debug("Warnings while converting process metadata to JSON", zap.Strings("warnings", warnings))
	}

	processesPayload := map[string]any{
		"snaps": []any{proc},
	}
	return &gohai.ProcessesPayload{
		Processes: processesPayload,
		Meta: map[string]string{
			"host": hostname,
		},
	}
}
