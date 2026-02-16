// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(windows && arm64)

package gohai // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/datadog/hostmetadata/internal/gohai"

import (
	"github.com/DataDog/datadog-agent/pkg/gohai/cpu"
	"github.com/DataDog/datadog-agent/pkg/gohai/filesystem"
	"github.com/DataDog/datadog-agent/pkg/gohai/memory"
	"github.com/DataDog/datadog-agent/pkg/gohai/network"
	"github.com/DataDog/datadog-agent/pkg/gohai/platform"
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

func convertMapOfStrings(m map[string]any) map[string]string {
	m2 := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			m2[k] = s
		}
	}
	return m2
}

func newGohai(logger *zap.Logger) *gohai.Gohai {
	res := new(gohai.Gohai)

	if p, warns, err := cpu.CollectInfo().AsJSON(); err != nil {
		logger.Debug("Failed to retrieve cpu metadata", zap.Error(err), zap.Strings("warns", warns))
	} else if cpu, ok := p.(map[string]any); !ok {
		logger.Warn("Internal error: Failed to cast cpu metadata to map[string]any", zap.Any("cpu", p))
	} else {
		if len(warns) > 0 {
			logger.Debug("Retrieving CPU metadata yielded warnings", zap.Strings("warns", warns))
		}
		res.CPU = convertMapOfStrings(cpu)
	}

	if info, err := filesystem.CollectInfo(); err != nil {
		logger.Debug("Failed to retrieve filesystem metadata", zap.Error(err))
	} else if p, warns, err := info.AsJSON(); err != nil {
		logger.Warn("Failed to convert filesystem metadata to JSON", zap.Error(err), zap.Strings("warns", warns))
	} else if fs, ok := p.([]any); !ok {
		logger.Warn("Internal error: Failed to cast filesystem metadata to []any", zap.Any("filesystem", p))
	} else {
		if len(warns) > 0 {
			logger.Debug("Converting filesystem metadata to JSON yielded warnings", zap.Strings("warns", warns))
		}
		res.FileSystem = fs
	}

	if p, warns, err := memory.CollectInfo().AsJSON(); err != nil {
		logger.Debug("Failed to retrieve memory metadata", zap.Error(err))
	} else if mem, ok := p.(map[string]any); !ok {
		logger.Warn("Internal error: Failed to cast memory metadata to map[string]any", zap.Any("memory", p))
	} else {
		if len(warns) > 0 {
			logger.Debug("Retrieving memory metadata yielded warnings", zap.Strings("warns", warns))
		}
		res.Memory = convertMapOfStrings(mem)
	}

	// in case of containerized environment, this would return pod id not node's ip
	if info, err := network.CollectInfo(); err != nil {
		logger.Debug("Failed to retrieve network metadata", zap.Error(err))
	} else if p, warns, err := info.AsJSON(); err != nil {
		logger.Warn("Failed to convert network metadata to JSON", zap.Error(err), zap.Strings("warnigns", warns))
	} else if net, ok := p.(map[string]any); !ok {
		logger.Warn("Internal error: Failed to cast network metadata to map[string]any", zap.Any("network", p))
	} else {
		if len(warns) > 0 {
			logger.Debug("Converting memory metadata to JSON yielded warnings", zap.Strings("warns", warns))
		}
		res.Network = net
	}

	if p, warns, err := platform.CollectInfo().AsJSON(); err != nil {
		logger.Debug("Failed to retrieve platform metadata", zap.Error(err), zap.Strings("warns", warns))
	} else if platform, ok := p.(map[string]any); !ok {
		logger.Warn("Internal error: Failed to cast platform metadata to map[string]any", zap.Any("platform", p))
	} else {
		if len(warns) > 0 {
			logger.Debug("Retrieving platform metadata yielded warnings", zap.Strings("warns", warns))
		}
		res.Platform = convertMapOfStrings(platform)
	}

	return res
}
