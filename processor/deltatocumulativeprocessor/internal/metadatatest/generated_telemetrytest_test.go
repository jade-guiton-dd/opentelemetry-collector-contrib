// Code generated by mdatagen. DO NOT EDIT.

package metadatatest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/deltatocumulativeprocessor/internal/metadata"
)

func TestSetupTelemetry(t *testing.T) {
	testTel := SetupTelemetry()
	tb, err := metadata.NewTelemetryBuilder(testTel.NewTelemetrySettings())
	require.NoError(t, err)
	defer tb.Shutdown()
	require.NoError(t, tb.RegisterDeltatocumulativeStreamsTrackedLinearCallback(func(_ context.Context, observer metric.Int64Observer) error {
		observer.Observe(1)
		return nil
	}))
	tb.DeltatocumulativeDatapointsDropped.Add(context.Background(), 1)
	tb.DeltatocumulativeDatapointsLinear.Add(context.Background(), 1)
	tb.DeltatocumulativeDatapointsProcessed.Add(context.Background(), 1)
	tb.DeltatocumulativeGapsLength.Add(context.Background(), 1)
	tb.DeltatocumulativeStreamsEvicted.Add(context.Background(), 1)
	tb.DeltatocumulativeStreamsLimit.Record(context.Background(), 1)
	tb.DeltatocumulativeStreamsMaxStale.Record(context.Background(), 1)
	tb.DeltatocumulativeStreamsTracked.Add(context.Background(), 1)

	testTel.AssertMetrics(t, []metricdata.Metrics{
		{
			Name:        "otelcol_deltatocumulative.datapoints.dropped",
			Description: "number of datapoints dropped due to given 'reason'",
			Unit:        "{datapoint}",
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: true,
				DataPoints: []metricdata.DataPoint[int64]{
					{},
				},
			},
		},
		{
			Name:        "otelcol_deltatocumulative.datapoints.linear",
			Description: "total number of datapoints processed. may have 'error' attribute, if processing failed",
			Unit:        "{datapoint}",
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: true,
				DataPoints: []metricdata.DataPoint[int64]{
					{},
				},
			},
		},
		{
			Name:        "otelcol_deltatocumulative.datapoints.processed",
			Description: "number of datapoints processed",
			Unit:        "{datapoint}",
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: true,
				DataPoints: []metricdata.DataPoint[int64]{
					{},
				},
			},
		},
		{
			Name:        "otelcol_deltatocumulative.gaps.length",
			Description: "total duration where data was expected but not received",
			Unit:        "s",
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: true,
				DataPoints: []metricdata.DataPoint[int64]{
					{},
				},
			},
		},
		{
			Name:        "otelcol_deltatocumulative.streams.evicted",
			Description: "number of streams evicted",
			Unit:        "{stream}",
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: true,
				DataPoints: []metricdata.DataPoint[int64]{
					{},
				},
			},
		},
		{
			Name:        "otelcol_deltatocumulative.streams.limit",
			Description: "upper limit of tracked streams",
			Unit:        "{stream}",
			Data: metricdata.Gauge[int64]{
				DataPoints: []metricdata.DataPoint[int64]{
					{},
				},
			},
		},
		{
			Name:        "otelcol_deltatocumulative.streams.max_stale",
			Description: "duration after which streams inactive streams are dropped",
			Unit:        "s",
			Data: metricdata.Gauge[int64]{
				DataPoints: []metricdata.DataPoint[int64]{
					{},
				},
			},
		},
		{
			Name:        "otelcol_deltatocumulative.streams.tracked",
			Description: "number of streams tracked",
			Unit:        "{dps}",
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: false,
				DataPoints: []metricdata.DataPoint[int64]{
					{},
				},
			},
		},
		{
			Name:        "otelcol_deltatocumulative.streams.tracked.linear",
			Description: "number of streams tracked",
			Unit:        "{dps}",
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: false,
				DataPoints: []metricdata.DataPoint[int64]{
					{},
				},
			},
		},
	}, metricdatatest.IgnoreTimestamp(), metricdatatest.IgnoreValue())
	AssertEqualDeltatocumulativeDatapointsDropped(t, testTel.Telemetry,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualDeltatocumulativeDatapointsLinear(t, testTel.Telemetry,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualDeltatocumulativeDatapointsProcessed(t, testTel.Telemetry,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualDeltatocumulativeGapsLength(t, testTel.Telemetry,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualDeltatocumulativeStreamsEvicted(t, testTel.Telemetry,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualDeltatocumulativeStreamsLimit(t, testTel.Telemetry,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualDeltatocumulativeStreamsMaxStale(t, testTel.Telemetry,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualDeltatocumulativeStreamsTracked(t, testTel.Telemetry,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())
	AssertEqualDeltatocumulativeStreamsTrackedLinear(t, testTel.Telemetry,
		[]metricdata.DataPoint[int64]{{Value: 1}},
		metricdatatest.IgnoreTimestamp())

	require.NoError(t, testTel.Shutdown(context.Background()))
}
