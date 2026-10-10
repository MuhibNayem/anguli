package telemetry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds configuration parameters for the telemetry subsystem.
type Config struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	EnableStdout   bool
}

// Telemetry provides handles to tracing and logging.
type Telemetry struct {
	TracerProvider *sdktrace.TracerProvider
	Tracer         trace.Tracer
	Logger         *slog.Logger
}

// Setup initializes OpenTelemetry tracing and structured slog logging.
func Setup(ctx context.Context, cfg Config) (*Telemetry, func(context.Context) error, error) {
	// Configure structured logger
	var logHandler slog.Handler
	opts := &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}

	logHandler = slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(logHandler).With(
		slog.String("service", cfg.ServiceName),
		slog.String("version", cfg.ServiceVersion),
		slog.String("env", cfg.Environment),
	)
	slog.SetDefault(logger)

	// Configure OpenTelemetry Resource
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create otel resource: %w", err)
	}

	// Configure Trace Exporter
	var exporter sdktrace.SpanExporter
	if cfg.EnableStdout {
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize stdout exporter: %w", err)
		}
	} else {
		exporter, err = stdouttrace.New(stdouttrace.WithWriter(io.Discard))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize noop exporter: %w", err)
		}
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := tp.Tracer(cfg.ServiceName)

	cleanup := func(shutdownCtx context.Context) error {
		return tp.Shutdown(shutdownCtx)
	}

	return &Telemetry{
		TracerProvider: tp,
		Tracer:         tracer,
		Logger:         logger,
	}, cleanup, nil
}
