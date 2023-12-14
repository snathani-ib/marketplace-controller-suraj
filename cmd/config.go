package main

import (
	"time"

	"github.com/spf13/pflag"
)

const (
	// gRPC server
	defaultDataExporterInsecure          = false
	defaultDataExporterAddress           = "0.0.0.0"
	defaultDataExporterPort              = "9090"
	defaultInsecureSkipVerifyEnable      = false
	defaultTimeForKeepAliveConnection    = 30 * time.Second
	defaultTimeOutForKeepAliveConnection = 10 * time.Second

	// soar_light
	defaultDataStreamPort = "9195"
	defaultDataStreamHost = "0.0.0.0"

	// healthchecks
	defaultInternalEnable  = true
	defaultInternalAddress = "0.0.0.0"
	defaultInternalPort    = "10001"
	defaultInternalHealth  = "/health"

	defaultSSLServerName = "cp.noa.infoblox.com"
	defaultSSLCACertFile = "/var/agent/certs/DigiCertCAChain.crt"

	// path configurations
	defaultConfigPath           = "/opt/grpc_in/conf/grpc_in.json"
	defaultVersionPath          = "/opt/grpc_in/conf/version"
	defaultGrpcInFolder         = "/infoblox/data/in/cloud"
	defaultGrpcOutFolder        = "/infoblox/data/out"
	defaultSplunkOutFolder      = "splunk/bloxone"
	defaultSplunkCloudOutFolder = "splunkcloud/bloxone"
	defaultSiemOutFolder        = "siem/bloxone"
	defaultReportingOutFolder   = "reporting/bloxone"

	// logging configurations
	defaultLoggingLevel = "info"

	// Number of records per file
	defaultRecordsPerFile = 100000

	// Sleep time in milliseconds for parser to pickup next parquet file
	defaultPickUpDelayInMs = 0

	// Refresh interval in seconds for processing pending files from transfer folder
	defaultRefreshInterval       = 10 * time.Second
	defaultPendingFilesBatchSize = 100

	// file write buffer size
	defaultFileBufferSize = 32768

	// Worker pool configuration parameters
	defaultDataWorkers     = 2
	defaultDataChannelSize = 256

	// Ack pool configuration parameters
	defaultAckWorkers     = 3
	defaultAckChannelSize = 256

	//stream cancel timeout interval
	defaultStreamCancelTimeout         = 2 * time.Minute
	defaultConnectionRetryInterval     = 150 * time.Second
	defaultConnectionRetryWaitInterval = 30 * time.Second
	defaultConnectionResetInterval     = 30 * time.Minute

	// backoff (min, max) time interval
	defaultBackOffMin    = 5 * time.Second
	defaultBackOffMax    = 5 * time.Minute
	defaultBackOffFactor = 2.0

	// data map cleanup interval in seconds
	defaultCleanUpDataMapInterval = 60 * time.Second
	defaultDataMapLimit           = 10000

	// metrics
	defaultMetricsSizeInterval      = 15 * time.Second
	defaultMetricsTimestampInterval = 5 * time.Second
	defaultMetricsWriteInterval     = 15 * time.Second

	// CDC app version and on-prem hostname
	defaultCdcAppVersion     = "2.1.3"
	defaultCdcOnpremHostName = "-"

	// feature flags
	defaultFeatureEnrichedDataEnable = true
	defaultFeatureDstreamEnable      = true
)

var (
	// gRPC-Proxy server
	flagServerEnv                                = pflag.Bool("data-exporter.insecure", defaultDataExporterInsecure, "default data-exporter environment")
	flagServerAddress                            = pflag.String("data-exporter.host", defaultDataExporterAddress, "address of Data Exporter server")
	flagServerPort                               = pflag.String("data-exporter.port", defaultDataExporterPort, "port of Data Exporter server")
	flagInsecureSkipVerifyEnable                 = pflag.Bool("insecure-skip-verify-enable", defaultInsecureSkipVerifyEnable, "enable/disable verification of the server's certificate chain and host name")
	flagTimeDefaultTimeForKeepAliveConnection    = pflag.Duration("keepalive.connection.time", defaultTimeForKeepAliveConnection, "default time for keep-alive connection")
	flagTimeDefaultTimeOutForKeepAliveConnection = pflag.Duration("keepalive.connection.timeout", defaultTimeOutForKeepAliveConnection, "default timeout for keep-alive connection")

	// soar-light
	flagDataStreamAdddress = pflag.String("data-stream-server.host", defaultDataStreamHost, "address of Data Exporter server")
	flagDataStreamPort     = pflag.String("data-stream-server.port", defaultDataStreamPort, "port of Soar Light service")

	// healthchecks
	flagInternalEnable  = pflag.Bool("internal.enable", defaultInternalEnable, "enable internal http server")
	flagInternalAddress = pflag.String("internal.address", defaultInternalAddress, "address of internal http server")
	flagInternalPort    = pflag.String("internal.port", defaultInternalPort, "port of internal http server")
	flagInternalHealth  = pflag.String("internal.health", defaultInternalHealth, "endpoint for health checks")

	// server parameters
	flagSSLCACertFile = pflag.String("SSL_CA_CERT_FILE", defaultSSLCACertFile, "SSL CA Cert FILE")
	flagSSLServerName = pflag.String("SSL_SERVER_NAME", defaultSSLServerName, "SSL Server Name")

	// path parameters
	flagConfigPath                 = pflag.String("grpc_in.config", defaultConfigPath, "grpc-in config file path")
	flagVersionPath                = pflag.String("grpc_in.version", defaultVersionPath, "grpc-in version file path")
	flagConfigGrpcInFolder         = pflag.String("grpc_in.dir", defaultGrpcInFolder, "grpc-in input directory where .parquet files stored")
	flagConfigGrpcOutFolder        = pflag.String("grpc_out.dir", defaultGrpcOutFolder, "grpc-in output directory common path")
	flagConfigSplunkOutFolder      = pflag.String("splunk_out.dir", defaultSplunkOutFolder, "splunk-out output directory where csv files stored")
	flagConfigSplunkCloudOutFolder = pflag.String("splunkcloud_out.dir", defaultSplunkCloudOutFolder, "splunkcloud-out output directory where csv files stored")
	flagConfigSiemOutFolder        = pflag.String("siem_out.dir", defaultSiemOutFolder, "siem-out output directory where cef|leef files stored")
	flagConfigReportingOutFolder   = pflag.String("reporting_out.dir", defaultReportingOutFolder, "reporting-out output directory where csv files stored")

	// No of records per file
	flagRecordsPerFile = pflag.Int("records.perfile", defaultRecordsPerFile, "Number of records/file")

	// Write file buffer size
	flagWriteFileBufferSize = pflag.Int("file.buffer.size", defaultFileBufferSize, "Write file buffer size while parsering input parquet files")

	// Sleep time in milliseconds before picking up parquet input file
	flagPickUpDelayInMs = pflag.Int("parser.file.sleep.ms", defaultPickUpDelayInMs, "Sleep time in milliseconds before parser pickup next file")

	// Refresh interval time in seconds for processing pending files from transfer folder
	flagRefreshInterval       = pflag.Duration("parser.refresh.interval", defaultRefreshInterval, "Refresh interval in seconds for processing pending files from transfer folder")
	flagPendingFilesBatchSize = pflag.Int("pending.files.batch.size", defaultPendingFilesBatchSize, "pending files batch size")

	// Logging parameters
	flagLoggingLevel = pflag.String("log.level", defaultLoggingLevel, "log level of application")

	// Minimum number of goroutines
	flagDataWorkersCount = pflag.Int("pool.data.workers.count", defaultDataWorkers, "pool count of data workers")
	flagDataChannelSize  = pflag.Int("pool.data.channel.size", defaultDataChannelSize, "buffered pool size for data workers")
	flagAckWorkersCount  = pflag.Int("pool.ack.workers.count", defaultAckWorkers, "pool count of ack workers")
	flagAckChannelSize   = pflag.Int("pool.ack.channel.size", defaultAckChannelSize, "buffered pool size of ack workers")
	flagUseMaxProcessors = pflag.Bool("pool.use.max.procs", false, "Use max processors")

	//Stream cancel timeout interval
	flagStreamCancelTimeout         = pflag.Duration("context.cancel.timeout", defaultStreamCancelTimeout, "Timeout interval for cancelling the stream in minutes(2m, 4m ..etc)")
	flagConnectionRetryInterval     = pflag.Duration("connection.retry.interval", defaultConnectionRetryInterval, "Connection retry interval if there is no activity b/w client and server(10s, 20s ..etc)")
	flagConnectionRetryWaitInterval = pflag.Duration("connection.retry.wait.interval", defaultConnectionRetryWaitInterval, "Connection retry wait internal")
	flagConnectionResetInterval     = pflag.Duration("connection.reset.interval", defaultConnectionResetInterval, "Connection reset interval which is used when data.exporter.kafka doesn't send logs")

	// Backoff exponential timeout (min, max)
	flagBackOffMin    = pflag.Duration("backoff.min", defaultBackOffMin, "backoff min time")
	flagBackOffMax    = pflag.Duration("backoff.max", defaultBackOffMax, "backoff max time")
	flagBackOffFactor = pflag.Float64("backoff.factor", defaultBackOffFactor, "backoff factor")

	// CleanUp data map interval in seconds
	flagCleanUpDataMapInterval = pflag.Duration("datamap.cleanup.interval", defaultCleanUpDataMapInterval, "Data map cleanup interval in seconds")
	flagDataMapLimit           = pflag.Int64("datamap.limit", defaultDataMapLimit, "max entries that data map can support")

	// metrics
	flagMetricSizeInterval      = pflag.Duration("metrics.timestamp.interval", defaultMetricsTimestampInterval, "interval to send timestamp metrics(i.e in seconds)")
	flagMetricTimestampInterval = pflag.Duration("metrics.size.interval", defaultMetricsSizeInterval, "interval to send size metrics(i.e in seconds)")
	flagMetricsWriteInterval    = pflag.Duration("metrics.write.interval", defaultMetricsWriteInterval, "interval to write metrics to a file(i.e in seconds)")

	flagCdcAppVersion  = pflag.String("cdc.app.version", defaultCdcAppVersion, "default CDC application version")
	flagOnpremHostName = pflag.String("cdc.onprem.hostname", defaultCdcOnpremHostName, "default CDC on-prem hostname")

	// feature flags
	flagFeatureEnrichedDataEnable = pflag.Bool("feature.enricheddata.enable", defaultFeatureEnrichedDataEnable, "Enriched Data feature to enable/disable, default is true")
	flagFeatureDstreamEnable      = pflag.Bool("feature.dstream.enable", defaultFeatureDstreamEnable, "Dstream feature to enable/disable, default is true")

	flagWriteToTempEnabled      = pflag.Bool("write.to.temp.enabled", false, "enable to write incoming data to temporary files")
	flagWriteToTempPath         = pflag.String("write.to.temp.path", "/tmp/", "write to temp path for debugging any production issues")
	flagStopPullingLogs         = pflag.Bool("sleep.before.pull.enabled", false, "flag to set sleep before pull logs")
	flagStopPullingLogsInterval = pflag.Duration("sleep.before.pull.interval", 60*time.Second, "sleep interval before pulling")
	flagGracefulWaitInterval    = pflag.Duration("graceful.shutdown.wait.time", 10*time.Second, "graceful shutdown wait time")
	flagKeepaliveTimeInterval   = pflag.Duration("keepalive.time.interval", 30*time.Second, "keep-alive time interval")
	flagKeepaliveRetryCount     = pflag.Int("keepalive.retry.count", 5, "keep-alive retry count")
)
