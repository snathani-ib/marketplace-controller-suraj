package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Infoblox-CTO/cdc.common/logger"
	"github.com/Infoblox-CTO/cdc.grpc-in/pkg/client"
	"github.com/Infoblox-CTO/cdc.grpc-in/pkg/config"
	"github.com/Infoblox-CTO/cdc.grpc-in/pkg/dsclient"
	"github.com/Infoblox-CTO/cdc.grpc-in/pkg/metrics"
	"github.com/Infoblox-CTO/cdc.grpc-in/pkg/migration"
	"github.com/Infoblox-CTO/cdc.grpc-in/pkg/soarlightserver"
	"github.com/Infoblox-CTO/cdc.grpc-in/pkg/ticker"
	"github.com/Infoblox-CTO/cdc.grpc-in/pkg/types"
	"github.com/Infoblox-CTO/cdc.grpc-in/pkg/utils"
	"github.com/Infoblox-CTO/data.exporter.kafka/pkg/pb"
	dspb "github.com/Infoblox-CTO/soar-light/pkg/api/datastream"
	ds "github.com/Infoblox-CTO/soar-light/pkg/dstream"
	"github.com/jpillora/backoff"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	RetryInterval        = 5 // seconds
	Healthy              = "healthy"
	InternalError        = "internal error"
	NotConfigured        = "yet to be configured"
	healthTimeout        = 30
	healthUpdateInterval = 30
)

var (
	isHealthy  bool
	emptyJson  = "{}"
	healthLock = &sync.Mutex{}
	healthLog  = log.WithField("name", "cdc_health")
	errChannel = make(chan error, 4)
)

func init() {
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	logger.NewLogger(map[string]interface{}{
		"service_id": os.Getenv("SERVICE_ID"),
	})
}

func main() {
	var (
		err          error
		inSecureMode = viper.GetBool("data-exporter.insecure")
		cloudUrl     = fmt.Sprintf("%s:%s", viper.GetString("data-exporter.host"), viper.GetString("data-exporter.port"))
	)

	log.Infof("Starting gRPC-In container...")
	ctx, cancel := context.WithCancel(context.Background())

	// health checks
	go healthCheck()

	configPath := viper.GetString("grpc_in.config")
	versionPath := viper.GetString("grpc_in.version")
	waitForConfig(configPath, versionPath)

	conf := config.NewConfig()
	if err = conf.Load(configPath); err != nil {
		log.Fatalf("Failed to load configurations, %v", err)
	}

	if err = conf.Parse(); err != nil {
		log.Fatalf("Error in parsing configurations, %v", err)
	}

	jsonConfig, _ := jsoniter.Marshal(conf)
	log.Infof("gRPC-In container configurations %+v", string(jsonConfig))

	if err := createDataDirs(conf.ParserConfig); err != nil {
		log.Fatalf("Failed to create input/output data directories, %v", err)
	}

	flowIds, err := config.GetFlowIds()
	if err != nil {
		log.Fatalf("Error in getting flow-ids, %v", err)
	}

	cl := client.NewClient(os.Getenv("NS_OPH_ID"))
	if err = cl.Connect(cloudUrl, inSecureMode); err != nil {
		log.Fatalf("Failed to create connection to %s: %v", cloudUrl, err)
	}

	log.Infof("Connection object is created successfully, CloudURL=%s", cloudUrl)

	// Read the hostapp config after that create thread to watch any changes in it
	go utils.MonitorHostAppConfig(os.Getenv("HOSTAPP_CONFIG"))

	// keep checking the health and update isHealthy which will be used by the healthCheck
	go updateHealthStatus(cloudUrl, inSecureMode)

	// Allocate client resources
	cl.AllocResources()
	go cl.ReleaseResources(ctx)

	// start metrics
	m := metrics.NewCdcAppMetrics()
	err = m.Init(config.GetDataTypes())
	if err != nil {
		log.Errorf("Failed to initialize metrics stats, %v", err)
	}

	go m.Start(ctx)

	// process any pending files
	go cl.Processor(ctx, viper.GetDuration("parser.refresh.interval"), viper.GetInt("pending.files.batch.size"))

	// handle signals with graceful shutdown
	go handleSignals(ctx, cancel)

	// Move old csv format files with latest csv format
	go migration.MoveOldCsvFiles()

	var legacyFlowIds, dstreamFlowIds []int64
	for _, id := range flowIds {
		dt := int32(id & 0xFFFFFFFF)
		dataType, _ := pb.DataType_name[dt]
		if types.IsLegacyDataType(dataType) {
			legacyFlowIds = append(legacyFlowIds, id)
			continue
		}

		dstreamFlowIds = append(dstreamFlowIds, id)
	}

	if viper.GetBool("feature.dstream.enable") && len(dstreamFlowIds) > 0 {
		accountId := os.Getenv("ACCOUNT_ID")
		if accountId == "" {
			accountId = config.GetAccountId()
			if accountId == "" {
				log.Fatalf("Account ID should not be empty")
			}
		}

		initDataStream(ctx, cancel, dstreamFlowIds, accountId)
	}

	// start dsstream server to destination soar-light
	if config.IsDestinationConfigured(config.DestinationSoarLight) {
		go startDataStreamServer(ctx, cancel)
	}

	// Not necessary to run legacy client if there are no legacy types configured
	if len(legacyFlowIds) == 0 {
		<-ctx.Done()
		waitTime := viper.GetDuration("graceful.shutdown.wait.time")
		time.Sleep(waitTime)
		return
	}

	expBackOff := &backoff.Backoff{
		Min:    viper.GetDuration("backoff.min"),
		Max:    viper.GetDuration("backoff.max"),
		Factor: viper.GetFloat64("backoff.factor"),
		Jitter: false,
	}

	var (
		dur             time.Duration
		tickr           *ticker.Ticker
		stream          pb.DataExporterKafka_DataReqClient
		shouldRetryConn bool
		resetBackOff    bool
	)

	err = nil // setting it to nil to be safer
	for {
		if err != nil {
			dur = WaitUpto(expBackOff)
			log.Errorf("%v, Will retry in %v", err, dur)
			time.Sleep(dur)

			if err == io.EOF || err == client.ErrClientConnNil {
				shouldRetryConn = true
			}
		}

		if dur.Minutes() == expBackOff.Max.Minutes() {
			log.Infof("Reset exponential backoff %s", dur)
			expBackOff.Reset()

			// Reconnect when max exponential backoff is reached
			shouldRetryConn = true
		}

		if shouldRetryConn {
			log.Infof("Reconnecting to data.exporter.kafka...")
			err = cl.ReConnect(cloudUrl, inSecureMode, viper.GetDuration("connection.retry.wait.interval"))
			if err != nil {
				continue
			}
			shouldRetryConn = false
			log.Infof("Connection to data.exporter.kafka is established successfully")
		}

		log.Infof("Subscribing to data.exporter.kafka server...")
		ctx, cancel := context.WithCancel(context.Background())
		stream, err = cl.Subscribe(legacyFlowIds, ctx)
		if err != nil {
			continue
		}

		log.Info("Subscribed to data.exporter.kafka server successfully")
		tickr = ticker.CreateTicker(
			viper.GetDuration("context.cancel.timeout"),
			viper.GetDuration("connection.retry.interval"),
		)

		go func(ctx context.Context, tickr *ticker.Ticker) {
			err := tickr.Monitor(ctx)
			if err != nil {
				log.Errorf("ticker monitoring failed, %v", err)
				err = cl.ReConnect(cloudUrl, inSecureMode, viper.GetDuration("connection.retry.wait.interval"))
				if err != nil {
					log.Errorf("unable to reconnect, %v", err)
				}
			}
		}(ctx, tickr)

		// Make the data request to data.exporter.kafka and process data logs
		resetBackOff, err = cl.Recv(ctx, stream, tickr)
		if resetBackOff {
			expBackOff.Reset()
		}

		// Cleanup resources
		cancel()
		tickr.Stop()
	}
}

func initDataStream(ctx context.Context, cancel context.CancelFunc, flowIds []int64, accountId string) {
	var (
		dsCloudUrl   = fmt.Sprintf("%s:%s", viper.GetString("data-exporter.host"), viper.GetString("data-exporter.port"))
		inSecureMode = viper.GetBool("data-exporter.insecure")
	)

	go func() {
		var (
			dur   time.Duration
			err   error
			ophId string
		)

		defer func() {
			cancel()
		}()

		err = nil // setting it to nil to be safer
		ophId = os.Getenv("NS_OPH_ID")
		if ophId == "" {
			log.Fatalf("Failed due to OphId is not being set")
		}

		expBackOff := &backoff.Backoff{
			Min:    viper.GetDuration("backoff.min"),
			Max:    viper.GetDuration("backoff.max"),
			Factor: viper.GetFloat64("backoff.factor"),
			Jitter: false,
		}

		conMsg := "connecting"
		for {
			if err != nil {
				dur = WaitUpto(expBackOff)
				log.Errorf("%v, Will retry in %v", err, dur)
				time.Sleep(dur)
			}

			if dur.Minutes() == expBackOff.Max.Minutes() {
				log.Infof("Reset exponential backoff %s", dur)
				expBackOff.Reset()
			}

			log.Infof("Data stream client %v to data.exporter.kafka...", conMsg)
			dscl := dsclient.NewDsClient(ophId)

			if err = dscl.Connect(dsCloudUrl, inSecureMode); err != nil {
				log.Infof("Failed %v with err %v", conMsg, err)
				continue
			}

			log.Infof("Data stream client is created, cloud url: %s, returned with err : %v", dsCloudUrl, err)
			newCtx, newCancel := context.WithCancel(context.Background())

			// blocking call (has indefinite for loop), will return ONLY when the connection is in trouble with data exporter kafka
			// will return nil when cdc-grpc-in is gracefully closed
			if err = startDataStreamClient(newCtx, newCancel, dscl, flowIds, accountId); err == nil {
				return
			}

			log.Warnf("Data stream client is failed with err %v", err)
			conMsg = "reconnecting"
		}
	}()
}

func startDataStreamServer(ctx context.Context, cancel context.CancelFunc) {
	// close the ds client to data-exporter-kafka when ds stream server (to soar-light) got closed
	defer cancel()

	addr := fmt.Sprintf("%s:%s", viper.GetString("data-stream-server.host"), viper.GetString("data-stream-server.port"))

	log.Infof("Starting data stream server, address: %s", addr)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s, err: %v", addr, err)
	}

	grpcServer := grpc.NewServer()
	dsServer, err := ds.NewServer(ds.WithDefaultDataSource(soarlightserver.DriverName, ""))
	if err != nil {
		log.Fatalf("Failed to create data stream server, err: %v", err)
	}
	defer dsServer.Close()

	dspb.RegisterServerServer(grpcServer, dsServer)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve, err: %v", err)
	}
}

func startDataStreamClient(ctx context.Context, cancel context.CancelFunc, dscl dsclient.DsClient, flowIds []int64, accountId string) error {
	var (
		err error
	)

	err = dscl.Subscribe(ctx, accountId, flowIds)
	if err != nil {
		return err
	}

	defer func() {
		dscl.Close(ctx)
	}()

	go func() {
		err := dscl.SendAck(ctx)
		if err != nil {
			errChannel <- err
		}
	}()

	go func() {
		err := dscl.SendKeepAlive(ctx)
		if err != nil {
			errChannel <- err
		}
	}()

	go func() {
		err := dscl.Recv(ctx)
		if err != nil {
			errChannel <- err
		}
	}()

	select {
	case err := <-errChannel:
		cancel()
		return err
	case <-ctx.Done():
		return nil
	}
}

// Upon graceful shutdown, follow the order for resource cleanup
//  1. Stop pending files processor
//  2. Close client connection and release all client resources(stopping ack & data workers and writing cache data to files..etc)
//  3. Write metrics to file and quit the loop
func handleSignals(ctx context.Context, cancel context.CancelFunc) {
	sigChannel := make(chan os.Signal, 3)
	signal.Notify(sigChannel, syscall.SIGTERM, syscall.SIGINT, syscall.SIGSTOP)

	// waiting for signal
	sig := <-sigChannel

	log.Infof("Received signal: %v, err: %v", sig, ctx.Err())
	close(sigChannel)
	errChannel <- ctx.Err()
	// cancel the context, this will trigger all go routines to stop
	cancel()

	waitTime := viper.GetDuration("graceful.shutdown.wait.time")
	log.Infof("cdc-grpc-in waiting %v for graceful shutdown", waitTime)
	time.Sleep(waitTime)

	log.Infof("cdc-grpc-in service is gracefully shutdown")
	os.Exit(0)
}

func waitForConfig(confPath, versionPath string) {
	var showOneTimeMsg bool

	for {
		file, err := os.Stat(versionPath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Fatalf("Version file is not present, VersionPath: %s", versionPath)
			} else {
				log.Fatalf("Version file error %v, VersionPath: %s", err, versionPath)
			}
		} else if file.Size() == 0 {
			log.Fatalf("Version file is empty, VersionPath: %s", versionPath)
		}

		file, err = os.Stat(confPath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Fatalf("Config file is not present, ConfigPath: %s", confPath)
			} else {
				log.Fatalf("Config file error %v, ConfigPath: %s", err, confPath)
			}
		} else if file.Size() > 0 {
			data, err := ioutil.ReadFile(confPath)
			trimFileData := strings.Trim(string(data), "\n")
			if err != nil {
				log.Errorf("Failed to read file %s", confPath)
			}

			if strings.Compare(trimFileData, emptyJson) != 0 {
				break
			} else {
				if !showOneTimeMsg {
					log.Warnf("Empty configurations %s, ConfigPath: %s", trimFileData, confPath)
					showOneTimeMsg = true
				}
			}
		} else {
			if !showOneTimeMsg {
				log.Debugf("Config file is empty, ConfigPath: %s", confPath)
				showOneTimeMsg = true
			}
		}

		time.Sleep(RetryInterval * time.Second)
	}
}

// go routine that is called in the beginning of the program and runs for ever. It keeps making a connection to the
// data exporter cloud url every healthUpdateInterval seconds by creating a new context every time with a timeout and
// cancel at the end.
// isHealthy variable will be updated depending on the success of the grpc DialContext. It is set to true in case of
// success and sleep is called for healthUpdateInterval seconds. It is set to false in case of failure and does not
// require a sleep in this case. Because its a blocking call and times out after healthTimeout seconds with context
// deadline exceeded. Hence a separate sleep of healthUpdateInterval is not required in case of failure.
func updateHealthStatus(cloudUrl string, dataExporterInsecure bool) {
	log.Infof("Starting updateHealthStatus routine with url %s", cloudUrl)
	// following log should never be hit
	defer log.Error("updateHealthStatus routine exited!")

	dialOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithBackoffMaxDelay(healthTimeout * time.Second),
	}

	if dataExporterInsecure {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	} else {
		// token-based authentication
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	for {
		ctx, cancel := context.WithTimeout(context.Background(), healthTimeout*time.Second)
		conn, err := grpc.DialContext(ctx, cloudUrl, dialOpts...)
		if err != nil || conn == nil {
			healthLock.Lock()
			isHealthy = false
			healthLock.Unlock()
			log.Errorf("Container is unhealthy: %v", err)
		} else {
			healthLock.Lock()
			isHealthy = true
			healthLock.Unlock()
			log.Debugf("Container is healthy and sleeping for %d seconds", healthUpdateInterval)
			time.Sleep(healthUpdateInterval * time.Second)
		}
		if conn != nil {
			conn.Close()
		}
		cancel()
	}
}

// health check
func healthCheck() {
	http.HandleFunc(viper.GetString("internal.health"), healthHandler)

	err := http.ListenAndServe(
		fmt.Sprint(viper.GetString("internal.address"),
			":",
			viper.GetString("internal.port")), nil,
	)

	if err != nil {
		healthLog.Fatalf("Couldn't start healthcheck %v", err)
	}
}

// health handler for checking container health
func healthHandler(w http.ResponseWriter, r *http.Request) {
	status, msg := doHealthChecks()
	w.WriteHeader(status)
	_, err := w.Write([]byte(msg))
	if err != nil {
		healthLog.Errorf("Failed to write healthcheck response %v", err)
	}
}

func doHealthChecks() (status int, msg string) {
	var (
		userErrorMsg string
	)

	configPath := viper.GetString("grpc_in.config")
	if configPath == "" {
		userErrorMsg = "grpc-in config file path is empty"
		healthLog.Errorf(userErrorMsg)
		return http.StatusNotFound, userErrorMsg
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		healthLog.Errorf("grpc-in config file read error %v", err)
		return http.StatusNotFound, InternalError
	}

	if len(data) == 0 {
		healthLog.Debug("grpc-in is yet to be configured")
		return http.StatusAccepted, NotConfigured
	}

	trimFileData := strings.Trim(string(data), "\n")
	if strings.Compare(trimFileData, emptyJson) == 0 {
		userErrorMsg = "grpc-in configurations are deleted"
		healthLog.Debug(userErrorMsg)
		return http.StatusAccepted, userErrorMsg
	}

	versionPath := viper.GetString("grpc_in.version")
	if versionPath == "" {
		userErrorMsg = "grpc-in version file path is empty"
		healthLog.Errorf(userErrorMsg)
		return http.StatusNotFound, userErrorMsg
	}

	data, err = ioutil.ReadFile(versionPath)
	if err != nil {
		healthLog.Errorf("grpc-in version file read error %v", err)
		return http.StatusNotFound, InternalError
	}

	if len(data) == 0 {
		healthLog.Errorf("grpc-in version file is empty")
		return http.StatusAccepted, InternalError
	}

	healthLock.Lock()
	defer healthLock.Unlock()
	if isHealthy == false {
		userErrorMsg = "Connection error with data-exporter endpoint"
		return http.StatusNotFound, userErrorMsg
	}

	return http.StatusAccepted, Healthy
}

func createDataDirs(cf config.ParserConfig) error {
	for _, dirPaths := range cf.DataTypes {
		// check actual path and create input directory
		if !utils.PathExists(dirPaths.InPath) {
			err := utils.CreateDir(dirPaths.InPath)
			if err != nil {
				return err
			}
		}

		// check transfer path and create directory
		transferPath := filepath.Join(dirPaths.InPath, "transfer")
		if !utils.PathExists(transferPath) {
			err := utils.CreateDir(transferPath)
			if err != nil {
				return err
			}
		}

		// check output path and create directories
		for _, flow := range dirPaths.OutPaths {
			if !utils.PathExists(flow.DestinationPath) {
				err := utils.CreateDir(flow.DestinationPath)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func WaitUpto(backOff *backoff.Backoff) time.Duration {
	if backOff == nil {
		return 0
	}

	return backOff.Duration()
}
