package shared

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Log *zap.Logger

// initLogger initializes the zap logger with file rotation.
func InitLogger(debug bool) {
	// Configure lumberjack for log rotation
	// Ensure logs directory exists and has appropriate permissions
	var logDir, logFile string
	switch runtime.GOOS {
	case "linux":
		logDir = "/var/log/alloy"
		logFile = "/var/log/alloy/alloy_updater.log"
	case "windows":
		logDir = "./"
		logFile = "./AlloyUpdater.log"
	}
	if err := ensureLogDir(logDir); err != nil {
		fmt.Printf("Error ensuring log directory: %v\n", err)
		os.Exit(1) // Exit the program with a non-zero status
	}
	rotatingLogger := &lumberjack.Logger{
		Filename:   logFile, // Log file location
		MaxSize:    10,      // Maximum size in megabytes before rotation (e.g., 10 MB)
		MaxBackups: 2,       // Maximum number of old log files to keep
		MaxAge:     30,      // Maximum number of days to retain old log files
		Compress:   true,    // Compress the old log files

	}
	// Set the log level based on the debug flag
	var level zapcore.Level
	if debug {
		level = zap.DebugLevel
		//fmt.Println("DEBUG: loglevel:debug")
	} else {
		level = zap.InfoLevel
		//fmt.Println("DEBUG: loglevel:info")
	}

	// Custom encoder configuration
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"                                  // The key for the timestamp field
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339) // Set the format for the timestamp
	encoderConfig.FunctionKey = zapcore.OmitKey                          // This avoids printing the function twice
	// Create a zapcore that writes to both console and the file with rotation
	fileCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig), // Use JSON encoder
		zapcore.AddSync(rotatingLogger),       // Send logs to lumberjack
		level,                                 // Log level
	)

	// Console output core (optional: for logging to both file and console)
	consoleCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig), // Console friendly, human-readable logs
		zapcore.AddSync(os.Stdout),            // Send logs to console
		level,                                 // Log level
	)

	// Combine both cores (console + file)
	core := zapcore.NewTee(fileCore, consoleCore)

	// Create the logger with combined cores
	Log = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	//Log.Info("test")
	defer Log.Sync()
}

// ensureLogDir checks if the log directory exists and has the correct permissions
func ensureLogDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create log directory: %w", err)
	}

	// Check permissions
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("could not stat log directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	// Optionally, you can check for read/write permissions here if needed

	return nil
}
