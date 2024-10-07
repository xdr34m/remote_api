package shared

import (
	"fmt"

	"github.com/spf13/viper"
)

// General represents the general configuration section.
type General struct {
	ClientType          string   `mapstructure:"client_type"` // one of managed_rhel, managed_win, rhel, win, ubuntu
	ClientDirectory     string   `mapstructure:"client_directory"`
	RandDelayExecutingS int      `mapstructure:"rand_delay_executing_s"` // delay execution randomly between 0 to 600 seconds
	UpdaterClientName   string   `mapstructure:"updater_client_name"`
	BuildType           string   `mapstructure:"build_type"` // supported are amd64_exe, amd64_rpm
	RandSleepDuration   string   `mapstructure:"rand_sleep_on_exe"`
	SyncDirs            []string `mapstructure:"sync_dirs"`
}

type Api struct {
	VerifySSL bool            `mapstructure:"verify_ssl"`
	BaseURL   string          `mapstructure:"base_url"`
	BasicAuth BasicAuthConfig `mapstructure:"basic_auth"`
}

type BasicAuthConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// Alloy represents the alloy configuration section.
type Alloy struct {
	Port              int           `mapstructure:"port"`
	InterfaceIP       string        `mapstructure:"interface_ip"`
	SysconfigFile     string        `mapstructure:"sysconfig_file"`
	ServiceName       string        `mapstructure:"service_name"`
	WorkingDir        string        `mapstructure:"working_dir"`
	Linux             LinuxConfig   `mapstructure:"linux"`   // Linux-specific config for Alloy
	Windows           WindowsConfig `mapstructure:"windows"` // Windows-specific config for Alloy
	MaxBootupDuration string        `mapstructure:"max_bootup_duration"`
}

// LinuxConfig represents the Linux-specific configuration for both Alloy and Script Exporter.
type LinuxConfig struct {
	SysconfigFile  string     `mapstructure:"sysconfig_file"`
	RPMName        string     `mapstructure:"rpm_name"`
	TmpDir         string     `mapstructure:"tmp_dir"`
	Username       string     `mapstructure:"username"`
	UID            int        `mapstructure:"uid"`
	GID            int        `mapstructure:"gid"`
	Cron           CronConfig `mapstructure:"cron"`
	VersionPattern string     `mapstructure:"version_pattern"`
}

// WindowsConfig represents the Windows-specific configuration for Alloy Script Exporter and shawl.
type WindowsConfig struct {
	ExeName        string `mapstructure:"exe_name"`
	VersionPattern string `mapstructure:"version_pattern"`
	VersionOpt     string `mapstructure:"version_opt"`
	ExeArgs        string `mapstructure:"exe_args"`
}

// ScriptExporter represents the script exporter configuration section.
type ScriptExporter struct {
	InterfaceIP       string        `mapstructure:"interface_ip"`
	Port              int           `mapstructure:"port"`
	HardconfigFile    string        `mapstructure:"hardconfig_file"`
	ServiceName       string        `mapstructure:"service_name"`
	Linux             LinuxConfig   `mapstructure:"linux"`   // Linux-specific config for Script Exporter
	Windows           WindowsConfig `mapstructure:"windows"` // Windows-specific config for Alloy
	MaxBootupDuration string        `mapstructure:"max_bootup_duration"`
}

// Windows represents the Windows-specific configuration section.
type Windows struct {
	User string     `mapstructure:"user"`
	Task TaskConfig `mapstructure:"task"`
}
type TaskConfig struct {
	TaskName       string `mapstructure:"task_name"`
	TaskIntervallm int    `mapstructure:"task_intervall_in_m"`
}
type SyncdirsConfig struct {
	SyncDirs []string `mapstructure:"sync_dir"` // A slice of strings for sync directories
}

// Logrotate represents the log rotation configuration section.
type LoggingConf struct {
	LogDir      string `mapstructure:"log_dir"`
	LogFile     string `mapstructure:"log_file"`
	MaxSize     int    `mapstructure:"max_size"` //in MB
	BackupCount int    `mapstructure:"backup_count"`
	MaxAgeDays  int    `mapstructure:"max_age_days"`
}

// Cron represents the cron job configuration section.
type CronConfig struct {
	File     string `mapstructure:"file"`
	Command  string `mapstructure:"command"`
	Schedule string `mapstructure:"schedule"` // Every 30 minutes
	User     string `mapstructure:"user"`
	Comment  string `mapstructure:"comment"`
}

// Config holds the entire configuration structure.
type Config struct {
	General        General        `mapstructure:"general"`
	Alloy          Alloy          `mapstructure:"alloy"`
	ScriptExporter ScriptExporter `mapstructure:"script_exporter"`
	Windows        Windows        `mapstructure:"windows"`
	LoggingStat    LoggingConf    `mapstructure:"loggingStat"`
	Api            Api            `mapstructure:"api"`
	Linux          LinuxConfig    `mapstructure:"linux"`
}

var GlobalConfig Config // Global variable to hold the config

// LoadConfig loads the configuration from the specified file path or defaults to "config.yaml"
func LoadConfig(configFilePath string) error {
	// Initialize Viper
	if configFilePath == "" {
		configFilePath = "config.yaml"
	}

	// Set the config file name and path
	viper.SetConfigFile(configFilePath)

	// Try to read the configuration file
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}

	// Unmarshal the config into the Config struct
	if err := viper.Unmarshal(&GlobalConfig); err != nil {
		return fmt.Errorf("unable to decode into config struct: %w", err)
	}
	return nil
}
