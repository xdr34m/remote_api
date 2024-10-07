package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	_ "net/http/pprof" // Import pprof for profiling
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/m/v2/shared"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Payload struct {
	Hostname          string `json:"hostname"`
	OperatingSystem   string `json:"operatingsystem"`
	NeedSignedScripts string `json:"need_signed_scripts,omitempty"` // Use pointer to allow nil for omitted
}

type Usr struct {
	Username string
	Gid      int
	Uid      int
}

type PackageVersion struct {
	Name     string
	Version  string
	Endpoint string
}

// Initialize the global vars
func newmain(ctx context.Context) error {
	//packing everyoperation into a deadline context, and interrupts on timeout! (works!)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err() // Return the context error (cancellation or timeout)
		default:
			err := shared.SetClientFacts()
			if err != nil {
				shared.Log.Error("error on SetClientFacts", zap.Error(err))
			}
			//fmt.Println("DEBUG: logger set")
			shared.Log.Debug("ParsedFlags")
			shared.Log.Debug("Started")

			shared.Log.Debug("User is Admin")
			//tools.Setglobals(*config)
			if shared.GlobalFlags.Deinstall {
				shared.Log.Info("Deinstalling...")
				if shared.OSFacts["os"] == "linux" {
					shared.Log.Debug("special linux uninstall here")
					err := LinuxDeinstall()
					if err != nil {
						shared.Log.Error("Unrecoverable: Error while LinuxDeinstall", zap.Error(err))
					}
					os.Exit(0)
				} else if shared.OSFacts["os"] == "windows" {
					shared.Log.Debug("special windows uninstall here")
					err := WinuxDeinstall()
					if err != nil {
						shared.Log.Error("Unrecoverable: Error while WindowsDeinstall", zap.Error(err))
					}
					os.Exit(0)
				}
			}

			if !shared.GlobalFlags.NoDelay {
				// Parse the sleep duration string to time.Duration
				duration, err := time.ParseDuration(shared.GlobalConfig.General.RandSleepDuration)
				if err != nil {
					log.Fatalf("invalid duration format: %v", err)
				}
				// Generate a random sleep duration between 0 and the specified duration
				randomDuration := time.Duration(rand.Int63n(int64(duration))) // Random duration
				// Use the random duration variable
				shared.Log.Debug("sleeping zzz", zap.Any("randomDuration in s", randomDuration))
				time.Sleep(randomDuration)
				shared.Log.Debug("Awake after sleeping for", zap.Any("randomDuration in s", randomDuration))
			}
			//checks if healthcheck of API is passed
			res, err := GetString(JoinURL(shared.GlobalConfig.Api.BaseURL, "ready"))
			if err != nil {
				shared.Log.Error("Error API not ready, exiting", zap.Error(err))
				os.Exit(1)
			}
			shared.Log.Debug("", zap.Any("API Healthcheck", res))

			var PackageResults []PackageResult //need for later to check if got stopped by a packageops
			var packagesNeedRestart []string
			if shared.OSFacts["os"] == "linux" {
				//Linux Doing User/Paths+Perms/Versions!
				if shared.GlobalConfig.Linux.Username != "" && shared.GlobalConfig.Linux.GID != 0 && shared.GlobalConfig.Linux.UID != 0 {
					err := LinuxCheckUser()
					if err != nil {
						shared.Log.Error("Unrecoverable: Error while checking Linux User", zap.Error(err))
						os.Exit(1)
					}
					shared.Log.Debug("", zap.Any("user_exists", shared.GlobalConfig.Linux.Username))
					usr := Usr{
						Username: shared.GlobalConfig.Linux.Username,
						Uid:      0,
						Gid:      shared.GlobalConfig.Linux.GID,
					}
					alloy_usr := Usr{
						Username: shared.GlobalConfig.Linux.Username,
						Uid:      shared.GlobalConfig.Linux.UID,
						Gid:      shared.GlobalConfig.Linux.GID,
					}
					err = EnsurePathExistswithPerms(shared.GlobalConfig.General.ClientDirectory, 0751, usr)
					if err != nil {
						shared.Log.Error("Unrecoverable: Failed Pathsoperation", zap.Error(err))
						os.Exit(1)
					}
					if viper.IsSet("alloy.data_path") {
						err := EnsurePathExistswithPerms(shared.GlobalConfig.Alloy.WorkingDir, 0775, alloy_usr)
						if err != nil {
							shared.Log.Error("Unrecoverable: Failed Pathsoperation", zap.Error(err))
							os.Exit(1)
						}
					}

					for _, dir := range shared.GlobalConfig.General.SyncDirs {
						err = EnsurePathExistswithPerms(filepath.Join(shared.GlobalConfig.General.ClientDirectory, dir), 0751, usr)
						if err != nil {
							shared.Log.Error("Unrecoverable: Failed Pathsoperation", zap.Error(err))
							os.Exit(1)
						}
					}

				} else {
					shared.Log.Error("Something is missing in Linux config")
					os.Exit(1)
				}

			} else if shared.OSFacts["os"] == "windows" {
				usr := Usr{
					Username: "",
					Uid:      0,
					Gid:      0,
				}
				err = EnsurePathExistswithPerms(shared.GlobalConfig.General.ClientDirectory, 0751, usr)
				if err != nil {
					shared.Log.Error("Unrecoverable: Failed Pathsoperation", zap.Error(err))
					os.Exit(1)
				}
				if viper.IsSet("alloy.data_path") {
					err := EnsurePathExistswithPerms(shared.GlobalConfig.Alloy.WorkingDir, 0775, usr)
					if err != nil {
						shared.Log.Error("Unrecoverable: Failed Pathsoperation", zap.Error(err))
						os.Exit(1)
					}
				}

				for _, dir := range shared.GlobalConfig.General.SyncDirs {
					err = EnsurePathExistswithPerms(filepath.Join(shared.GlobalConfig.General.ClientDirectory, dir), 0751, usr)
					if err != nil {
						shared.Log.Error("Unrecoverable: Failed Pathsoperation", zap.Error(err))
						os.Exit(1)
					}
				}
			}
			// handle packages(apps) -build specific
			res_rpm_updates, err := GetJson(JoinURL(shared.GlobalConfig.Api.BaseURL, fmt.Sprintf("check_rpm_updates/%s", shared.GlobalConfig.General.BuildType)))
			if err != nil {
				shared.Log.Error("Error Checking for rpm Updates", zap.Any("err", err))
			}
			shared.Log.Debug("check_rpm_updates res", zap.Any("res_rpm_updates", res_rpm_updates))
			// Process packages
			PackageResults, err = ProcessPackageVersions(res_rpm_updates)
			if err != nil {
				shared.Log.Error("Error processing packages", zap.Error(err))
				return nil // Handle main error as needed
			}

			// Log the results of processing
			for _, result := range PackageResults {
				if result.Error != nil {
					shared.Log.Error("error Package processing result", zap.Any("pkg.Name", result.Name), zap.String("action", result.Action), zap.Error(result.Error))
				} else {
					shared.Log.Info("Package processing result", zap.Any("pkg.Name", result.Name), zap.String("action", result.Action))
					if result.Action != "insync(noaction)" {
						packagesNeedRestart = append(packagesNeedRestart, result.Name)
					}
				}
			}
			//FILEOPS
			payload := Payload{
				Hostname:          shared.OSFacts["hostname"],
				OperatingSystem:   shared.GlobalConfig.General.ClientType, //config.General.BuildType,
				NeedSignedScripts: shared.OSFacts["signed"],               // Set to nil if you don't want to include it in JSON
			}
			//shared.Log.Debug("", zap.Any("res2", res2))
			res_file_versions, err := PostJson(payload, JoinURL(shared.GlobalConfig.Api.BaseURL, "check_updates"))
			if err != nil {
				shared.Log.Error("Error Checking for File Updates", zap.Error(err))
			}
			shared.Log.Debug("", zap.Any("res2", res_file_versions))
			localFileVersions, err := GetLocalVersions(shared.GlobalConfig.General.ClientDirectory, shared.GlobalConfig.General.SyncDirs)
			if err != nil {
				shared.Log.Error("Error failed in GetLocalVersions", zap.Error(err))
			}
			shared.Log.Debug("localVersions", zap.Any("localFileVersions", localFileVersions))
			fileOperations, err := SyncLocalWithRemote(localFileVersions, res_file_versions, shared.GlobalConfig.General.ClientDirectory)
			if err != nil {
				shared.Log.Error("Error while syncing FileVersions", zap.Error(err))
			} else {
				shared.Log.Info("Synced Files with remote")
			}
			// Process the operations returned
			for _, op := range fileOperations {
				if op.Error != nil {
					// Log the error
					shared.Log.Error("FileSync Operation failed", zap.String("action", op.Action), zap.String("file", op.File), zap.Error(op.Error))
				} else {
					// Log the successful operation
					shared.Log.Info("FileSync Operation completed", zap.String("action", op.Action), zap.String("file", op.File))
				}
			}

			//restart logic - shawl not included - should be okay cause they are later checked if up
			shared.Log.Debug("packages needing restart", zap.Any("packagesNeedRestart", packagesNeedRestart))
			var pkg_restarted []string
			if len(packagesNeedRestart) > 0 {
				shared.Log.Debug("Pkgs need restart", zap.Any("len(packagesNeedRestart)", len(packagesNeedRestart)))
				for _, pkg := range packagesNeedRestart {
					if pkg == "alloy" {
						err := RestartAlloy()
						if err != nil {
							shared.Log.Error("Error restarting alloy", zap.Error(err))
						} else {
							shared.Log.Info("Restarted Alloy")
						}
						pkg_restarted = append(pkg_restarted, pkg)
					} else if pkg == "script_exporter" {
						err := RestartScriptExporter()
						if err != nil {
							shared.Log.Error("Error restarting ScriptExporter", zap.Error(err))
						} else {
							shared.Log.Info("Restarted ScriptExporter")
						}
						pkg_restarted = append(pkg_restarted, pkg)
					}

				}
			}
			//check if SYSTEMCTL/Service Actions needed
			if len(fileOperations) > 0 {

				for _, pkg := range PackageResults {
					if pkg.Name == "alloy" && !Contains(pkg_restarted, "alloy") {
						res, err := GetString(fmt.Sprintf("http://%s:%d/-/reload", shared.GlobalConfig.Alloy.InterfaceIP, shared.GlobalConfig.Alloy.Port))
						if err != nil {
							shared.Log.Error("Error reloading alloy", zap.Error(err))
						} else {
							shared.Log.Info("Reloaded Alloy", zap.Any("res", strings.TrimSpace(res)))
						}
					}
					if pkg.Name == "script_exporter" && !Contains(pkg_restarted, "script_exporter") {
						err := RestartScriptExporter()
						if err != nil {
							shared.Log.Error("Error restarting ScriptExporter", zap.Error(err))
						} else {
							shared.Log.Info("Restarted ScriptExporter")
						}

					}
				}
			}
			//check Apps are Serving HTTP and if not 1 time restarting to check again
			for _, pkg := range PackageResults {
				if pkg.Name != "shawl" {
					err := CheckAppIsServing(pkg.Name)
					if err != nil {
						if pkg.Name == "script_exporter" && !Contains(pkg_restarted, "script_exporter") {
							err := RestartScriptExporter()
							if err != nil {
								shared.Log.Error("Error restarting ScriptExporter", zap.Error(err))
							} else {
								shared.Log.Info("Restarting ScriptExporter after servingcheck failed")
							}

						}
						if pkg.Name == "alloy" && !Contains(pkg_restarted, "alloy") {
							err := RestartAlloy()
							if err != nil {
								shared.Log.Error("Error restarting alloy", zap.Error(err))
							} else {
								shared.Log.Info("Restarting Alloy after servingcheck failed")
							}
						}
						err = CheckAppIsServing(pkg.Name)
						if err != nil {
							shared.Log.Error("App is not serving, even after restart!!", zap.String("pkg", pkg.Name))
						} else {
							shared.Log.Info("App is serving", zap.String("pkg", pkg.Name))
						}
					} else {
						shared.Log.Info("App is serving", zap.String("pkg", pkg.Name))
					}
				}
			}
			//doing cron/task/autoservices
			if shared.OSFacts["os"] == "windows" {
				if viper.IsSet("windows.task") {
					err := CreateScheduledTask()
					if err != nil {
						shared.Log.Error("Failed Creating Task", zap.Error(err))
					}
				}
				if viper.IsSet("alloy") {
					err := CheckAndSetServiceToAutomatic(shared.GlobalConfig.Alloy.ServiceName)
					if err != nil {
						shared.Log.Error("Failed setting Service to automatic", zap.Error(err), zap.String("ServiceName", shared.GlobalConfig.Alloy.ServiceName))
					}
				}
				if viper.IsSet("script_exporter") {
					err := CheckAndSetServiceToAutomatic(shared.GlobalConfig.ScriptExporter.ServiceName)
					if err != nil {
						shared.Log.Error("Failed setting Service to automatic", zap.Error(err), zap.String("ServiceName", shared.GlobalConfig.Alloy.ServiceName))
					}
				}
			} else if shared.OSFacts["os"] == "linux" {
				if viper.IsSet("linux.cron") {
					err := InstallCronJobForUser()
					if err != nil {
						shared.Log.Error("Failed Creating CronTab", zap.Error(err))
					}
				}
			}

			return nil
		}
	}
}
func main() {
	// Set the program to timeout after 120 seconds
	timeout := 120 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel() // Ensure cancel is called to release resources
	// Call ParseFlags() to get the flag values
	//fmt.Printf("DEBUG | %s\n", runtime.GOOS)
	shared.ParseFlags()
	//fmt.Printf("DEBUG: parsed flags: %v", shared.GlobalFlags.Debug)

	err := CheckCurrentUserRoot()
	if err != nil {
		fmt.Printf("DEBUG: Error exiting no admin err: %v\n", err)
		os.Exit(1)
	}
	err = shared.LoadConfig(shared.GlobalFlags.ConfigFilePath)
	if err != nil {
		fmt.Printf("Unrecoverable: Failed to load config %v", err)
		os.Exit(1)
	}
	//fmt.Printf("Loaded Config: %+v\n", shared.GlobalConfig)
	shared.InitLogger(shared.GlobalFlags.Debug) //Logger available here!
	defer shared.Log.Sync()

	/* Start pprof server in a separate goroutine
	go func() {
		shared.Log.Info("Starting pprof server", zap.String("address", "localhost:6060"))
		err := http.ListenAndServe("localhost:6060", nil)
		if err != nil {
			shared.Log.Error("Failed to start pprof server", zap.Error(err))
		}
	}()*/
	// Start the long-running operation
	err = newmain(ctx)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Println("Program timed out - 2min!")
			shared.Log.Error("Program timed out", zap.Error(err))
		} else {
			fmt.Println("Operation failed:", err)
			shared.Log.Error("Operation failed", zap.Error(err))
		}
		os.Exit(1) // Exit with a non-zero status
	}

	// Cleanup and exit normally
	shared.Log.Debug("Operation completed successfully")

}
