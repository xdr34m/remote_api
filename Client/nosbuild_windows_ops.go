package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"example.com/m/v2/shared"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// ExecutePowerShellCommand executes a PowerShell command and returns its output
func ExecutePowerShellCommand(command string) (string, error) {
	// Create a context with the specified timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) //timeout 5s
	defer cancel()

	// Create a new command to execute PowerShell with the given command
	cmd := exec.CommandContext(ctx, "powershell", "-Command", command)

	// Create a buffer to capture the command's output
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Run the command
	err := cmd.Run()
	if err != nil {
		//pushed this error upwards only
		//shared.Log.Error("Error running powershell command", zap.Error(err), zap.Any("out", out.String()))
		return strings.TrimSpace(out.String()), err
	}

	// Return the output of the command
	return strings.TrimSpace(out.String()), nil
}

type ServiceOps string

const (
	WinInstall   ServiceOps = "localinstall"
	WinDowngrade ServiceOps = "downgrade"
	WinUpdate    ServiceOps = "update"
	WinRemove    ServiceOps = "remove"
)

func WindowsSCcmdAction(serviceName, action string) (string, error) {

	cmdout, err := ExecutePowerShellCommand(fmt.Sprintf("sc.exe %s %s", action, serviceName))
	if err != nil {
		//delegation to caller can be false alert
		shared.Log.Debug("Error SC action", zap.Any("action", action), zap.Error(err))
		return cmdout, fmt.Errorf("error SC action: %s", err)
	}
	return cmdout, nil
}

// CheckAndSetServiceToAutomatic checks if a Windows service is set to automatic startup and sets it to automatic if it is not.
func CheckAndSetServiceToAutomatic(serviceName string) error {
	// PowerShell command to check the service startup type
	checkCmd := fmt.Sprintf(`(Get-Service -Name '%s').StartType`, serviceName)

	// Execute the PowerShell command to check the service startup type
	output, err := ExecutePowerShellCommand(checkCmd)
	if err != nil {
		shared.Log.Error("Failed to check service startup type", zap.String("service", serviceName), zap.Error(err))
		return fmt.Errorf("error checking service: %w", err)
	}

	// Trim the output and check if it's set to 'Automatic'
	output = strings.TrimSpace(output)
	if strings.EqualFold(output, "Automatic") {
		shared.Log.Debug("Service is already set to automatic", zap.String("service", serviceName))
		return nil
	}

	// If the service is not set to automatic, set it to automatic
	shared.Log.Info("Service is not set to automatic, changing startup type", zap.String("service", serviceName))
	setCmd := fmt.Sprintf(`Set-Service -Name '%s' -StartupType Automatic`, serviceName)
	_, err = ExecutePowerShellCommand(setCmd)
	if err != nil {
		shared.Log.Error("Failed to set service to automatic", zap.String("service", serviceName), zap.Error(err))
		return fmt.Errorf("error setting service to automatic: %w", err)
	}

	shared.Log.Info("Service startup type set to automatic successfully", zap.String("service", serviceName))
	return nil
}

// CreateScheduledTaskCopyUpdater creates a scheduled task if it doesn't exist
func CreateScheduledTask() error {
	taskCommand := fmt.Sprintf("%s\\%s", shared.GlobalConfig.General.ClientDirectory, shared.GlobalConfig.General.UpdaterClientName)

	// Command to check if the scheduled task exists
	schtasksQueryCommand := fmt.Sprintf("schtasks /Query /TN \"%s\"", shared.GlobalConfig.Windows.Task.TaskName)

	// Check if the task already exists
	if _, err := ExecutePowerShellCommand(schtasksQueryCommand); err == nil {
		shared.Log.Debug("Scheduled task already exists", zap.String("task_name", shared.GlobalConfig.Windows.Task.TaskName))
		return nil
	}

	// Task does not exist, create it
	schtasksCreateCommand := fmt.Sprintf("schtasks /Create /SC MINUTE /MO %d /TN \"%s\" /TR \"%s\" /RU SYSTEM /F", shared.GlobalConfig.Windows.Task.TaskIntervallm, shared.GlobalConfig.Windows.Task.TaskName, taskCommand)

	if _, err := ExecutePowerShellCommand(schtasksCreateCommand); err != nil {
		shared.Log.Error("Failed to create scheduled task", zap.String("task_name", shared.GlobalConfig.Windows.Task.TaskName), zap.Error(err))
		return err
	} else {
		shared.Log.Info("task created successfully", zap.String("task_name", shared.GlobalConfig.Windows.Task.TaskName))
	}
	return nil
}

// RemoveScheduledTask removes the scheduled task
func RemoveScheduledTask() error {
	// Command to check if the scheduled task exists
	schtasksQueryCommand := fmt.Sprintf("schtasks /Query /TN \"%s\"", shared.GlobalConfig.Windows.Task.TaskName)

	// Check if the task already exists
	if _, err := ExecutePowerShellCommand(schtasksQueryCommand); err != nil {
		shared.Log.Debug("Scheduled task doesnt exists", zap.String("task_name", shared.GlobalConfig.Windows.Task.TaskName))
		return nil
	} else {
		schtasksDeleteCommand := fmt.Sprintf("schtasks /Delete /TN \"%s\" /F", shared.GlobalConfig.Windows.Task.TaskName)
		if _, err := ExecutePowerShellCommand(schtasksDeleteCommand); err != nil {
			shared.Log.Error("Failed to delete scheduled task", zap.String("task_name", shared.GlobalConfig.Windows.Task.TaskName), zap.Error(err))
			return err
		} else {
			shared.Log.Info("Scheduled task deleted successfully", zap.String("task_name", shared.GlobalConfig.Windows.Task.TaskName))
		}
		return nil
	}

}

// Generalized function for service manager operations
func ServiceManagerOps(op ServiceOps, filePath string, pkgName string) error {
	//move to powershell instead of cmd
	var cmd *exec.Cmd

	switch op {
	case WinInstall:
		var pkgExeArgs string
		if pkgName == "shawl" {
			shared.Log.Debug("Shawl doesnt need Install logic, returning")
			return nil
		} else if pkgName == "alloy" {
			pkgExeArgs = fmt.Sprintf("run --disable-reporting=true --storage.path=%s --server.http.memory-addr=alloy.internal:%d --server.http.listen-addr=%s:%d %s", shared.GlobalConfig.Alloy.WorkingDir, shared.GlobalConfig.Alloy.Port, shared.GlobalConfig.Alloy.InterfaceIP, shared.GlobalConfig.Alloy.Port, filepath.Join(shared.GlobalConfig.General.ClientDirectory, "config"))
		} else if pkgName == "script_exporter" {
			pkgExeArgs = fmt.Sprintf("-config.file %s -web.listen-address %s:%d", filepath.Join(shared.GlobalConfig.ScriptExporter.HardconfigFile), shared.GlobalConfig.ScriptExporter.InterfaceIP, shared.GlobalConfig.ScriptExporter.Port)
		}
		serviceName := viper.GetString(fmt.Sprintf("%s.service_name", pkgName))
		shawlExePath := filepath.Join(viper.GetString("general.client_directory"), viper.GetString("shawl.windows.exe_name"))
		pkgExePath := filepath.Join(viper.GetString("general.client_directory"), viper.GetString(fmt.Sprintf("%s.windows.exe_name", pkgName)))
		//pkgExeArgs := viper.GetString(fmt.Sprintf("%s.windows.exe_args", pkgName))
		ps_cmd := fmt.Sprintf("sc.exe create %s binPath= \"%s run --name %s -- %s %s\"", serviceName, shawlExePath, serviceName, pkgExePath, pkgExeArgs)
		shared.Log.Debug("Should trigger WinInstall", zap.Any("ps_cmd", ps_cmd))
		cmd = exec.Command("powershell", "-Command", ps_cmd)
		//shared.Log.Debug("Should trigger WinInstall")
	case WinDowngrade:
		//cmd = exec.Command("yum", string(Downgrade), "-y", filepath, "--disablerepo=*", "--noplugins")
		//cmd = exec.Command("powershell", "-Command", "echo Should trigger WinDowngrade")
		shared.Log.Debug("Should trigger WinDowngrade")
		return nil
	case WinUpdate:
		//cmd = exec.Command("yum", "update", "-y", filepath, "--disablerepo=*", "--noplugins")
		//cmd = exec.Command("powershell", "-Command", "echo Should trigger WinUpdate")
		shared.Log.Debug("Should trigger WinUpdate, no")
		return nil
	case WinRemove:
		//cmd = exec.Command("yum", string(Remove), pkgName, "-y", "--disablerepo=*", "--noplugins")
		//cmd = exec.Command("powershell", "-Command", "echo Should trigger WinRemove")
		if pkgName == "shawl" {
			shared.Log.Debug("Shawl doesnt need Remove logic, returning")
			return nil
		}
		serviceName := viper.GetString(fmt.Sprintf("%s.service_name", pkgName))
		ps_cmd := fmt.Sprintf("sc.exe delete %s ", serviceName)
		shared.Log.Debug("Should trigger WinRemove -")
		cmd = exec.Command("powershell", "-Command", ps_cmd)
	default:
		return fmt.Errorf("unknown operation: %s", op)
	}

	// Log the filepath and package name for debugging
	shared.Log.Debug("Executing powershell command", zap.String("operation", string(op)), zap.String("filepath", filePath), zap.String("pkgName", pkgName))

	// Execute the command and capture the output
	psout, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(CleanWhitespace(string(psout)), "1060") {
			shared.Log.Debug("Skipping on Error, when out contains 1060 (service not found)")
			return nil
		} else {
			return fmt.Errorf("command failed: %v, output: %s", err, CleanWhitespace(string(psout)))
		}
	}

	// Log the command output
	shared.Log.Debug("Powershell out", zap.String("psout", CleanWhitespace(string(psout))))
	return nil
}

// Define the type for the package management action
type windowsinstallActionFunc func(op ServiceOps, filepath string, pkgName string) error

// Combined function to handle install, update, downgrade, and remove
func windowsPackageAction(packet PackageVersion, action windowsinstallActionFunc, op ServiceOps) error {
	var filepath string
	var err error

	//till here its okay i think
	// Stop the service if not installing (for update, downgrade, remove)
	if packet.Name == "shawl" && op != WinInstall {
		if viper.IsSet("alloy") {
			_, err = WindowsSCcmdAction(viper.GetString(fmt.Sprintf("%s.service_name", "alloy")), "stop")
			if err != nil {
				shared.Log.Error("Failed to stop service. stopping package operation.", zap.Error(err))
				return err
			}
		}
		if viper.IsSet("script_exporter") {
			_, err = WindowsSCcmdAction(viper.GetString(fmt.Sprintf("%s.service_name", "script_exporter")), "stop")
			if err != nil {
				shared.Log.Error("Failed to stop service. stopping package operation.", zap.Error(err))
				return err
			}
		}
	} else if op != WinInstall {
		_, err = WindowsSCcmdAction(viper.GetString(fmt.Sprintf("%s.service_name", packet.Name)), "stop")
		if err != nil {
			shared.Log.Error("Failed to stop service. stopping package operation.", zap.Error(err))
			return err
		}
	}
	// Fetch the file if it's not a removal operation
	if op != WinRemove {
		if packet.Name == "shawl" {
			filepath, err = FetchFile(JoinURL(shared.GlobalConfig.Api.BaseURL, "/download/"+packet.Endpoint), shared.GlobalConfig.General.ClientDirectory)
			if err != nil {
				shared.Log.Error("FetchFile failed", zap.Error(err))
				return err
			}
		} else {
			filepath, err = FetchFile(JoinURL(shared.GlobalConfig.Api.BaseURL, "/download/"+packet.Endpoint+"/"+shared.GlobalConfig.General.BuildType), shared.GlobalConfig.General.ClientDirectory)
			if err != nil {
				shared.Log.Error("FetchFile failed", zap.Error(err))
				return err
			}
		}
	}
	// Perform the action: install, update, downgrade, or remove
	if op == WinRemove {
		err = action(WinRemove, "", packet.Name)
		if err != nil {
			shared.Log.Error("Failed to remove package", zap.Error(err))
			return err
		}
	} else {
		err = action(op, filepath, packet.Name)
		if err != nil {
			shared.Log.Error("Package action failed", zap.Error(err))
			return err
		}
	}

	// Remove the file if it's not a removal operation
	/*if op != WinRemove {
		err = os.Remove(filepath)
		if err != nil {
			shared.Log.Error("Cleanup failed", zap.Error(err))
			return err
		}
	}*/

	// Apply sysconfig changes if it's not a removal operation
	if op != WinRemove {
		/*err = linuxHardSysconfigChanges(packet)
		if err != nil {
			return err
		}*/

		err = removeConfigAlloyFiles(shared.GlobalConfig.General.ClientDirectory)
		if err != nil {
			return err
		}
	}

	return nil
}

// Wrappers for install, update, downgrade, and remove
func WindowsDownloadAndInstall(packet PackageVersion) error {
	return windowsPackageAction(packet, ServiceManagerOps, WinInstall)
}

func WindowsDownloadAndUpdate(packet PackageVersion) error {
	return windowsPackageAction(packet, ServiceManagerOps, WinUpdate)
}

func WindowsDownloadAndDowngrade(packet PackageVersion) error {
	return windowsPackageAction(packet, ServiceManagerOps, WinDowngrade)
}

func WindowsRemove(packet PackageVersion) error {
	return windowsPackageAction(packet, ServiceManagerOps, WinRemove)
}
func WinuxDeinstall() error {
	if viper.IsSet("alloy") {
		out, err := WindowsSCcmdAction(viper.GetString(fmt.Sprintf("%s.service_name", "alloy")), "stop")
		if err != nil {
			if strings.Contains(out, "1062") {
				shared.Log.Debug("Failed to stop, cause isnt started, all good")
			} else if strings.Contains(out, "1060") {
				shared.Log.Debug("Failed to stop, cause isnt installed, all good")
			} else {
				shared.Log.Error("Failed to stop service. stopping package operation.", zap.Error(err))
				return err
			}
		}
		err = ServiceManagerOps("remove", "", "alloy")
		if err != nil {
			shared.Log.Error("Failed to remove alloy:", zap.Error(err))
		}
		shared.Log.Info("Removed Alloy Service")
		// Attempt to remove the directory and all its contents
		err = os.RemoveAll(shared.GlobalConfig.Alloy.WorkingDir)
		if err != nil {
			shared.Log.Error("Failed to remove directory:", zap.Error(err))
		}

		shared.Log.Info("Directory and its contents removed successfully", zap.Any("dir", shared.GlobalConfig.Alloy.WorkingDir))
	}
	if viper.IsSet("script_exporter") {
		out, err := WindowsSCcmdAction(viper.GetString(fmt.Sprintf("%s.service_name", "script_exporter")), "stop")
		if err != nil {
			if strings.Contains(out, "1062") {
				shared.Log.Debug("Failed to stop, cause isnt started, all good")
			} else if strings.Contains(out, "1060") {
				shared.Log.Debug("Failed to stop, cause isnt installed, all good")
			} else {
				shared.Log.Error("Failed to stop service. stopping package operation.", zap.Error(err))
				return err
			}
		}
		err = ServiceManagerOps("remove", "", "script_exporter")
		if err != nil {
			shared.Log.Error("Failed to remove script_exporter:", zap.Error(err))
		}
		shared.Log.Info("Removed script_exporter Service")
	}
	if viper.IsSet("windows.task.task_name") {
		err := RemoveScheduledTask()
		if err != nil {
			shared.Log.Error("Failed to remove Task:", zap.Error(err))
		}
	}
	// Attempt to remove the directory and all its contents
	err := os.RemoveAll(shared.GlobalConfig.General.ClientDirectory)
	if err != nil {
		shared.Log.Error("Failed to remove directory:", zap.Error(err))
	}

	shared.Log.Info("Directory and its contents removed successfully", zap.Any("dir", shared.GlobalConfig.General.ClientDirectory))
	return nil
}
