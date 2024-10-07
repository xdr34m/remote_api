package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"example.com/m/v2/shared"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// checkUserAndGroup checks if a user exists with the specified UID and if there is a corresponding group with the same name and GID.
func checkUserAndGroup(username string, expectedUID, expectedGID int) (bool, error) {
	// Get user information
	usr, err := user.Lookup(username)
	if err != nil {
		if err == err.(user.UnknownUserError) {
			// User does not exist, create the user and group
			return createUserAndGroup(username, expectedUID, expectedGID)
		}
		return false, fmt.Errorf("error looking up user: %v", err)
	}
	// Convert UID to int
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return false, fmt.Errorf("error converting user UID: %v", err)
	}

	// Check if the UIDs match
	if uid != expectedUID {
		return false, fmt.Errorf("UID do not match: %v", err)
	}

	// Check if a group exists with the same name
	grp, err := user.LookupGroup(username)
	if err != nil {
		if err == err.(user.UnknownGroupError) {
			return false, nil // Group does not exist
		}
		return false, fmt.Errorf("error looking up group: %v", err)
	}

	// Convert group GID to int
	groupGID, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return false, fmt.Errorf("error converting group GID: %v", err)
	}

	// Check if the GIDs match
	if groupGID != expectedGID {
		return false, fmt.Errorf("UID and GID do not match: %v", err)
	}

	return true, nil // User and group exist with matching UID/GID
}

// createUserAndGroup creates a user and group with the specified username, UID, and GID.
func createUserAndGroup(username string, uid, gid int) (bool, error) {
	// Create group first
	if err := exec.Command("groupadd", "-g", strconv.Itoa(gid), username).Run(); err != nil {
		return false, fmt.Errorf("failed to create group: %v", err)
	}

	// Create user with the specified UID and GID
	if err := exec.Command("useradd", "-u", strconv.Itoa(uid), "-g", username, username).Run(); err != nil {
		return false, fmt.Errorf("failed to create user: %v", err)
	}
	shared.Log.Info("Created User", zap.String("username", username), zap.Int("uid", uid), zap.Int("gid", gid))
	return true, nil // User and group successfully created
}
func LinuxCheckUser() error {
	_, err := checkUserAndGroup(shared.GlobalConfig.Linux.Username, shared.GlobalConfig.Linux.UID, shared.GlobalConfig.Linux.GID)
	if err != nil {
		return err
	}
	return nil
}

// Gets The RPM Version from rpm -q, return Version or "" if not installed.
func LinuxGetRPMVersion(packageName string) (string, error) {
	// Run the rpm command to query the package
	cmd := exec.Command("rpm", "-q", packageName)

	// Get the output from the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If the package is not found, it will return an error
		if strings.Contains(string(output), "is not installed") {
			return "", nil
		} else {
			return "", fmt.Errorf("error checking package: %v\nOutput: %s", err, output)
		}
	}
	// If the package is found, output the result
	//fmt.Printf("DEBUG | %s", string(output))
	pattern := viper.GetString(fmt.Sprintf("%s.linux.version_pattern", packageName))
	version, err := linuxParseVersionRegex(string(output), pattern)
	if err != nil {
		return "", fmt.Errorf("error appling pattern %s to output: %v\nOutput: %s", pattern, err, output)
	}

	return version, nil
}

func removeConfigAlloyFiles(dir string) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil // Skip directories
		}
		if strings.HasPrefix(info.Name(), "config.alloy") { // Check for prefix
			shared.Log.Debug(fmt.Sprintf("Removing file: %s\n", path))
			return os.Remove(path) // Remove the file
		}
		return nil
	})
	return err
}

type YumOperation string

const (
	Install   YumOperation = "localinstall"
	Downgrade YumOperation = "downgrade"
	Update    YumOperation = "update"
	Remove    YumOperation = "remove"
)

// Generalized function for yum package manager operations
func yumPackageManagerOps(op YumOperation, filepath string, pkgName string) error {
	var cmd *exec.Cmd

	switch op {
	case Install:
		cmd = exec.Command("yum", string(Install), "-y", filepath, "--disablerepo=*", "--noplugins")
	case Downgrade:
		cmd = exec.Command("yum", string(Downgrade), "-y", filepath, "--disablerepo=*", "--noplugins")
	case Update:
		cmd = exec.Command("yum", "update", "-y", filepath, "--disablerepo=*", "--noplugins")
	case Remove:
		cmd = exec.Command("yum", string(Remove), pkgName, "-y", "--disablerepo=*", "--noplugins")
	default:
		return fmt.Errorf("unknown operation: %s", op)
	}

	// Log the filepath and package name for debugging
	shared.Log.Debug("Executing yum command", zap.String("operation", string(op)), zap.String("filepath", filepath), zap.String("pkgName", pkgName))

	// Execute the command and capture the output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %v, output: %s", err, CleanWhitespace(string(output)))
	}

	// Log the command output
	shared.Log.Debug("Yum output", zap.String("yumout", CleanWhitespace(string(output))))
	return nil
}

func SystemCTLcommand(servicename string, command string) error {
	// Run the rpm command to query the package
	cmd := exec.Command("systemctl", command, servicename)
	// Get the output from the command
	shared.Log.Debug("systemctl command", zap.Any("command", command))
	output, err := cmd.CombinedOutput()
	if err != nil {
		shared.Log.Warn("systemctl", zap.Any("command", command), zap.Error(err))
		return err
	}
	shared.Log.Debug("", zap.String("ouput", CleanWhitespace(string(output))))
	return nil
}

func linuxHardSysconfigChanges(pkg PackageVersion) error {
	switch pkg.Name {
	case "alloy":
		err := ChangeConfigVariable(viper.GetString(fmt.Sprintf("%s.linux.sysconfig_file", pkg.Name)), "CONFIG_FILE", "\"/etc/alloy/config\"", 0644)
		if err != nil {
			shared.Log.Error("Could not change Sysconfig", zap.Error(err))
			return err
		}
		err = ChangeConfigVariable(viper.GetString(fmt.Sprintf("%s.linux.sysconfig_file", pkg.Name)), "CUSTOM_ARGS", fmt.Sprintf("\"--disable-reporting --server.http.memory-addr=alloy.internal:%d --server.http.listen-addr=%s:%d\"", shared.GlobalConfig.Alloy.Port, shared.GlobalConfig.Alloy.InterfaceIP, shared.GlobalConfig.Alloy.Port), 0644)
		if err != nil {
			shared.Log.Error("Could not change Sysconfig", zap.Error(err))
			return err
		}
	case "script_exporter":
		err := ChangeConfigVariable(viper.GetString(fmt.Sprintf("%s.linux.sysconfig_file", pkg.Name)), "CUSTOM_ARGS", fmt.Sprintf("-config.file '%s' -web.listen-address '%s:%d'", shared.GlobalConfig.ScriptExporter.HardconfigFile, shared.GlobalConfig.ScriptExporter.InterfaceIP, shared.GlobalConfig.ScriptExporter.Port), 0644)
		if err != nil {
			shared.Log.Error("Could not change Sysconfig", zap.Error(err))
			return err
		}
	}
	return nil
}

// Define the type for the package management action
type linuxinstallActionFunc func(op YumOperation, filepath string, pkgName string) error

// Combined function to handle install, update, downgrade, and remove
func linuxPackageAction(packet PackageVersion, action linuxinstallActionFunc, op YumOperation) error {
	var filepath string
	var err error

	// Fetch the file if it's not a removal operation
	if op != Remove {
		filepath, err = FetchFile(JoinURL(shared.GlobalConfig.Api.BaseURL, "/download/"+packet.Endpoint+"/"+shared.GlobalConfig.General.BuildType), shared.GlobalConfig.Linux.TmpDir)
		if err != nil {
			shared.Log.Error("FetchFile failed", zap.Error(err))
			return err
		}
	}

	// Stop the service if not installing (for update, downgrade, remove)
	if op != Install {
		err = SystemCTLcommand(viper.GetString(fmt.Sprintf("%s.service_name", packet.Name)), "stop")
		if err != nil {
			shared.Log.Warn("Failed to stop service. Continuing with package operation.", zap.Error(err))
		}
	}

	// Perform the action: install, update, downgrade, or remove
	if op == Remove {
		err = action(Remove, "", packet.Name)
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
	if op != Remove {
		err = os.Remove(filepath)
		if err != nil {
			shared.Log.Error("Cleanup failed", zap.Error(err))
			return err
		}
	}

	// Apply sysconfig changes if it's not a removal operation
	if op != Remove {
		err = linuxHardSysconfigChanges(packet)
		if err != nil {
			return err
		}

		err = removeConfigAlloyFiles(shared.GlobalConfig.General.ClientDirectory)
		if err != nil {
			return err
		}
	}

	return nil
}

// Wrappers for install, update, downgrade, and remove
func linuxDownloadAndInstall(packet PackageVersion) error {
	return linuxPackageAction(packet, yumPackageManagerOps, Install)
}

func linuxDownloadAndUpdate(packet PackageVersion) error {
	return linuxPackageAction(packet, yumPackageManagerOps, Update)
}

func linuxDownloadAndDowngrade(packet PackageVersion) error {
	return linuxPackageAction(packet, yumPackageManagerOps, Downgrade)
}

func LinuxRemove(packet PackageVersion) error {
	return linuxPackageAction(packet, yumPackageManagerOps, Remove)
}

// PackageResult holds the result of processing a package
type PackageResult struct {
	Name   string // Name of the package
	Action string // Action performed (install, update, downgrade, etc.)
	Error  error  // Any error that occurred during processing
}

func LinuxDeinstall() error {
	if viper.IsSet("alloy") {
		err := yumPackageManagerOps("remove", "", "alloy")
		if err != nil {
			shared.Log.Error("Failed to remove alloy:", zap.Error(err))
		}
		shared.Log.Info("Removed Alloy")
		// Attempt to remove the directory and all its contents
		err = os.RemoveAll(shared.GlobalConfig.Alloy.WorkingDir)
		if err != nil {
			shared.Log.Error("Failed to remove directory:", zap.Error(err))
		}

		shared.Log.Info("Directory and its contents removed successfully", zap.Any("dir", shared.GlobalConfig.Alloy.WorkingDir))
	}
	if viper.IsSet("script_exporter") {
		err := yumPackageManagerOps("remove", "", "script_exporter")
		if err != nil {
			shared.Log.Error("Failed to remove script_exporter:", zap.Error(err))
		}
		shared.Log.Info("Removed script_exporter")
	}
	if viper.IsSet("linux.cron") {
		err := DeleteCronJobForUser()
		if err != nil {
			shared.Log.Error("Failed to delete cron File:", zap.Error(err))
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
func SetFileAttributes(filePath string, fileattrs FileAttributes) error {
	// Change file permissions
	if err := os.Chmod(filePath, fileattrs.FileMode); err != nil {
		return err // Return error if unable to set file permissions
	}

	// Change file ownership (UserID and GroupID)
	if err := os.Chown(filePath, fileattrs.UserID, fileattrs.GroupID); err != nil {
		return err // Return error if unable to set file ownership
	}
	return nil
}

// InstallCronJobForUser installs a cron job for a specific user by creating a cron file.
func InstallCronJobForUser() error {
	cronFilePath := shared.GlobalConfig.Linux.Cron.File
	cronDir := filepath.Dir(cronFilePath) // Get the directory of the cron file

	// Check if the cron directory exists
	if _, err := os.Stat(cronDir); os.IsNotExist(err) {
		// Directory does not exist; create it
		if err := os.MkdirAll(cronDir, 0700); err != nil { // Ensure the directory and permissions
			return fmt.Errorf("failed to create cron directory: %w", err)
		}
		// Log only when the directory is newly created
		shared.Log.Info("Cron directory created", zap.String("cron_dir", cronDir))
	}

	// Check if the cron file exists; if not, create it
	if _, err := os.Stat(cronFilePath); os.IsNotExist(err) {
		shared.Log.Info("Cron file does not exist; creating", zap.String("cron_file", cronFilePath))
		if err := os.WriteFile(cronFilePath, []byte("# Cron jobs for alloy\n"), 0700); err != nil {
			return fmt.Errorf("failed to create cron file: %w", err)
		}
	}

	// Create the cron job entry
	newCronJob := fmt.Sprintf("%s %s %s # %s\n", shared.GlobalConfig.Linux.Cron.Schedule, shared.GlobalConfig.Linux.Cron.User, shared.GlobalConfig.Linux.Cron.Command, shared.GlobalConfig.Linux.Cron.Comment)

	// Check if the cron job already exists in the cron file
	if cronJobExists(cronFilePath, newCronJob) {
		shared.Log.Debug("Cron job already exists; skipping installation", zap.String("comment", shared.GlobalConfig.Linux.Cron.Comment), zap.String("cron_file", cronFilePath))
		return nil
	}

	// Append the new cron job to the existing cron file
	if err := appendCronJob(cronFilePath, newCronJob); err != nil {
		return err
	}

	shared.Log.Info("Cron job installed successfully", zap.String("comment", shared.GlobalConfig.Linux.Cron.Comment), zap.String("user", shared.GlobalConfig.Linux.Cron.User), zap.String("schedule", shared.GlobalConfig.Linux.Cron.Schedule), zap.String("command", shared.GlobalConfig.Linux.Cron.Command))
	return nil
}

// DeleteCronJobForUser deletes the cron job file entirely.
func DeleteCronJobForUser() error {
	// Check if the cron file exists before attempting to delete it
	if _, err := os.Stat(shared.GlobalConfig.Linux.Cron.File); os.IsNotExist(err) {
		shared.Log.Debug("Cron file does not exist; nothing to delete", zap.String("cron_file", shared.GlobalConfig.Linux.Cron.File))
		return nil
	}

	// Remove the cron file
	if err := os.Remove(shared.GlobalConfig.Linux.Cron.File); err != nil {
		return fmt.Errorf("failed to delete cron file: %w", err)
	}

	shared.Log.Info("Cron job file deleted successfully", zap.String("cron_file", shared.GlobalConfig.Linux.Cron.File))
	return nil
}

// appendCronJob appends a new cron job to the cron file.
func appendCronJob(cronFile, cronJob string) error {
	f, err := os.OpenFile(cronFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600) // Ensure restricted permissions
	if err != nil {
		return fmt.Errorf("failed to open cron file for appending: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(cronJob); err != nil {
		return fmt.Errorf("failed to write new cron job: %w", err)
	}

	return nil
}

// cronJobExists checks if the specified cron job already exists in the cron file.
func cronJobExists(cronFile string, newJob string) bool {
	file, err := os.Open(cronFile)
	if err != nil {
		shared.Log.Error("Failed to open cron file for reading", zap.String("cron_file", cronFile), zap.Error(err))
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Check if the new job matches any existing line in the cron file
		if strings.TrimSpace(line) == strings.TrimSpace(newJob) {
			return true
		}
	}

	if err := scanner.Err(); err != nil {
		shared.Log.Error("Error reading cron file", zap.String("cron_file", cronFile), zap.Error(err))
		return false
	}

	return false
}
func linuxParseVersionRegex(input, pattern string) (string, error) {
	// Compile the regex pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to compile regex pattern: %w", err)
	}

	// Find the first match in the input string
	match := re.FindStringSubmatch(input)
	if len(match) < 2 {
		return "", fmt.Errorf("no matches found")
	}

	// Return the captured version number (group 1)
	return match[1], nil
}
