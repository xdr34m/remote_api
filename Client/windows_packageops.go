//go:build windows
// +build windows

// ProcessPackageVersions checks the installed packages, compares versions, and updates or installs as necessary.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"example.com/m/v2/shared"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func ProcessPackageVersions(remoteVersionRes map[string]interface{}) ([]PackageResult, error) {
	var versions []PackageVersion
	var results []PackageResult // To hold results of package processing
	shared.Log.Debug("Processing Package Versions for Windows")
	if (viper.IsSet("script_exporter") || viper.IsSet("alloy")) && !viper.IsSet("shawl") {
		shared.Log.Error("Missing Shawl configs, cant use pkg install on script_exporter or alloy without it")
		return []PackageResult{}, fmt.Errorf("missing Shawl configs, cant use pkg install on script_exporter or alloy without it")

	}
	if viper.IsSet("shawl") {
		version, err := windowsGetPKGVersion("shawl")
		if err != nil {
			shared.Log.Error("Error checking Version of shawl", zap.Error(err))
			results = append(results, PackageResult{Name: "shawl", Action: "check_version", Error: err})
		} else {
			shared.Log.Debug("shawl version fetched", zap.Any("version", version))
			versions = append(versions, PackageVersion{Name: "shawl", Version: version, Endpoint: "shawl_service"})
		}
	}
	// Check for "alloy" package
	if viper.IsSet("alloy") {
		version, err := windowsGetPKGVersion("alloy")
		if err != nil {
			shared.Log.Error("Error checking Version of alloy", zap.Error(err))
			results = append(results, PackageResult{Name: "alloy", Action: "check_version", Error: err})
		} else {
			shared.Log.Debug("Alloy version fetched", zap.Any("version", version))
			versions = append(versions, PackageVersion{Name: "alloy", Version: version, Endpoint: "alloy_installer"})
		}
	}

	// Check for "script_exporter" package
	if viper.IsSet("script_exporter") {
		version, err := windowsGetPKGVersion("script_exporter")
		if err != nil {
			shared.Log.Error("Error checking Version of script_exporter", zap.Error(err))
			results = append(results, PackageResult{Name: "script_exporter", Action: "check_version", Error: err})
		} else {
			shared.Log.Debug("Script Exporter version fetched", zap.Any("version", version))
			versions = append(versions, PackageVersion{Name: "script_exporter", Version: version, Endpoint: "script_exporter"})
		}
	}

	// TODO - is still on linux!!!
	// Compare versions
	for _, pkg := range versions {
		packagename := pkg.Name

		// Check if the version is empty
		if pkg.Version == "" {
			shared.Log.Debug("Local not found, trigger download & installing", zap.Any("pkg.Name", pkg.Name))
			err := WindowsDownloadAndInstall(pkg)
			if err != nil {
				shared.Log.Error("Error Downloading and Installing", zap.Any("packagename", packagename), zap.Error(err))
				results = append(results, PackageResult{Name: pkg.Name, Action: "install", Error: err})
			} else {
				results = append(results, PackageResult{Name: pkg.Name, Action: "install", Error: nil}) // Only add if successful
			}
			continue
		}

		// Fetch remote version
		remoteVersionInterface, exists := remoteVersionRes[packagename]
		if !exists {
			shared.Log.Error("Package does not exist in remote", zap.String("packagename", packagename))
			results = append(results, PackageResult{Name: pkg.Name, Action: "not_found", Error: nil})
			continue // Skip if the package is not found
		}

		remoteVersion, ok := remoteVersionInterface.(string)
		if !ok {
			shared.Log.Error("Could not convert remote version to string", zap.String("packagename", packagename))
			results = append(results, PackageResult{Name: pkg.Name, Action: "conversion_error", Error: nil})
			continue // Skip if the conversion fails
		}

		// Extract and compare versions
		remoteVersion = ExtractVersion(remoteVersion)
		localVersion := ExtractVersion(pkg.Version)

		// Check if the remote version is greater or lower
		if IsVersionGreater(remoteVersion, localVersion) {
			shared.Log.Debug("Remote version is greater", zap.Any("packagename", pkg.Name), zap.Any("remoteVersion", remoteVersion), zap.Any("localVersion", localVersion))
			err := WindowsDownloadAndUpdate(pkg)
			if err != nil {
				shared.Log.Error("Failed on windowsDownloadAndUpdate", zap.Error(err))
				results = append(results, PackageResult{Name: pkg.Name, Action: "update", Error: err})
			} else {
				results = append(results, PackageResult{Name: pkg.Name, Action: "update", Error: nil}) // Only add if successful
			}
		} else if IsVersionLower(remoteVersion, localVersion) {
			shared.Log.Debug("Remote version is lower", zap.Any("packagename", pkg.Name), zap.Any("remoteVersion", remoteVersion), zap.Any("localVersion", localVersion))
			err := WindowsDownloadAndDowngrade(pkg)
			if err != nil {
				shared.Log.Error("Failed on windowsDownloadAndDowngrade", zap.Error(err))
				results = append(results, PackageResult{Name: pkg.Name, Action: "downgrade", Error: err})
			} else {
				results = append(results, PackageResult{Name: pkg.Name, Action: "downgrade", Error: nil}) // Only add if successful
			}
		} else {
			shared.Log.Debug("Versions are in sync", zap.Any("packagename", pkg.Name), zap.Any("remoteVersion", remoteVersion), zap.Any("localVersion", localVersion))
			results = append(results, PackageResult{Name: pkg.Name, Action: "insync(noaction)", Error: nil}) // No error for sync
		}
	}

	return results, nil // Return results and nil error if there are no fatal errors
}
func IsRootUser() bool {
	ps_command := "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] \"Administrator\")"
	out, err := ExecutePowerShellCommand(ps_command)
	if err != nil {
		shared.Log.Error("Error running powershell command", zap.Error(err))
		return false
	}
	my_bool, err := ConvertStringToBool(out)
	if err != nil {
		shared.Log.Error("Error ConvertStringToBool", zap.Error(err))
		return false
	}
	return my_bool

}

/*
	func IsSystemUser(user *user.User) bool {
		// On Windows, the SID for SYSTEM is commonly "S-1-5-18"
		return user.Uid == "S-1-5-18"
	}
*/

// returns the LocalVersions/or "" if no exe found
func windowsGetPKGVersion(pkgName string) (string, error) {
	pkgBaseConfig := fmt.Sprintf("%s.windows", pkgName)
	if !viper.IsSet(fmt.Sprintf("%s.exe_name", pkgBaseConfig)) || !viper.IsSet(fmt.Sprintf("%s.version_pattern", pkgBaseConfig)) || !viper.IsSet(fmt.Sprintf("%s.version_opt", pkgBaseConfig)) {
		err := fmt.Errorf("error getting exe_name or version_pattern or version_opt of pkg (missing configitems)")
		shared.Log.Error("", zap.Error(err), zap.Any("pkgName", pkgName))
		return "", err
	}
	pkgExeName := viper.GetString(fmt.Sprintf("%s.exe_name", pkgBaseConfig))
	pkgVersionPattern := viper.GetString(fmt.Sprintf("%s.version_pattern", pkgBaseConfig))
	pkgExePath := filepath.Join(shared.GlobalConfig.General.ClientDirectory, pkgExeName)
	exists, err := fileExists(pkgExePath)
	if err != nil {
		return "", err
	}
	if !exists {
		shared.Log.Debug("Pkg doesnt exist", zap.Any("pkgExePath", pkgExePath))
		return "", nil
	}
	cmd := fmt.Sprintf("%s %s", pkgExePath, viper.Get(fmt.Sprintf("%s.version_opt", pkgBaseConfig)))

	out, err := ExecutePowerShellCommand(cmd)
	if err != nil {
		shared.Log.Error("Powershell cmd failed to get Version for pkg", zap.Any("pkgName", pkgName), zap.Error(err), zap.Any("cmd", cmd))
		return "", err
	}
	shared.Log.Debug("Powershell out get Version for pkg", zap.Any("out", out), zap.Any("pkgName", pkgName))
	version, err := windowsParseVersionRegex(out, pkgVersionPattern)
	if err != nil {
		shared.Log.Error("Failed to parse Version", zap.Any("Pattern", pkgVersionPattern), zap.Error(err))
		return "", err
	}

	return version, nil

}
func fileExists(filepath string) (bool, error) {
	_, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, so it's not an error worth logging in this case
			return false, nil
		}
		// Log the error if it's not related to the file not existing
		shared.Log.Error("error checking if file exists", zap.Error(err))
		return false, err
	}
	return true, nil
}
func windowsParseVersionRegex(input, pattern string) (string, error) {
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
