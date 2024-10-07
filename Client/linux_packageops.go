//go:build linux
// +build linux

// ProcessPackageVersions checks the installed packages, compares versions, and updates or installs as necessary.
package main

import (
	"os"
	"strings"

	"example.com/m/v2/shared"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func ProcessPackageVersions(remoteVersionRes map[string]interface{}) ([]PackageResult, error) {
	var versions []PackageVersion
	var results []PackageResult // To hold results of package processing

	// Check for "alloy" package
	if viper.IsSet("alloy") {
		version, err := LinuxGetRPMVersion("alloy")
		if err != nil {
			shared.Log.Error("Error checking RPM Version of alloy", zap.Error(err))
			results = append(results, PackageResult{Name: "alloy", Action: "check_version", Error: err})
		} else {
			shared.Log.Debug("Alloy version fetched", zap.Any("version", version))
			versions = append(versions, PackageVersion{Name: "alloy", Version: version, Endpoint: "alloy_installer"})
		}
	}

	// Check for "script_exporter" package
	if viper.IsSet("script_exporter") {
		version, err := LinuxGetRPMVersion("script_exporter")
		if err != nil {
			shared.Log.Error("Error checking RPM Version of script_exporter", zap.Error(err))
			results = append(results, PackageResult{Name: "script_exporter", Action: "check_version", Error: err})
		} else {
			shared.Log.Debug("Script Exporter version fetched", zap.Any("version", version))
			versions = append(versions, PackageVersion{Name: "script_exporter", Version: version, Endpoint: "script_exporter"})
		}
	}

	// Compare versions
	for _, pkg := range versions {
		packagename := strings.Split(pkg.Version, "-")[0]

		// Check if the version is empty
		if pkg.Version == "" {
			shared.Log.Debug("Local not found, trigger download & installing", zap.Any("pkg.Name", pkg.Name))
			err := linuxDownloadAndInstall(pkg)
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
			err := linuxDownloadAndUpdate(pkg)
			if err != nil {
				shared.Log.Error("Failed on linuxDownloadAndUpdate", zap.Error(err))
				results = append(results, PackageResult{Name: pkg.Name, Action: "update", Error: err})
			} else {
				results = append(results, PackageResult{Name: pkg.Name, Action: "update", Error: nil}) // Only add if successful
			}
		} else if IsVersionLower(remoteVersion, localVersion) {
			shared.Log.Debug("Remote version is lower", zap.Any("packagename", pkg.Name), zap.Any("remoteVersion", remoteVersion), zap.Any("localVersion", localVersion))
			err := linuxDownloadAndDowngrade(pkg)
			if err != nil {
				shared.Log.Error("Failed on linuxDownloadAndDowngrade", zap.Error(err))
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
	eUid := os.Geteuid()
	//fmt.Printf("eUid %v", eUid)
	return eUid == 0
}
