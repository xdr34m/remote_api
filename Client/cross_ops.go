package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"example.com/m/v2/shared"
	"go.uber.org/zap"
)

func CheckCurrentUserRoot() error {
	if !IsRootUser() {
		return fmt.Errorf("not run as root User")
	}
	return nil
}

// creates dir at path, sets linux perms on params, sets windows perms hardcoded to ACL SYSTEM and Administrators(Localized)
func EnsurePathExistswithPerms(path string, perm os.FileMode, user Usr) error {
	// Check if the path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create the directory along with any necessary parent directories
		err := os.MkdirAll(path, perm)
		if err != nil {
			shared.Log.Error("failed to create directory", zap.Error(err))
			return err
		}
	} else if err != nil {
		shared.Log.Error("error accessing directory", zap.Error(err))
		return err
	}
	switch shared.OSFacts["os"] {
	case "linux":
		err := os.Chown(path, user.Uid, user.Gid)
		if err != nil {
			shared.Log.Error("failed to set user/grp", zap.Error(err))
			return err
		}

		err = os.Chmod(path, perm)
		if err != nil {
			shared.Log.Error("failed to set permissions", zap.Error(err))
			return err
		}
	case "windows":
		locale := getOSLanguage()
		var adminLocalized string
		switch locale {
		case "de-DE":
			adminLocalized = "Administratoren"
		default:
			adminLocalized = "Administrators"
		}
		ps_script := fmt.Sprintf(`
			$sm_path = '%s'
			$sm_path_acls = Get-Acl -Path $sm_path
			$sm_path_acls.SetAccessRuleProtection($true, $false)
			
			# SYSTEM
			$identity = "SYSTEM"
			$fsAcRArgs = $identity, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
			$fsAcR = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fsAcRArgs
			$sm_path_acls.SetAccessRule($fsAcR)

			# Administrators
			#Care switch for english installs
			$identity = "%s"
			$fsAcRArgs = $identity, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
			$fsAcR = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fsAcRArgs
			$sm_path_acls.SetAccessRule($fsAcR)
						
			Set-Acl -Path $sm_path -AclObject $sm_path_acls
    `, path, adminLocalized)
		//REMEMBER TO CHANGE ADMIN NAME TO ENGLISH
		out, err := ExecutePowerShellCommand(ps_script)
		if err != nil {
			shared.Log.Error("Error setting ACL via PS", zap.Error(err))
		} else {
			shared.Log.Debug("ACL SET!", zap.Any("out", out))
		}
	}

	return nil
}

// Parse version string into a slice of integers
func parseVersion(version string) []int {
	// Use a regular expression to extract version numbers
	re := regexp.MustCompile(`(\d+)`)
	matches := re.FindAllString(version, -1)

	// Create a slice to hold the parsed version integers
	parsed := make([]int, len(matches))
	for i, part := range matches {
		var v int
		fmt.Sscanf(part, "%d", &v) // Safely parse each part into an integer
		parsed[i] = v
	}
	return parsed
}

// Compare two version slices
func compareVersions(v1, v2 []int) int {
	// Compare each part of the version slice
	for i := 0; i < len(v1) && i < len(v2); i++ {
		if v1[i] > v2[i] {
			return 1 // v1 is greater
		} else if v1[i] < v2[i] {
			return -1 // v2 is greater
		}
	}

	// If we reached here, they are equal up to the length of the shorter version
	if len(v1) > len(v2) {
		return 1 // v1 is longer, hence greater
	} else if len(v1) < len(v2) {
		return -1 // v2 is longer, hence greater
	}
	return 0 // Both versions are equal
}

// Check if version1 is greater than version2
func IsVersionGreater(version1, version2 string) bool {
	return compareVersions(parseVersion(version1), parseVersion(version2)) > 0
}

// Check if version1 is lower than version2
func IsVersionLower(version1, version2 string) bool {
	return compareVersions(parseVersion(version1), parseVersion(version2)) < 0
}

// ExtractVersion extracts the main version and the immediate release number from the version string.
func ExtractVersion(version string) string {
	// Use a regular expression to match the version format
	re := regexp.MustCompile(`(\d+\.\d+(\.\d+)?(-\d+)?)`) // Matches patterns like 1.2, 1.2-1, 1.4.2, etc.

	matches := re.FindStringSubmatch(version)
	if len(matches) > 0 {
		return matches[0] // Return the first match which includes version and immediate release
	}
	return version // If no match found, return the original string
}

// FileOperation represents an operation performed on a local file.
type FileOperation struct {
	Action string // Action taken (downloaded, deleted, created)
	File   string // File path
	Error  error  // Error, if any
}

// SyncLocalWithRemote synchronizes the local file versions with the remote ones.
func SyncLocalWithRemote(localVersions, remoteVersions map[string]interface{}, clientDirectory string) ([]FileOperation, error) {
	var operations []FileOperation // To collect information about operations

	// Extract local directories safely
	localDirs, ok := localVersions["dirs"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("localVersions['dirs'] is not a map or is nil")
	}

	// Iterate over local versions
	for localDir, localFiles := range localDirs {
		remoteDirs, ok := remoteVersions["dirs"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("remoteVersions['dirs'] is not a map or is nil")
		}

		remoteFiles, exists := remoteDirs[localDir].(map[string]interface{})
		if !exists {
			shared.Log.Debug(fmt.Sprintf("Directory %s does not exist in remote, skipping", localDir))
			continue // Skip directories that do not exist in remote
		}

		shared.Log.Debug("some debugging in Sync", zap.String("localDir", localDir))

		// Ensure localFiles is a map
		localFilesMap, ok := localFiles.(map[string]interface{})
		if !ok {
			shared.Log.Error(fmt.Sprintf("localFiles for %s is not in the expected format", localDir))
			continue
		}

		// Process local files
		for filename, localHash := range localFilesMap {
			remoteHash, exists := remoteFiles[filename]
			localFilePath := filepath.Join(clientDirectory, localDir, filename)

			if exists {
				// If file exists in both local and remote, check hashes
				if localHash != remoteHash {
					// Hashes differ, download new file
					urlencoded := JoinURL(shared.GlobalConfig.Api.BaseURL, fmt.Sprintf("download/files/%s/%s/%s/%s/%s", shared.GlobalConfig.General.ClientType, shared.OSFacts["hostname"], localDir, shared.OSFacts["signed"], filename))
					if _, err := FetchFile(urlencoded, filepath.Dir(localFilePath)); err != nil {
						operations = append(operations, FileOperation{Action: "replacing", File: localFilePath, Error: err})
					} else {
						operations = append(operations, FileOperation{Action: "replacing", File: localFilePath})
					}
				}
			} else {
				// Local file doesn't exist in remote, delete it
				if err := os.Remove(localFilePath); err != nil {
					operations = append(operations, FileOperation{Action: "deleting", File: localFilePath, Error: err})
				} else {
					operations = append(operations, FileOperation{Action: "deleting", File: localFilePath})
				}
			}
		}

		// Check for remote files that are not local
		for filename := range remoteFiles {
			if _, exists := localFilesMap[filename]; !exists {
				// File exists in remote but not locally, download and create it
				remoteFilePath := filepath.Join(clientDirectory, localDir, filename)

				// Download the file
				urlencoded := JoinURL(shared.GlobalConfig.Api.BaseURL, fmt.Sprintf("download/files/%s/%s/%s/%s/%s", shared.GlobalConfig.General.ClientType, shared.OSFacts["hostname"], localDir, shared.OSFacts["signed"], filename))
				downloaded_filepath, err := FetchFile(urlencoded, filepath.Dir(remoteFilePath))
				if err != nil {
					operations = append(operations, FileOperation{Action: "creating", File: remoteFilePath, Error: err})
					continue // Skip setting attributes if download fails
				}
				if shared.OSFacts["os"] != "windows" {
					// Set file attributes after download
					fileattrs := FileAttributes{
						UserID:   0,
						GroupID:  shared.GlobalConfig.Linux.GID,
						FileMode: 0640,
					}
					err = SetFileAttributes(downloaded_filepath, fileattrs)
					if err != nil {
						operations = append(operations, FileOperation{Action: "creating", File: remoteFilePath, Error: err})
					} else {
						operations = append(operations, FileOperation{Action: "creating", File: remoteFilePath})
					}
				}
			}
		}
	}

	// Make all files in the scripts directory executable
	scriptsDir := filepath.Join(clientDirectory, "scripts")
	// Walk through the files in the scripts directory
	err := filepath.Walk(scriptsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing file %s: %w", path, err) // Return the error to the caller
		}

		// Skip directories; we only want to change file permissions
		if info.IsDir() {
			return nil
		}

		// Get the current permissions
		currentPerms := info.Mode().Perm()

		// Modify permissions to ensure owner and group can execute
		newPerms := currentPerms | 0110 // Set owner and group execute permission

		// Change permission of the file
		if err := os.Chmod(path, newPerms); err != nil {
			return fmt.Errorf("error setting file %s to executable for owner and group: %w", path, err) // Return the error to the caller
		}

		// Successfully changed permissions
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking the scripts directory %s: %w", scriptsDir, err) // Return the error to the caller
	}

	return operations, nil
}
func getOSLanguage() string {
	//REMEMBER TO CHANGE ADMIN NAME TO ENGLISH

	out, err := ExecutePowerShellCommand("(Get-WinSystemLocale).Name")
	if err != nil {
		shared.Log.Warn("Could not get SystemLocale setting to default en-US", zap.Error(err))
		return "de-US"
	} else {
		shared.Log.Debug("Got SystemLocale", zap.Any("out", out))
		switch out {
		case "de-DE":
			return "de-DE"
		default:
			return "de-US"
		}
	}
}
