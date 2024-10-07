package main

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"example.com/m/v2/shared"
	"go.uber.org/zap"
)

// FileAttributes holds the user ID, group ID, and file permissions.
type FileAttributes struct {
	UserID   int
	GroupID  int
	FileMode fs.FileMode
}

func GenerateFileHash(filePath string, hashAlgorithm string) (string, error) {
	var hashFunc hash.Hash
	switch hashAlgorithm {
	case "sha256":
		hashFunc = sha256.New()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", hashAlgorithm)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buf := make([]byte, 8192)
	for {
		n, err := file.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		hashFunc.Write(buf[:n])
	}

	return fmt.Sprintf("%x", hashFunc.Sum(nil)), nil
}

// AddNestedKey adds a value to a nested map structure.
func addNestedKey(dictionary map[string]interface{}, keys []string, value interface{}) {
	subDict := dictionary
	for _, key := range keys[:len(keys)-1] {
		if _, exists := subDict[key]; !exists {
			subDict[key] = make(map[string]interface{})
		}
		subDict = subDict[key].(map[string]interface{})
	}
	subDict[keys[len(keys)-1]] = value
}

// GetLocalVersions collects hashes of files in the specified subdirectories and includes empty subdirectories.
func GetLocalVersions(directoryToWatch string, subDirs []string) (map[string]interface{}, error) {
	localFileVersions := make(map[string]interface{})

	// Iterate over each subdirectory provided
	for _, subDir := range subDirs {
		rootDir := filepath.Join(directoryToWatch, subDir)

		// Check if the directory exists
		if _, err := os.Stat(rootDir); os.IsNotExist(err) {
			shared.Log.Warn("Subdirectory does not exist", zap.String("subDir", rootDir))
			continue // Skip this subdirectory if it doesn't exist
		}

		// Add the empty directory to the results
		addNestedKey(localFileVersions, []string{"dirs", subDir}, make(map[string]interface{}))

		// Walk through the files in the specified subdirectory
		err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				shared.Log.Error("Error walking the directory", zap.String("path", path), zap.Error(err))
				return nil // Skip this path
			}

			// Skip directories and only process files at the immediate level
			if info.IsDir() {
				if path != rootDir { // Ignore subdirectories, only consider the root of the current subDir
					return filepath.SkipDir // Skip this directory entirely
				}
				return nil // Skip processing for empty subdirectory
			}

			// Ignore specific files
			if info.Name() == ".env" || (len(info.Name()) > 4 && info.Name()[:4] == "cus_") {
				return nil
			}

			// Generate file hash and add to localFileVersions
			fileHash, err := GenerateFileHash(path, "sha256")
			if err != nil {
				shared.Log.Error("Error generating hash for file", zap.String("file", path), zap.Error(err))
				return nil // Skip this file and continue
			}

			folder := filepath.Base(rootDir) // Use the name of the current subdirectory
			addNestedKey(localFileVersions, []string{"dirs", folder, info.Name()}, fileHash)

			return nil
		})

		if err != nil {
			shared.Log.Error("Error walking the subdirectory", zap.String("subDir", rootDir), zap.Error(err))
			return nil, err
		}
	}

	shared.Log.Debug("Local file versions collected", zap.Any("local_file_versions", localFileVersions))
	return localFileVersions, nil
}
func GetAllFilesWithFilenames(rootDir string) ([]string, error) {
	var allFiles []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			allFiles = append(allFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return allFiles, nil
}

// changeConfigVariable changes the value of a variable in a config file or adds it if it doesn't exist maybe execute everytime, in case it was written partially
func ChangeConfigVariable(filePath string, variableName string, newValue string, perm fs.FileMode) error {
	// Read the content of the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Convert content to string for processing
	contentStr := string(content)

	// Create a regex pattern to find the variable
	pattern := fmt.Sprintf(`(%s\s*=\s*).*`, regexp.QuoteMeta(variableName))
	re := regexp.MustCompile(pattern)

	// Check if the variable exists
	if re.MatchString(contentStr) {
		// Replace the existing variable value
		newContent := re.ReplaceAllString(contentStr, fmt.Sprintf(`$1%s`, newValue))
		return writeToFile(filePath, newContent, perm)
	} else {
		// If it doesn't exist, append it to the content
		newContent := contentStr + fmt.Sprintf("\n%s = %s\n", variableName, newValue)
		return writeToFile(filePath, newContent, perm)
	}
}

// writeToFile writes the new content to the file
func writeToFile(filePath string, content string, perm fs.FileMode) error {
	err := os.WriteFile(filePath, []byte(content), perm)
	if err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	return nil
}
func CreateFile(filePath string, fileattrs FileAttributes) error { //unused
	// Create the file if it doesn't exist
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		file, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer file.Close()
		//fmt.Println("Creating file:", filePath)

		// Set file permissions to perm
		if err := os.Chmod(filePath, fileattrs.FileMode); err != nil {
			return err
		}
		// Set file ownership (user: attrs.UserID, group: attrs.GroupID)
		if err := os.Chown(filePath, fileattrs.UserID, fileattrs.GroupID); err != nil {
			return err
		}
		shared.Log.Debug("Set file attributes", zap.String("file", filePath), zap.Any("fileattrs", fileattrs))
	}
	return nil
}
