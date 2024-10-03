package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

// Declare global variables
var (
	// General variables
	oprs            string = "rhel"
	sign            string = "none"
	clientDirectory string = "/etc/alloy"

	alloyDebugPort   int    = 10310
	alloyInterfaceIP string = "127.0.0.1"
	alloyUser        string = "alloy"

	scriptExporterInterfaceIP    string = "127.0.0.1"
	scriptExporterPort           int    = 10311
	scriptExporterSysconfigFile  string = "/etc/sysconfig/script_exporter.config"
	scriptExporterHardconfigFile string = "/etc/alloy/files/std_script_exporter_config.yaml"

	// LogRotate, only needed under Linux
	logFile        string = "/var/log/alloy_updater_client.log"
	logMaxSize     int64  = 5 * 1024 * 1024 // 5 MB
	logBackupCount int    = 4
	logMaxAgeDays  int    = 30

	// RHEL-specific variables
	tmpDir                string = "/tmp"                 // tmp dir for RPM download
	buildType             string = "amd64_rpm"            // build type
	serviceName           string = "alloy.service"        // service name
	dataPath              string = "/var/lib/alloy/data"  // path for WAL
	alloySysconfigFile    string = "/etc/sysconfig/alloy" // env vars for unit file
	rpmName               string = "alloy"                // RPM name
	scriptExporterRpmName string = "script_exporter"
	updaterClientName     string = "alloy_updater_client"
	alloyConfigRootDir    string = "/etc/alloy"
	cronCommand           string = fmt.Sprintf("%s/%s >> %s", alloyConfigRootDir, updaterClientName, logFile)
	cronSchedule          string = "*/30 * * * *" // Every 30 minutes
	cronUser              string = "root"
	cronComment           string = "alloy_updater_client" // used to identify cron job

	linuxUID            int = 2065
	linuxGID            int = 2065
	randDelayExecutingS int = 600 // delay execution randomly between 0 to 600 seconds
)

func parseargs() {
	reinstall := flag.Bool("reinstall", false, "if set, deletes alloy and reinstalls it")
	deinstall := flag.Bool("deinstall", false, "if set, deletes alloy")
	debug := flag.Bool("debug", false, "if set uses debug_dir where the script resides and logs debug")
	nodelay := flag.Bool("norandomdelay", false, "if set no sleep before executing")
	flag.Parse()
	fmt.Printf("reinstall: %t, deinstall: %t, debug: %t, nodelay: %t\n", *reinstall, *deinstall, *debug, *nodelay)
}

func changeConfigVariable(filePath, variableName, newValue string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	pattern := regexp.MustCompile(fmt.Sprintf(`(%s\s*=\s*).*`, variableName))
	if pattern.Match(content) {
		newContent := pattern.ReplaceAll(content, []byte(fmt.Sprintf(`$1%s`, newValue)))
		err = os.WriteFile(filePath, newContent, 0644)
		if err != nil {
			fmt.Println("Error writing file:", err)
		}
	} else {
		newContent := append(content, []byte(fmt.Sprintf("\n%s = %s", variableName, newValue))...)
		err = os.WriteFile(filePath, newContent, 0644)
		if err != nil {
			fmt.Println("Error writing file:", err)
		}
	}
}
func getAllFilesWithFilenames(rootDir string) []string {
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
		fmt.Println(err)
	}
	return allFiles
}
func generateFileHash(filePath string, hashAlgorithm string) (string, error) {
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
func fetchServerVersions(oprs, hostname, sign, serverURL string) (map[string]interface{}, error) {
	var requestBody []byte
	if sign != "" {
		requestBody, _ = json.Marshal(map[string]interface{}{
			"hostname":            hostname,
			"operatingsystem":     oprs,
			"need_signed_scripts": sign,
		})
	} else {
		requestBody, _ = json.Marshal(map[string]interface{}{
			"hostname":        hostname,
			"operatingsystem": oprs,
		})
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/check_updates", serverURL), bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(body))
	}

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
