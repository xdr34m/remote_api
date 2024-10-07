package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/m/v2/shared"
	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"
)

type ServerAuth struct {
	Username string
	Password string
}

/*var (
	GlobalServerAuth *ServerAuth
	GlobalVerifySSL  bool //std is false if not set!
)*/

func newRestyClient() *resty.Client {
	client := resty.New()

	// Configure SSL verification based on global config
	client.SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: !shared.GlobalConfig.Api.VerifySSL,
	})

	// Set a timeout for the client (30 seconds for example)
	client.SetTimeout(30 * time.Second)
	client.SetRetryCount(0)
	client.SetDebug(false)

	return client
}

// makeHTTPRequest performs the HTTP POST request.
func PostJson(payload interface{}, serverURL string) (map[string]interface{}, error) {
	client := newRestyClient()
	// Create a map to store the response result
	var result map[string]interface{}
	// Make the POST request
	req := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		SetResult(&result)

	// Conditionally set Basic Auth if credentials are provided
	if shared.GlobalConfig.Api.BasicAuth.Username != "" && shared.GlobalConfig.Api.BasicAuth.Password != "" {
		req.SetBasicAuth(shared.GlobalConfig.Api.BasicAuth.Username, shared.GlobalConfig.Api.BasicAuth.Password)
	}
	resp, err := req.Post(serverURL)
	// Handle error
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}

	// Check the HTTP response status
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("error fetching data: %s", resp.Status())
	}

	return result, nil
}

// GetJson performs the HTTP GET request.
func GetJson(serverURL string) (map[string]interface{}, error) {
	client := newRestyClient()
	// Create a map to store the response result
	var result map[string]interface{}
	// Make the GET request
	req := client.R().
		SetHeader("Content-Type", "application/json").
		SetResult(&result)

	// Conditionally set Basic Auth if credentials are provided
	if shared.GlobalConfig.Api.BasicAuth.Username != "" && shared.GlobalConfig.Api.BasicAuth.Password != "" {
		req.SetBasicAuth(shared.GlobalConfig.Api.BasicAuth.Username, shared.GlobalConfig.Api.BasicAuth.Password)
	}
	resp, err := req.Get(serverURL)
	// Handle error
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}

	// Check the HTTP response status
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("error fetching data: %s", resp.Status())
	}

	return result, nil
}
func GetString(serverURL string) (string, error) {
	client := newRestyClient()

	// Make the GET request
	req := client.R().
		SetHeader("Content-Type", "application/json")

		// Conditionally set Basic Auth if credentials are provided
	if shared.GlobalConfig.Api.BasicAuth.Username != "" && shared.GlobalConfig.Api.BasicAuth.Password != "" {
		req.SetBasicAuth(shared.GlobalConfig.Api.BasicAuth.Username, shared.GlobalConfig.Api.BasicAuth.Password)
	}
	resp, err := req.Get(serverURL)
	// Handle error
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %v", err)
	}

	// Check the HTTP response status
	if resp.StatusCode() != 200 {
		return "", fmt.Errorf("error fetching data: %s, %s", resp.Status(), resp.String())
	}

	// Return the response as a string
	return resp.String(), nil
}
func FetchFile(url string, dir string) (string, error) {
	shared.Log.Debug("Fetching file", zap.String("url", url), zap.String("dir", dir))

	client := newRestyClient()

	// Start building the request
	req := client.R()

	// Conditionally set Basic Auth if credentials are provided
	if shared.GlobalConfig.Api.BasicAuth.Username != "" && shared.GlobalConfig.Api.BasicAuth.Password != "" {
		req.SetBasicAuth(shared.GlobalConfig.Api.BasicAuth.Username, shared.GlobalConfig.Api.BasicAuth.Password)
	}
	// Define an error variable to track errors
	var err error
	// Create a temporary file path for the download with a generic name initially
	tempFilePath := filepath.Join(dir, "alloyupdatertmpfile.part")
	defer func() {
		if err != nil {
			// If there was an error, try to delete the temporary file
			if err := os.Remove(tempFilePath); err != nil {
				shared.Log.Warn("Failed to delete temporary file", zap.String("tempFilePath", tempFilePath), zap.Error(err))
			}
		}
	}()
	// Make the GET request and stream the response to the .part file
	resp, err := req.
		SetContext(context.Background()).
		SetOutput(tempFilePath).
		Get(url)

	// Handle download errors
	if err != nil {
		shared.Log.Error("Failed to fetch URL", zap.Error(err))
		return "", fmt.Errorf("failed to fetch URL: %v", err)
	}

	// Check if the response status is OK
	if resp.StatusCode() != http.StatusOK {
		err := fmt.Errorf("failed to download file: %s", resp.Status())
		shared.Log.Error("Download failed", zap.Error(err))
		return "", err
	}

	// Extract the filename from the Content-Disposition header after the GET request
	filename := extractFilename(resp.Header().Get("Content-Disposition"))
	if filename == "" {
		err := fmt.Errorf("filename not found in Content-Disposition header")
		shared.Log.Error("Filename extraction failed", zap.Error(err))
		return "", err
	}

	// Now that the file is downloaded, rename the .part file to the final filename
	finalFilePath := filepath.Join(dir, filename)
	if err := os.Rename(tempFilePath, finalFilePath); err != nil {
		shared.Log.Error("Failed to rename temporary file", zap.Error(err))
		return "", fmt.Errorf("failed to rename temporary file: %v", err)
	}

	return finalFilePath, nil
}

// extractFilename extracts the filename from the Content-Disposition header.
func extractFilename(contentDisposition string) string {
	// Look for the "filename=" part
	if strings.Contains(contentDisposition, "filename=") {
		// Split the header by ';' and find the filename part
		parts := strings.Split(contentDisposition, ";")
		for _, part := range parts {
			trimmedPart := strings.TrimSpace(part)
			if strings.HasPrefix(trimmedPart, "filename=") {
				// Remove "filename=" and trim quotes
				filename := strings.Trim(strings.TrimPrefix(trimmedPart, "filename="), "\"")
				return filename
			}
		}
	}
	return ""
}
