package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"example.com/m/v2/shared"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Function to join base URL and endpoint
func JoinURL(base, endpoint string) string {
	// Parse the base URL
	u, err := url.Parse(base)
	if err != nil {
		fmt.Println("Error parsing base URL:", err)
		return ""
	}

	// Ensure there's exactly one slash between the base URL and the endpoint
	// Trim the trailing slash from the base URL
	basePath := strings.TrimSuffix(u.Path, "/")

	// Trim the leading slash from the endpoint
	endpoint = strings.TrimPrefix(endpoint, "/")

	// Join the base path and the endpoint
	u.Path = fmt.Sprintf("%s/%s", basePath, endpoint)

	// Return the full URL as a string
	return u.String()
}

// Remove all extra spaces, tabs, newlines, etc., and reduce multiple spaces to a single space
func CleanWhitespace(input string) string {
	// Replace all newlines, tabs, etc., with a single space
	re := regexp.MustCompile(`\s+`)
	trimmed := re.ReplaceAllString(input, " ")
	maxtrimmed := strings.ReplaceAll(trimmed, "=", "")

	// Trim spaces from the start and end, if any
	return strings.TrimSpace(maxtrimmed)
}

// Contains checks if a string is in a slice of strings in a concise manner.
func Contains(slice []string, str string) bool {
	return func() bool {
		for _, item := range slice {
			if item == str {
				return true
			}
		}
		return false
	}()
}
func CheckAppIsServing(pkg string) error {
	// Calculate the total retry duration and sleep duration
	maxDuration := viper.GetDuration(fmt.Sprintf("%s.max_bootup_duration", pkg))
	shared.Log.Debug("CheckAppServing maxbootupduration", zap.Any("maxDuration", maxDuration))
	sleepDuration := time.Millisecond * 250

	// Get the application's IP and port from the configuration
	interfaceIP := viper.GetString(fmt.Sprintf("%s.interface_ip", pkg))
	port := viper.GetInt(fmt.Sprintf("%s.port", pkg))

	// Create the URL to check
	url := fmt.Sprintf("http://%s:%d", interfaceIP, port)

	// Initialize a variable to keep track of the elapsed time
	startTime := time.Now()

	for {
		_, err := GetString(url)
		if err == nil {
			// Successfully received response, return nil error
			return nil
		}

		// Check if the total elapsed time has exceeded the max duration
		if time.Since(startTime) >= maxDuration {
			return fmt.Errorf("application at %s is not serving after 10 seconds: %w", url, err)
		}

		// Sleep for sleepDuration before trying again
		//shared.Log.Debug("CheckAppServing sleeping before trying again", zap.Any("sleepDuration", sleepDuration), zap.Any("pkg", pkg))
		time.Sleep(sleepDuration)
	}
}

// ConvertStringToBool converts a string to a boolean value.
func ConvertStringToBool(str string) (bool, error) {
	str = strings.TrimSpace(str) // Remove any leading/trailing whitespace
	if str == "" {
		return false, fmt.Errorf("empty string cannot be converted to bool")
	}

	// Check if the string is "true" (case-insensitive)
	if strings.EqualFold(str, "true") {
		return true, nil
	} else if strings.EqualFold(str, "false") {
		return false, nil
	}

	// If it's not a valid boolean string, return an error
	return false, fmt.Errorf("invalid boolean string: %s", str)
}
