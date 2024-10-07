package shared

import (
	"flag"
	"fmt"
	"os"
)

// Struct to hold all flag values
type Flags struct {
	Reinstall      bool
	Deinstall      bool
	Debug          bool
	NoDelay        bool
	Install        bool
	ConfigFilePath string
	Help           bool
}

var GlobalFlags Flags

// ParseFlags returns a struct containing all parsed flag values
func ParseFlags() {
	// Define flags
	flag.BoolVar(&GlobalFlags.Reinstall, "reinstall", false, "if set, deletes alloy and reinstalls it")
	flag.BoolVar(&GlobalFlags.Deinstall, "deinstall", false, "if set, deletes alloy")
	flag.BoolVar(&GlobalFlags.Install, "install", false, "if set installs alloy")
	flag.BoolVar(&GlobalFlags.Debug, "debug", false, "if set uses debug_dir where the script resides and logs debug")
	flag.BoolVar(&GlobalFlags.NoDelay, "nodelay", false, "if set no sleep before executing")
	flag.StringVar(&GlobalFlags.ConfigFilePath, "config", "", "Path to the configuration file")
	flag.BoolVar(&GlobalFlags.Help, "help", false, "Display help")

	// Check for help flag first
	flag.Parse()
	if GlobalFlags.Help {
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0) // Exit after printing help
	}

	// Check for mutually exclusive flags
	if GlobalFlags.Deinstall && GlobalFlags.Reinstall {
		fmt.Println("Error: You cannot use -deinstall and -reinstall together.")
		os.Exit(1) // Exit with an error code
	}

	// Check for unknown flags
	for _, arg := range os.Args[1:] {
		if !isValidFlag(arg) {
			fmt.Println("Error: Unknown flag:", arg)
			fmt.Println("Usage:")
			flag.PrintDefaults()
			os.Exit(1) // Exit after printing error and help
		}
	}
}

// isValidFlag checks if a given argument is a valid flag
func isValidFlag(arg string) bool {
	validFlags := []string{
		"-reinstall", "-deinstall", "-debug", "-install", "-nodelay", "-config",
		"-help", "--help", // Include help flag variations
	}

	for _, flag := range validFlags {
		if arg == flag {
			return true
		}
	}
	return false
}
