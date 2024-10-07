//go:build linux
// +build linux

package main

import (
	"fmt"
	"os/exec"

	"example.com/m/v2/shared"
	"go.uber.org/zap"
)

func RestartScriptExporter() error {

	//var cmd *exec.Cmd
	cmd := exec.Command("/usr/bin/script_exporter", "-config.check", "-config.file", shared.GlobalConfig.ScriptExporter.HardconfigFile)
	// Execute the command and capture the output
	cmdout, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error on script_exporter config check %v, output %s", err, CleanWhitespace(string(cmdout)))
	}
	shared.Log.Debug("Script Exporter Config Valid", zap.Any("cmdout", CleanWhitespace(string(cmdout))))
	err = SystemCTLcommand(shared.GlobalConfig.ScriptExporter.ServiceName, "restart")
	if err != nil {
		return fmt.Errorf("error restarting script_exporter %s", err)
	}
	return nil

}
func RestartAlloy() error {
	err := SystemCTLcommand(shared.GlobalConfig.Alloy.ServiceName, "restart")
	if err != nil {
		return fmt.Errorf("error restarting script_exporter %s", err)
	}
	return nil
}
