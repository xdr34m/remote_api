//go:build windows
// +build windows

package main

import (
	"fmt"
	"path/filepath"

	"example.com/m/v2/shared"
	"go.uber.org/zap"
)

func RestartScriptExporter() error {
	//var cmd *exec.Cmd
	exeFilePath := filepath.Join(shared.GlobalConfig.General.ClientDirectory, shared.GlobalConfig.ScriptExporter.Windows.ExeName)
	ps_cmd := fmt.Sprintf("%s -'config.check' -'config.file' %s", exeFilePath, filepath.Join(shared.GlobalConfig.ScriptExporter.HardconfigFile))
	ps_out, err := ExecutePowerShellCommand(ps_cmd)
	shared.Log.Debug("ps_cmd", zap.Any("ps_cmd", ps_cmd))
	if err != nil {
		shared.Log.Debug("ps_cmd", zap.Any("ps_cmd", ps_cmd))
		return fmt.Errorf("error on script_exporter config check %v, output %s", err, CleanWhitespace(string(ps_out)))
	}
	shared.Log.Debug("Script Exporter Config Valid", zap.Any("cmdout", CleanWhitespace(string(ps_out))))
	ps_cmd = fmt.Sprintf("sc.exe stop %s;sc.exe start %s", shared.GlobalConfig.ScriptExporter.ServiceName, shared.GlobalConfig.ScriptExporter.ServiceName)
	ps_out, err = ExecutePowerShellCommand(ps_cmd)
	shared.Log.Debug("ps_cmd", zap.Any("ps_cmd", ps_cmd))
	if err != nil {
		shared.Log.Debug("ps_cmd", zap.Any("ps_cmd", ps_cmd))
		return fmt.Errorf("error stopping&starting Service %v, output %s", err, CleanWhitespace(string(ps_out)))
	}
	shared.Log.Debug("Should have restarted Script exporter")
	return nil
}

// TODO// TODO is still on linux
func RestartAlloy() error {
	ps_cmd := fmt.Sprintf("sc.exe stop %s;sc.exe start %s", shared.GlobalConfig.Alloy.ServiceName, shared.GlobalConfig.Alloy.ServiceName)
	ps_out, err := ExecutePowerShellCommand(ps_cmd)
	if err != nil {
		return fmt.Errorf("error stopping&starting Service %v, output %s", err, CleanWhitespace(string(ps_out)))
	}
	shared.Log.Debug("Should have restarted Alloy")
	return nil
}
