# RonflexGo
Suspends known AV/EDRs processes by loading and controlling the PROCEXP driver. Made with <3 for pentesters. Ported to Golang from https://github.com/Nariod/ronflex.

WIP 

## WARNING
RonflexGo tries to suspend all known AV/EDRs and other security product processes. There is a high chance that the system will be unstable after RonflexGo did its thing ! Use at your own risks.

## Todo
- [x] Dynamically load the list of known processes from a file at compile time
- [x] Check if the process is running in elevated context
- [x] Write PROCEXP driver to disk
- [x] Create the appropriate registry keys to load the driver
- [x] Get all privileges using [wintoken](https://github.com/fourcorelabs/wintoken) 
- [x] Load the PROCEXP driver using NtLoadDriver
- [ ] Call the driver using DeviceIoControl
- [ ] Suspend all target processes 
- [ ] Update the PROCEXP driver to the latest one


# Quick start
No time ? Let's make it short then.

## Binary
In case of an emergency, you will find a ready to deploy x64 binary for Windows in the repo Release section. However, consider taking the time to compile it yourself.

## Cross-compile from Linux
TBD

## Compile on Windows

Install and configure Golang:
TBD

## Usage
Run the binary with the highest privileges you can and without argument to freeze all known security products:
- `RonflexGo.exe`

Alternatively, you can freeze a specific target process by passing the exact process name:
- `RonflexGo.exe notepad.exe`

# Usage and details
WIP

## Credits
- [Backstab](https://github.com/Yaxser/Backstab) for the inspiration
- [The Sliver project](https://github.com/BishopFox/sliver) for the list of known AV/EDRs processes
- StackOverflow

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
