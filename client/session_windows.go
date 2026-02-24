package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	modwtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	moduserenv  = syscall.NewLazyDLL("userenv.dll")

	procWTSGetActiveConsoleSessionId = modkernel32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQueryUserToken            = modwtsapi32.NewProc("WTSQueryUserToken")
	procDuplicateTokenEx             = modadvapi32.NewProc("DuplicateTokenEx")
	procCreateEnvironmentBlock       = moduserenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock      = moduserenv.NewProc("DestroyEnvironmentBlock")
	procCreateProcessAsUserW         = modadvapi32.NewProc("CreateProcessAsUserW")
	procGetTokenInformation          = modadvapi32.NewProc("GetTokenInformation")
)

const (
	SecurityImpersonation      = 2
	TokenPrimary               = 1
	TokenLinkedToken           = 19
	CREATE_UNICODE_ENVIRONMENT = 0x00000400
	CREATE_NO_WINDOW           = 0x08000000
	STARTF_USESHOWWINDOW       = 0x00000001
	SW_HIDE                    = 0
)

// TOKEN_LINKED_TOKEN holds the linked token retrieved from a restricted token.
type TOKEN_LINKED_TOKEN struct {
	LinkedToken syscall.Token
}

// startChildInUserSession launches a child process inside the active user session.
// The args parameter is appended to the executable path, e.g. " -child -ipcport 12345".
func startChildInUserSession(args string) error {
	// Get the session ID of the physical console.
	r1, _, _ := procWTSGetActiveConsoleSessionId.Call()
	sessionID := uint32(r1)
	if sessionID == 0xFFFFFFFF {
		return fmt.Errorf("no active console session (nobody logged in)")
	}

	// Obtain the user token for that session (may initially be a restricted token).
	var userToken syscall.Token
	ret, _, err := procWTSQueryUserToken.Call(uintptr(sessionID), uintptr(unsafe.Pointer(&userToken)))
	if ret == 0 {
		return fmt.Errorf("WTSQueryUserToken failed: %v", err)
	}

	// Try to retrieve the linked (elevated) token.
	var linkedToken TOKEN_LINKED_TOKEN
	var returnLength uint32

	ret, _, _ = procGetTokenInformation.Call(
		uintptr(userToken),
		uintptr(TokenLinkedToken),
		uintptr(unsafe.Pointer(&linkedToken)),
		uintptr(unsafe.Sizeof(linkedToken)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret != 0 && linkedToken.LinkedToken != 0 {
		syscall.CloseHandle(syscall.Handle(userToken))
		userToken = linkedToken.LinkedToken
	}

	defer syscall.CloseHandle(syscall.Handle(userToken))

	// Duplicate the token as a primary token.
	var duplicatedToken syscall.Token
	ret, _, err = procDuplicateTokenEx.Call(
		uintptr(userToken),
		0,
		0,
		uintptr(SecurityImpersonation),
		uintptr(TokenPrimary),
		uintptr(unsafe.Pointer(&duplicatedToken)),
	)
	if ret == 0 {
		return fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(duplicatedToken))

	// Create an environment block for the user.
	var env uintptr
	ret, _, err = procCreateEnvironmentBlock.Call(uintptr(unsafe.Pointer(&env)), uintptr(duplicatedToken), 0)
	if ret == 0 {
		return fmt.Errorf("CreateEnvironmentBlock failed: %v", err)
	}
	defer procDestroyEnvironmentBlock.Call(env)

	// Build the command line string.
	exePath, _ := os.Executable()
	cmdLineStr := fmt.Sprintf(`"%s"%s`, exePath, args)
	cmdLine := syscall.StringToUTF16Ptr(cmdLineStr)

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = STARTF_USESHOWWINDOW
	si.ShowWindow = SW_HIDE
	// Run the process on the default desktop.
	si.Desktop = syscall.StringToUTF16Ptr("winsta0\\default")

	var pi syscall.ProcessInformation

	// Launch the child process under the user's token.
	ret, _, err = procCreateProcessAsUserW.Call(
		uintptr(duplicatedToken),
		0,
		uintptr(unsafe.Pointer(cmdLine)),
		0,
		0,
		0,
		uintptr(CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW),
		env,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessAsUser failed: %v", err)
	}

	// Close the process and thread handles.
	syscall.CloseHandle(syscall.Handle(pi.Process))
	syscall.CloseHandle(syscall.Handle(pi.Thread))
	return nil
}
