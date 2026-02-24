package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kardianos/service"
	"github.com/kbinani/screenshot"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/text/encoding/simplifiedchinese"
)

type program struct {
	logger service.Logger
}

func (p *program) Start(s service.Service) error {
	p.logger, _ = s.Logger(nil)
	if p.logger != nil {
		p.logger.Info("Service is starting...")
	}
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	if p.logger != nil {
		p.logger.Info("Service is stopping...")
	}
	return nil
}

func logToFile(msg string) {
	// Debug log written to the root of the C drive.
	f, err := os.OpenFile("C:\\rmm_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	f.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, msg))
}

func (p *program) run() {
	logToFile(">>> Service run() method started")

	defer func() {
		if r := recover(); r != nil {
			logToFile(fmt.Sprintf("!!! Service fatal crash (Panic): %v", r))
		}
	}()

	exePath, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exePath)
		os.Chdir(dir)
		logToFile(fmt.Sprintf("Working directory changed to: %s", dir))
	}

	if err := loadEncryptedConfig(); err != nil {
		logToFile(fmt.Sprintf("Config load failed: %v", err))
		config.Port = "8080"
	} else {
		logToFile("Config loaded successfully")
	}

	// Determine the running mode.
	if !service.Interactive() {
		logToFile("Service mode detected, starting IPC...")
		port := startLocalIPCServer()
		logToFile(fmt.Sprintf("IPC started, port: %d", port))

		if port > 0 {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						logToFile(fmt.Sprintf("!!! Child process watchdog goroutine crashed: %v", r))
					}
				}()

				logToFile("Watchdog goroutine started, monitoring child process...")
				for {
					screenChildLock.Lock()
					isConnected := (screenChildConn != nil)
					screenChildLock.Unlock()

					if !isConnected {
						args := fmt.Sprintf(" -child -ipcport %d", port)
						// Call the function defined in session_windows.go.
						startChildInUserSession(args)
					}
					time.Sleep(5 * time.Second)
				}
			}()
		}
	} else {
		logToFile("Desktop/console mode detected")
	}

	// Start Passive mode.
	if config.PassiveMode {
		logToFile("Enabling passive mode loop")
		go passiveModeLoop()
	}

	// Start USB monitoring goroutine.
	logToFile("Starting USB monitoring module...")
	lastUSBDevices = make(map[string]bool)
	go monitorUSB()

	// Start HTTP server.
	addr := ":" + config.Port
	logToFile(fmt.Sprintf("Starting HTTP listener on: %s", addr))

	http.HandleFunc("/ws", handleWS)

	err = http.ListenAndServe(addr, nil)
	if err != nil {
		logToFile(fmt.Sprintf("!!! HTTP server failed to start: %v", err))
	}
}

// startLocalIPCServer starts a local TCP IPC server and returns its port.
func startLocalIPCServer() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Println("IPC listen failed:", err)
		return 0
	}
	addr := ln.Addr().(*net.TCPAddr)
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			screenChildLock.Lock()
			if screenChildConn != nil {
				screenChildConn.Close()
			}
			screenChildConn = conn
			screenChildReader = bufio.NewReader(conn)
			screenChildLock.Unlock()
		}
	}()
	return addr.Port
}

const CryptoKey = "0123456789ABCDEF0123456789ABCDEF"

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	procSetCursorPos = user32.NewProc("SetCursorPos")
	procMouseEvent   = user32.NewProc("mouse_event")
	procKeybdEvent   = user32.NewProc("keybd_event")
)

const (
	MOUSEEVENTF_LEFTDOWN   = 0x0002
	MOUSEEVENTF_LEFTUP     = 0x0004
	MOUSEEVENTF_RIGHTDOWN  = 0x0008
	MOUSEEVENTF_RIGHTUP    = 0x0010
	MOUSEEVENTF_MIDDLEDOWN = 0x0020
	MOUSEEVENTF_MIDDLEUP   = 0x0040
	MOUSEEVENTF_WHEEL      = 0x0800
	MOUSEEVENTF_ABSOLUTE   = 0x8000
	KEYEVENTF_KEYUP        = 0x0002
)

type ClientConfig struct {
	Port          string `json:"port"`
	Password      string `json:"password"`
	Autostart     bool   `json:"autostart"`
	PassiveMode   bool   `json:"passive_mode"`
	ServerAddr    string `json:"server_addr"`
	ServerPort    string `json:"server_port"`
	ServerPass    string `json:"server_pass"`
	CheckInterval int    `json:"check_interval"`
}

type USBRecord struct {
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	DeviceName string `json:"device_name"`
	VolumeID   string `json:"volume_id"`
	Model      string `json:"model"`
}

type ProgressPayload struct {
	TaskID  string `json:"task_id,omitempty"` // Associated task ID.
	Path    string `json:"path"`
	Percent int    `json:"percent"`
	Status  string `json:"status"` // "downloading", "finished", "error", "cancelled"
	Error   string `json:"error,omitempty"`
}

var (
	config            ClientConfig
	upgrader          = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	CurrentDir        string
	usbRecords        []USBRecord
	lastUSBDevices    map[string]bool
	activeConnections []*websocket.Conn
	connMutex         sync.RWMutex
	currentUploadFile *os.File
	uploadLock        sync.Mutex

	wsWriteMutex sync.Mutex

	screenChildConn   net.Conn
	screenChildReader *bufio.Reader // Persistent reader.
	screenChildLock   sync.Mutex
	isChildMode       bool = false
	isServiceMode     bool = false

	// Cancellation controls for large file downloads.
	downloadCancels = make(map[string]context.CancelFunc)
	dlMutex         sync.Mutex
)

func main() {
	var targetPort string = ""
	var execCmd string = ""

	for i, arg := range os.Args {
		if arg == "-child" {
			isChildMode = true
		}
		if arg == "-ipcport" && i+1 < len(os.Args) {
			targetPort = os.Args[i+1]
		}
		if arg == "-exec" && i+1 < len(os.Args) {
			execCmd = os.Args[i+1]
		}
	}

	if execCmd != "" {
		runCmd(execCmd)
		return
	}

	if isChildMode {
		if targetPort == "" {
			return
		}
		runChildProcess(targetPort)
		return
	}

	svcConfig := &service.Config{
		Name:        "XxkAgent",
		DisplayName: "Xxk RMM Agent Service",
		Description: "Remote Management & Monitoring Background Service",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
		err = service.Control(s, os.Args[1])
		if err != nil {
			log.Printf("Service control error: %s\n", err)
		}
		return
	}

	exePath, _ := os.Executable()
	os.Chdir(filepath.Dir(exePath))

	loadEncryptedConfig()

	if !service.Interactive() {
		isServiceMode = true
		s.Run()
	} else {
		if config.Autostart {
			status, err := s.Status()
			if err == nil && status == service.StatusRunning {
				return
			}
			err = s.Install()
			if err != nil {
				p := &program{}
				p.run()
				return
			}
			s.Start()
			return
		} else {
			p := &program{}
			p.run()
		}
	}
}

func passiveModeLoop() {
	defer func() {
		if r := recover(); r != nil {
			logToFile(fmt.Sprintf("Passive mode goroutine crashed (attempting restart): %v", r))
			time.Sleep(5 * time.Second) // Wait a few seconds before restarting.
			go passiveModeLoop()
		}
	}()

	interval := config.CheckInterval
	if interval <= 10 {
		interval = 10
	}

	for {
		connected := connectToServer()

		if !connected {
			logToFile("Failed to connect to server, waiting to retry...")
			time.Sleep(time.Duration(interval) * time.Second)
		} else {
			time.Sleep(1 * time.Second)
		}
	}
}

func connectToServer() bool {
	if config.ServerAddr == "" || config.ServerPort == "" {
		return false
	}

	// Build the connection URL and authentication header.
	u := url.URL{Scheme: "ws", Host: config.ServerAddr + ":" + config.ServerPort, Path: "/ws"}
	header := http.Header{}
	header.Add("X-Auth-Pass", config.ServerPass)

	// Set a handshake timeout to avoid hanging on poor networks.
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(u.String(), header)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Enable TCP KeepAlive on the underlying connection.
	if tcpConn, ok := conn.UnderlyingConn().(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Add the connection to the global active list (so other modules can send USB records, etc.).
	connMutex.Lock()
	activeConnections = append(activeConnections, conn)
	connMutex.Unlock()

	// Remove the connection from the active list on exit.
	defer func() {
		connMutex.Lock()
		for i, c := range activeConnections {
			if c == conn {
				activeConnections = append(activeConnections[:i], activeConnections[i+1:]...)
				break
			}
		}
		connMutex.Unlock()
	}()

	// Send registration message.
	uniqueID := getUniqueID()
	hostname, _ := os.Hostname()
	registerMsg := map[string]interface{}{
		"type": "register",
		"payload": map[string]string{
			"id":    uniqueID,
			"ip":    getLocalIP(),
			"alias": hostname,
			"group": "Default Group",
			"mode":  "passive",
		},
	}
	if err := conn.WriteJSON(registerMsg); err != nil {
		return true
	}

	logToFile("Successfully connected and registered to server")

	// Enter the blocking receive loop.
	// The program stays in this loop as long as the connection is healthy, using no CPU.
	for {
		var msg map[string]interface{}
		// ReadJSON returns immediately on disconnect, server restart, or network error.
		if err := conn.ReadJSON(&msg); err != nil {
			logToFile(fmt.Sprintf("Connection to server lost: %v", err))
			// Return true to signal that a reconnect can be attempted immediately.
			return true
		}

		// Handle commands from the management console.
		handleMessage(conn, msg)
	}
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth-Pass") != config.Password {
		http.Error(w, "Auth failed", 403)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	hostname, _ := os.Hostname()
	registerMsg := map[string]interface{}{
		"type": "id_report",
		"payload": map[string]string{
			"id":    getUniqueID(),
			"ip":    getLocalIP(),
			"alias": hostname,
		},
	}
	conn.WriteJSON(registerMsg)

	connMutex.Lock()
	activeConnections = append(activeConnections, conn)
	connMutex.Unlock()

	defer func() {
		connMutex.Lock()
		for i, c := range activeConnections {
			if c == conn {
				activeConnections = append(activeConnections[:i], activeConnections[i+1:]...)
				break
			}
		}
		connMutex.Unlock()
		conn.Close()
	}()

	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}
		handleMessage(conn, msg)
	}
}

func handleMessage(conn *websocket.Conn, msg map[string]interface{}) {
	// Safely retrieve the message type.
	typInterface, ok := msg["type"]
	if !ok {
		return
	}
	typ, ok := typInterface.(string)
	if !ok {
		return
	}

	payload := msg["payload"]

	switch typ {
	case "cmd":
		cmdStr, ok := payload.(string)
		if !ok {
			return
		}
		out := runStatefulCommand(cmdStr)
		safeWriteJSON(conn, map[string]interface{}{"type": "cmd_out", "payload": out, "cwd": CurrentDir})

	case "screen_req":
		quality := 50
		scale := 0.8

		// Parse parameters sent from the frontend (format: "quality|scale", e.g. "60|0.8").
		if params, ok := payload.(string); ok && params != "" {
			var s float64
			var q int
			n, _ := fmt.Sscanf(params, "%d|%f", &q, &s)
			if n == 2 {
				quality = q
				scale = s
			}
		}

		// Clamp values to prevent extreme parameters.
		if quality < 10 {
			quality = 10
		}
		if quality > 90 {
			quality = 90
		}
		if scale < 0.2 {
			scale = 0.2
		}
		if scale > 1.0 {
			scale = 1.0
		}

		// Check running mode.
		if !service.Interactive() {
			// Service mode: use IPC.
			screenChildLock.Lock()
			client := screenChildConn
			reader := screenChildReader
			screenChildLock.Unlock()

			if client == nil || reader == nil {
				conn.WriteJSON(map[string]interface{}{"type": "screen", "payload": "LOCKED"})
				return
			}

			// Send 'S' command with parameters to the child process.
			_, err := fmt.Fprintf(client, "S%d|%f\n", quality, scale)
			if err != nil {
				// Write failure indicates the child process may have died; reset the connection.
				client.Close()
				screenChildLock.Lock()
				screenChildConn = nil
				screenChildLock.Unlock()
				return
			}

			client.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			line, err := reader.ReadBytes('\n')
			client.SetReadDeadline(time.Time{})

			if err != nil {
				client.Close()
				screenChildLock.Lock()
				screenChildConn = nil
				screenChildReader = nil
				screenChildLock.Unlock()
				return
			}

			var childResp struct {
				Payload string `json:"payload"`
				Width   int    `json:"width"`
				Height  int    `json:"height"`
			}
			json.Unmarshal(line, &childResp)
			conn.WriteJSON(map[string]interface{}{
				"type": "screen", "payload": childResp.Payload, "width": childResp.Width, "height": childResp.Height,
			})

		} else {
			// Interactive mode (console/desktop): supports dynamic parameter adjustment.
			b64, w, h := captureScreenAndSize(quality, scale)
			conn.WriteJSON(map[string]interface{}{
				"type":    "screen",
				"payload": b64,
				"width":   w,
				"height":  h,
			})
		}

	case "fs_drives":
		// Enumerate all partitions/disks.
		partitions, err := disk.Partitions(true)
		var drives []string
		if err == nil {
			for _, p := range partitions {
				drives = append(drives, p.Mountpoint)
			}
		}

		if len(drives) == 0 {
			if runtime.GOOS == "windows" {
				drives = []string{"C:", "D:"}
			} else {
				drives = []string{"/"}
			}
		}
		conn.WriteJSON(map[string]interface{}{"type": "drive_list", "payload": drives})

	case "input_event":
		if payload == nil {
			return
		}

		if !service.Interactive() {
			screenChildLock.Lock()
			client := screenChildConn
			screenChildLock.Unlock()

			if client != nil {
				client.Write([]byte{'I'})
				jsonBytes, _ := json.Marshal(payload)
				client.Write(jsonBytes)
				client.Write([]byte("\n"))
			}
		} else {
			if pMap, ok := payload.(map[string]interface{}); ok {
				handleInputEvent(pMap)
			}
		}

	case "file_pull":
		payloadMap, ok := payload.(map[string]interface{})
		if !ok || payloadMap == nil {
			log.Println("Error: file_pull payload is invalid or nil")
			return
		}

		url, _ := payloadMap["url"].(string)
		savePath, _ := payloadMap["path"].(string)

		if url == "" || savePath == "" {
			return
		}

		run, _ := payloadMap["run"].(bool)

		taskId, _ := payloadMap["task_id"].(string)

		runAsAdmin := false
		if v, ok := payloadMap["run_as_admin"].(bool); ok {
			runAsAdmin = v
		}

		go startManagedPull(conn, url, savePath, run, runAsAdmin, taskId)

	case "cancel_pull":
		targetPath, ok := payload.(string)
		if !ok {
			return
		}

		dlMutex.Lock()
		if cancel, exists := downloadCancels[targetPath]; exists {
			cancel()
			delete(downloadCancels, targetPath)
			log.Printf("File download cancelled: %s", targetPath)
		}
		dlMutex.Unlock()

	case "file_delete":
		path, ok := payload.(string)
		if !ok {
			return
		}
		err := os.RemoveAll(path)
		res := "Deleted: " + path
		if err != nil {
			res = "Error deleting: " + err.Error()
		}
		safeWriteJSON(conn, map[string]interface{}{"type": "cmd_out", "payload": res, "cwd": CurrentDir})

	case "file_exec":
		path, ok := payload.(string)
		if !ok {
			return
		}
		res := executeFile(path, false)
		safeWriteJSON(conn, map[string]interface{}{"type": "cmd_out", "payload": res, "cwd": CurrentDir})

	case "ps_list":
		list := getProcessList()
		conn.WriteJSON(map[string]interface{}{"type": "ps_list", "payload": list})

	case "ps_kill":
		var pid int32
		switch v := payload.(type) {
		case float64:
			pid = int32(v)
		case string:
			i, _ := strconv.Atoi(v)
			pid = int32(i)
		}
		killProcess(pid)
		conn.WriteJSON(map[string]interface{}{"type": "ps_list", "payload": getProcessList()})

	case "fs_list":
		rawPath, ok := payload.(string)
		if !ok {
			rawPath = "C:\\"
		}

		realHome := getRealUserHome()
		replaceEnv := func(input, envKey, replacement string) string {
			return strings.ReplaceAll(input, envKey, replacement)
		}

		if strings.Contains(strings.ToUpper(rawPath), "%USERPROFILE%") {
			rawPath = replaceEnv(rawPath, "%USERPROFILE%", realHome)
		}
		if strings.Contains(strings.ToUpper(rawPath), "%APPDATA%") {
			appData := filepath.Join(realHome, "AppData", "Roaming")
			rawPath = replaceEnv(rawPath, "%APPDATA%", appData)
		}
		if strings.Contains(strings.ToUpper(rawPath), "%TEMP%") {
			temp := filepath.Join(realHome, "AppData", "Local", "Temp")
			rawPath = replaceEnv(rawPath, "%TEMP%", temp)
		}

		if strings.Contains(strings.ToLower(rawPath), "systemprofile") {
			if strings.Contains(strings.ToLower(rawPath), "desktop") {
				rawPath = filepath.Join(realHome, "Desktop")
			} else if strings.Contains(strings.ToLower(rawPath), "downloads") {
				rawPath = filepath.Join(realHome, "Downloads")
			} else if strings.Contains(strings.ToLower(rawPath), "documents") {
				rawPath = filepath.Join(realHome, "Documents")
			}
		}

		path := os.ExpandEnv(rawPath)
		path = filepath.Clean(path)
		files := listFiles(path)
		conn.WriteJSON(map[string]interface{}{"type": "file_list", "payload": files, "path": path})

	case "upload_start":
		path, ok := msg["file_path"].(string)
		if !ok {
			return
		}

		overwrite := true
		if val, ok := msg["overwrite"].(bool); ok {
			overwrite = val
		}
		if msg["overwrite"] == nil && payload != nil {
			if plMap, ok := payload.(map[string]interface{}); ok {
				if val, ok := plMap["overwrite"].(bool); ok {
					overwrite = val
				}
			}
		}

		uploadLock.Lock()
		if currentUploadFile != nil {
			currentUploadFile.Close()
			currentUploadFile = nil
		}
		skip := false
		if !overwrite {
			if _, err := os.Stat(path); err == nil {
				skip = true
			}
		}

		if skip {
			currentUploadFile = nil
		} else {
			dir := filepath.Dir(path)
			os.MkdirAll(dir, 0755)
			f, err := os.Create(path)
			if err != nil {
				currentUploadFile = nil
			} else {
				currentUploadFile = f
			}
		}
		uploadLock.Unlock()

	case "upload_chunk":
		uploadLock.Lock()
		if currentUploadFile != nil {
			dataStr, ok := msg["data"].(string)
			if ok {
				dataBytes, err := base64.StdEncoding.DecodeString(dataStr)
				if err == nil {
					currentUploadFile.Write(dataBytes)
				}
			}
		}
		uploadLock.Unlock()

	case "upload_finish":
		uploadLock.Lock()
		if currentUploadFile != nil {
			filePath := currentUploadFile.Name()
			currentUploadFile.Close()
			currentUploadFile = nil

			var run bool
			var runAsAdmin bool

			if r, ok := msg["run"].(bool); ok {
				run = r
			}
			if r, ok := msg["run_as_admin"].(bool); ok {
				runAsAdmin = r
			}

			if !run && payload != nil {
				if plMap, ok := payload.(map[string]interface{}); ok {
					if r, ok := plMap["run"].(bool); ok {
						run = r
					}
					if r, ok := plMap["run_as_admin"].(bool); ok {
						runAsAdmin = r
					}
				}
			}

			if run {
				output := executeFile(filePath, runAsAdmin)
				safeWriteJSON(conn, map[string]interface{}{
					"type":    "cmd_out",
					"payload": fmt.Sprintf("Batch task result:\n%s", output),
					"cwd":     CurrentDir,
				})
			} else {
				safeWriteJSON(conn, map[string]interface{}{
					"type":    "cmd_out",
					"payload": "File upload complete (no execution action)",
					"cwd":     CurrentDir,
				})
			}
			files := listFiles(CurrentDir)
			conn.WriteJSON(map[string]interface{}{"type": "file_list", "payload": files, "path": CurrentDir})
		}
		uploadLock.Unlock()

	case "upload_cancel":
		uploadLock.Lock()
		if currentUploadFile != nil {
			name := currentUploadFile.Name()
			currentUploadFile.Close()
			currentUploadFile = nil
			os.Remove(name)
		}
		uploadLock.Unlock()

	case "file_upload":
		data, ok := payload.(map[string]interface{})
		if !ok {
			return
		}
		savePath, _ := data["path"].(string)
		fileData, _ := data["data"].(string)

		if savePath == "" || fileData == "" {
			return
		}

		err := saveFile(savePath, fileData)
		var outputMsg string
		if err != nil {
			outputMsg = fmt.Sprintf("File upload failed: %s\nError: %v", savePath, err)
		} else {
			outputMsg = fmt.Sprintf("File uploaded: %s", savePath)
			if run, ok := data["run"].(bool); ok && run {
				runAsAdmin := false
				if admin, ok := data["run_as_admin"].(bool); ok {
					runAsAdmin = admin
				}
				execResult := executeFile(savePath, runAsAdmin)
				outputMsg += "\n" + execResult
			}
		}
		safeWriteJSON(conn, map[string]interface{}{"type": "cmd_out", "payload": outputMsg, "cwd": CurrentDir})

	case "file_download":
		pathStr, ok := payload.(string)
		if !ok {
			return
		}
		path := os.ExpandEnv(pathStr)
		conn.WriteJSON(map[string]interface{}{
			"type": "file_download_data",
			"payload": map[string]string{"path": path, "data": readFile(path)},
		})

	case "sys_info":
		info := getSysInfo()
		conn.WriteJSON(map[string]interface{}{"type": "sys_info", "payload": info})

	case "function":
		fnStr, ok := payload.(string)
		if !ok {
			return
		}
		result := execFunction(fnStr)
		safeWriteJSON(conn, map[string]interface{}{"type": "cmd_out", "payload": result, "cwd": CurrentDir})

	case "get_usb_records":
		conn.WriteJSON(map[string]interface{}{"type": "usb_records", "payload": usbRecords})
	}
}

// startManagedPull downloads a file with progress reporting and cancellation support.
func startManagedPull(ws *websocket.Conn, fileUrl string, savePath string, run bool, runAsAdmin bool, taskId string) {
	ctx, cancel := context.WithCancel(context.Background())

	dlMutex.Lock()
	downloadCancels[savePath] = cancel
	dlMutex.Unlock()

	defer func() {
		dlMutex.Lock()
		delete(downloadCancels, savePath)
		dlMutex.Unlock()
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", fileUrl, nil)
	if err != nil {
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		sendProgress(ws, savePath, 0, "error", err.Error(), taskId)
		return
	}
	defer resp.Body.Close()

	os.MkdirAll(filepath.Dir(savePath), 0755)
	f, err := os.Create(savePath)
	if err != nil {
		sendProgress(ws, savePath, 0, "error", "Failed to create file: "+err.Error(), taskId)
		return
	}

	defer func() {
		// Specific error-handling paths below manage closing; this is a safety net.
	}()

	totalSize := resp.ContentLength
	var downloaded int64 = 0
	buf := make([]byte, 32*1024)
	lastReport := time.Now()

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			_, wErr := f.Write(buf[:n])
			if wErr != nil {
				f.Close()
				return
			}
			downloaded += int64(n)

			if time.Since(lastReport) > 500*time.Millisecond {
				pct := 0
				if totalSize > 0 {
					pct = int(float64(downloaded) / float64(totalSize) * 100)
				}
				sendProgress(ws, savePath, pct, "downloading", "", taskId)
				lastReport = time.Now()
			}
		}
		if err != nil {
			f.Close()
			if err == io.EOF {
				sendProgress(ws, savePath, 100, "finished", "", taskId)
				if run {
					executeFile(savePath, runAsAdmin)
				}
				return
			}
			if errors.Is(err, context.Canceled) {
				os.Remove(savePath)
				sendProgress(ws, savePath, 0, "cancelled", "", taskId)
				return
			}
			os.Remove(savePath) // Clean up file on download error.
			sendProgress(ws, savePath, 0, "error", err.Error(), taskId)
			return
		}
	}
}

func sendProgress(conn *websocket.Conn, path string, pct int, status, errMsg string, taskId string) {
	conn.WriteJSON(map[string]interface{}{
		"type": "download_progress",
		"payload": ProgressPayload{
			TaskID:  taskId,
			Path:    path,
			Percent: pct,
			Status:  status,
			Error:   errMsg,
		},
	})
}

func executeFile(path string, asAdmin bool) string {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "start", "", path)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	} else {
		if asAdmin {
			cmd = exec.Command("sudo", "-b", path)
		} else {
			cmd = exec.Command("sh", "-c", path)
		}
	}
	err := cmd.Start()
	if err != nil {
		return fmt.Sprintf("Launch failed: %v", err)
	}
	return fmt.Sprintf("Background task triggered: %s", path)
}

func monitorUSB() {
	if runtime.GOOS != "windows" {
		return
	}

	if lastUSBDevices == nil {
		lastUSBDevices = make(map[string]bool)
	}

	initialDevices := getUSBDevices()
	for dev := range initialDevices {
		lastUSBDevices[dev] = true
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		currentDevices := getUSBDevices()

		for dev := range currentDevices {
			if !lastUSBDevices[dev] {
				model := getDriveModel(dev)
				record := USBRecord{
					Timestamp:  time.Now().Format("2006-01-02 15:04:05"),
					Action:     "Inserted",
					DeviceName: dev,
					VolumeID:   getVolumeID(dev),
					Model:      model,
				}
				usbRecords = append(usbRecords, record)
				sendUSBRecordToServer(record)
			}
		}

		for dev := range lastUSBDevices {
			if !currentDevices[dev] {
				record := USBRecord{
					Timestamp:  time.Now().Format("2006-01-02 15:04:05"),
					Action:     "Removed",
					DeviceName: dev,
					VolumeID:   "",
				}
				usbRecords = append(usbRecords, record)
				sendUSBRecordToServer(record)
			}
		}
		lastUSBDevices = currentDevices
	}
}

func getUSBDevices() map[string]bool {
	devices := make(map[string]bool)
	if runtime.GOOS != "windows" {
		return devices
	}

	cmd := exec.Command("wmic", "logicaldisk", "where", "drivetype=2", "get", "deviceid,volumename")
	output, err := cmd.Output()
	if err != nil {
		return devices
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && strings.Contains(line, ":") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				devices[parts[0]] = true
			}
		}
	}
	return devices
}

func getVolumeID(drive string) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	driveLetter := strings.TrimSuffix(drive, ":") + ":"
	cmd := exec.Command("wmic", "logicaldisk", "where", "DeviceID='"+driveLetter+"'", "get", "VolumeSerialNumber")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "VolumeSerialNumber") {
			return line
		}
	}
	return ""
}

func runStatefulCommand(cmdStr string) string {
	cmdStr = strings.TrimSpace(cmdStr)
	lowerCmd := strings.ToLower(cmdStr)

	if strings.HasPrefix(lowerCmd, "cd ") || (len(cmdStr) == 2 && cmdStr[1] == ':') {
		target := CurrentDir
		if len(cmdStr) == 2 {
			target = cmdStr + "\\"
		} else {
			args := strings.Fields(cmdStr)
			if len(args) >= 2 {
				target = strings.Join(args[1:], " ")
			}
		}
		target = os.ExpandEnv(target)
		if !filepath.IsAbs(target) {
			target = filepath.Join(CurrentDir, target)
		}
		if info, err := os.Stat(target); err == nil && info.IsDir() {
			CurrentDir = target
			return ""
		} else {
			return "Path not found.\n"
		}
	}

	if lowerCmd == "ls" || lowerCmd == "ll" {
		cmdStr = "dir"
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", cmdStr)
	} else {
		cmd = exec.Command("sh", "-c", cmdStr)
	}
	cmd.Dir = CurrentDir

	output, err := cmd.CombinedOutput()
	if runtime.GOOS == "windows" {
		decoder := simplifiedchinese.GB18030.NewDecoder()
		output, _ = decoder.Bytes(output)
	}
	if err != nil {
		return string(output) + "\n" + err.Error()
	}
	return string(output)
}

func getSysInfo() map[string]string {
	info := make(map[string]string)
	if cpuInfo, err := cpu.Info(); err == nil && len(cpuInfo) > 0 {
		info["cpu"] = fmt.Sprintf("%s (%d cores)", cpuInfo[0].ModelName, runtime.NumCPU())
	}
	if memInfo, err := mem.VirtualMemory(); err == nil {
		info["memory"] = fmt.Sprintf("Total: %.2f GB | Used: %.2f GB (%.1f%%)",
			float64(memInfo.Total)/1024/1024/1024, float64(memInfo.Used)/1024/1024/1024, memInfo.UsedPercent)
	}
	if diskInfo, err := disk.Usage("/"); err == nil {
		info["disk"] = fmt.Sprintf("Total: %.2f GB | Used: %.2f GB (%.1f%%)",
			float64(diskInfo.Total)/1024/1024/1024, float64(diskInfo.Used)/1024/1024/1024, diskInfo.UsedPercent)
	} else if runtime.GOOS == "windows" {
		if diskInfo, err := disk.Usage("C:"); err == nil {
			info["disk"] = fmt.Sprintf("C: Total: %.2f GB | Used: %.2f GB (%.1f%%)",
				float64(diskInfo.Total)/1024/1024/1024, float64(diskInfo.Used)/1024/1024/1024, diskInfo.UsedPercent)
		}
	}

	netInfo := "N/A"
	if ifaces, err := net.Interfaces(); err == nil {
		var macs []string
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
				macs = append(macs, fmt.Sprintf("%s: %s", iface.Name, iface.HardwareAddr.String()))
			}
		}
		if len(macs) > 0 {
			netInfo = strings.Join(macs, " | ")
		}
	}
	info["network"] = netInfo

	if hostInfo, err := host.Info(); err == nil {
		info["os"] = fmt.Sprintf("%s %s (%s)", hostInfo.OS, hostInfo.PlatformVersion, hostInfo.Platform)
	} else {
		info["os"] = runtime.GOOS
	}
	info["time"] = time.Now().Format("2006-01-02 15:04:05")
	return info
}

func execFunction(fn string) string {
	switch fn {
	case "disable_usb":
		if runtime.GOOS == "windows" {
			return runCmd("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 4 /f")
		}
	case "enable_usb":
		if runtime.GOOS == "windows" {
			return runCmd("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 3 /f")
		}
	case "disable_printer":
		if runtime.GOOS == "windows" {
			return runCmd("net stop spooler")
		}
	case "enable_printer":
		if runtime.GOOS == "windows" {
			return runCmd("net start spooler")
		}
	case "lock_screen":
		if runtime.GOOS == "windows" {
			cmd := "rundll32.exe user32.dll,LockWorkStation"
			if isServiceMode {
				return runCmdInUserSession(cmd)
			}
			return runCmd(cmd)
		}
	case "logoff":
		if runtime.GOOS == "windows" {
			cmd := "shutdown /l"
			if isServiceMode {
				return runCmdInUserSession(cmd)
			}
			return runCmd(cmd)
		} else {
			return runCmd("pkill -KILL -u $USER")
		}
	case "restart":
		if runtime.GOOS == "windows" {
			return runCmd("shutdown /r /t 0")
		}
		return runCmd("sudo reboot")
	case "shutdown":
		if runtime.GOOS == "windows" {
			return runCmd("shutdown /s /t 0")
		}
		return runCmd("sudo shutdown -h now")
	}
	return "Not supported or Unknown"
}

func runCmdInUserSession(command string) string {
	args := fmt.Sprintf(" -exec \"%s\"", command)
	err := startChildInUserSession(args)
	if err != nil {
		return fmt.Sprintf("Failed to execute in user session: %v", err)
	}
	return "Command sent to user session successfully"
}

func runCmd(cmdStr string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", cmdStr)
	} else {
		cmd = exec.Command("sh", "-c", cmdStr)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %s\n%s", err.Error(), string(output))
	}
	return string(output)
}

func getProcessList() []map[string]interface{} {
	ps, _ := process.Processes()
	var res []map[string]interface{}
	for _, p := range ps {
		n, err := p.Name()
		if err != nil || n == "" {
			n = "[System/Hidden]"
		}
		m, _ := p.MemoryInfo()
		var mem uint64 = 0
		if m != nil {
			mem = m.RSS
		}
		res = append(res, map[string]interface{}{"pid": p.Pid, "name": n, "mem": mem})
	}
	return res
}

func killProcess(pid int32) {
	p, err := process.NewProcess(pid)
	if err == nil {
		p.Kill()
	}
}

func listFiles(path string) []map[string]interface{} {
	entries, err := os.ReadDir(path)
	if err != nil {
		return []map[string]interface{}{}
	}
	var res []map[string]interface{}
	for _, e := range entries {
		i, _ := e.Info()
		res = append(res, map[string]interface{}{
			"name": e.Name(), "is_dir": e.IsDir(), "size": i.Size(),
		})
	}
	return res
}

func saveFile(path, b64 string) error {
	d, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "\\" {
		os.MkdirAll(dir, 0755)
	}
	return ioutil.WriteFile(path, d, 0644)
}

func readFile(path string) string {
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(d)
}

func loadEncryptedConfig() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	configPath := filepath.Join(filepath.Dir(exePath), "config.dat")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return err
	}

	d, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}
	dec, err := decrypt(d, []byte(CryptoKey))
	if err != nil {
		return err
	}

	if err := json.Unmarshal(dec, &config); err != nil {
		return err
	}
	if config.Port == "" {
		config.Port = "8080"
	}
	return nil
}

func decrypt(ct, key []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ct) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, ct[:ns], ct[ns:], nil)
}

func sendUSBRecordToServer(record USBRecord) {
	connMutex.RLock()
	defer connMutex.RUnlock()
	if len(activeConnections) == 0 {
		return
	}

	recordData := map[string]interface{}{
		"timestamp":   record.Timestamp,
		"action":      record.Action,
		"device_name": record.DeviceName,
		"volume_id":   record.VolumeID,
		"model":       record.Model,
	}
	msg := map[string]interface{}{"type": "usb_record", "payload": recordData}
	for _, conn := range activeConnections {
		conn.WriteJSON(msg)
	}
}

func getDriveModel(driveLetter string) string {
	if runtime.GOOS != "windows" {
		return "N/A"
	}
	drive := strings.TrimSuffix(driveLetter, ":")

	psCmd1 := fmt.Sprintf(`
		$l = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='%s:'" -ErrorAction SilentlyContinue
		if ($l) { 
			$p = $l.GetRelated('Win32_DiskPartition')
			if ($p) { 
				$d = $p.GetRelated('Win32_DiskDrive')
				if ($d) { $d | Select-Object -First 1 -ExpandProperty Model }
			}
		}
	`, drive)

	cmd1 := exec.Command("powershell", "-NoProfile", "-Command", psCmd1)
	out1, _ := cmd1.Output()
	result1 := strings.TrimSpace(string(out1))
	if result1 != "" {
		return result1
	}

	psCmd2 := `
		$usbs = Get-WmiObject Win32_DiskDrive -Filter "InterfaceType='USB'" -ErrorAction SilentlyContinue
		if ($usbs -and $usbs.GetType().IsArray) {
			if ($usbs.Count -eq 1) { $usbs[0].Model }
		} elseif ($usbs) { $usbs.Model }
	`
	cmd2 := exec.Command("powershell", "-NoProfile", "-Command", psCmd2)
	out2, _ := cmd2.Output()
	result2 := strings.TrimSpace(string(out2))
	if result2 != "" {
		return result2
	}

	psCmd3 := fmt.Sprintf(`(Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='%s:'").VolumeName`, drive)
	cmd3 := exec.Command("powershell", "-NoProfile", "-Command", psCmd3)
	out3, _ := cmd3.Output()
	result3 := strings.TrimSpace(string(out3))
	if result3 != "" {
		return "USB Drive (" + result3 + ")"
	}

	return "Generic Flash Disk"
}

func captureScreenAndSize(quality int, scale float64) (string, int, int) {
	if screenshot.NumActiveDisplays() <= 0 {
		return "ERROR_NO_DISPLAY", 0, 0
	}

	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil || img == nil {
		return "LOCKED", 0, 0
	}

	width := bounds.Dx()
	height := bounds.Dy()

	var finalImg image.Image = img

	if scale < 1.0 {
		targetWidth := int(float64(width) * scale)
		if targetWidth < 400 {
			targetWidth = 400
		}

		if targetWidth < width {
			ratio := float64(targetWidth) / float64(width)
			targetHeight := int(float64(height) * ratio)

			dst := image.NewRGBA(image.Rect(0, 0, targetWidth, targetHeight))

			for y := 0; y < targetHeight; y++ {
				for x := 0; x < targetWidth; x++ {
					srcX := x * width / targetWidth
					srcY := y * height / targetHeight
					dst.Set(x, y, img.At(srcX, srcY))
				}
			}
			finalImg = dst
		}
	}

	var buf bytes.Buffer
	err = jpeg.Encode(&buf, finalImg, &jpeg.Options{Quality: quality})
	if err != nil {
		return "ERROR_ENCODE", 0, 0
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), width, height
}

func handleInputEvent(data map[string]interface{}) {
	defer func() {
		if r := recover(); r != nil {
		}
	}()

	evtType, ok := data["event"].(string)
	if !ok {
		return
	}

	if evtType == "mouse_move" {
		xf, ok1 := data["x"].(float64)
		yf, ok2 := data["y"].(float64)
		if ok1 && ok2 {
			setCursorPos(int32(xf), int32(yf))
		}
	} else if evtType == "mouse_click" {
		btn, _ := data["button"].(string)
		state, _ := data["state"].(string)
		var flag uint32
		if btn == "left" {
			if state == "down" {
				flag = MOUSEEVENTF_LEFTDOWN
			} else {
				flag = MOUSEEVENTF_LEFTUP
			}
		} else if btn == "right" {
			if state == "down" {
				flag = MOUSEEVENTF_RIGHTDOWN
			} else {
				flag = MOUSEEVENTF_RIGHTUP
			}
		}
		if flag != 0 {
			mouseEvent(flag, 0, 0, 0, 0)
		}
	} else if evtType == "key" {
		kf, ok := data["key"].(float64)
		state, _ := data["state"].(string)
		if ok {
			key := byte(kf)
			var flag uint32 = 0
			if state == "up" {
				flag = KEYEVENTF_KEYUP
			}
			keybdEvent(key, 0, flag, 0)
		}
	} else if evtType == "mouse_wheel" {
		delta, ok := data["delta"].(float64)
		if ok {
			var wheelAmt int32 = 0
			if delta > 0 {
				wheelAmt = -120 // Scroll down.
			} else if delta < 0 {
				wheelAmt = 120 // Scroll up.
			}

			if wheelAmt != 0 {
				// dwData specifies the scroll amount.
				mouseEvent(MOUSEEVENTF_WHEEL, 0, 0, uint32(wheelAmt), 0)
			}
		}
	}
}

func setCursorPos(x, y int32) { procSetCursorPos.Call(uintptr(x), uintptr(y)) }
func mouseEvent(dwFlags, dx, dy, dwData, dwExtraInfo uint32) {
	procMouseEvent.Call(uintptr(dwFlags), uintptr(dx), uintptr(dy), uintptr(dwData), uintptr(dwExtraInfo))
}
func keybdEvent(bVk byte, bScan byte, dwFlags, dwExtraInfo uint32) {
	procKeybdEvent.Call(uintptr(bVk), uintptr(bScan), uintptr(dwFlags), uintptr(dwExtraInfo))
}

func getUniqueID() string {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 && len(i.HardwareAddr) > 0 {
				return i.HardwareAddr.String()
			}
		}
	}
	h, _ := os.Hostname()
	return fmt.Sprintf("%s-%s", h, getLocalIP())
}

func getRealUserHome() string {
	currentHome, _ := os.UserHomeDir()
	if !strings.Contains(strings.ToLower(currentHome), "systemprofile") {
		return currentHome
	}

	cmd := exec.Command("wmic", "computersystem", "get", "username")
	out, err := cmd.Output()
	var username string
	if err == nil {
		output := string(out)
		output = strings.ReplaceAll(output, "UserName", "")
		output = strings.TrimSpace(output)
		if idx := strings.LastIndex(output, "\\"); idx >= 0 {
			username = output[idx+1:]
		} else {
			username = output
		}
	}
	if username != "" {
		candidate := filepath.Join("C:\\Users", username)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	usersDir := "C:\\Users"
	entries, err := os.ReadDir(usersDir)
	if err == nil {
		var lastModTime time.Time
		var bestCandidate string
		for _, e := range entries {
			if e.IsDir() {
				name := e.Name()
				if name == "Public" || name == "Default" || name == "Default User" || name == "All Users" {
					continue
				}
				info, _ := e.Info()
				if info.ModTime().After(lastModTime) {
					lastModTime = info.ModTime()
					bestCandidate = filepath.Join(usersDir, name)
				}
			}
		}
		if bestCandidate != "" {
			return bestCandidate
		}
	}
	return "C:\\Users\\Public"
}

func runChildProcess(port string) {
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		lineStr, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		lineStr = strings.TrimSpace(lineStr)
		if len(lineStr) == 0 {
			continue
		}

		// Determine the command type by the first character ('S' or 'I').
		cmdChar := lineStr[0]

		if cmdChar == 'S' {
			q := 60
			s := 1.0

			params := lineStr[1:]

			if params != "" {
				var parsedQ int
				var parsedS float64
				n, _ := fmt.Sscanf(params, "%d|%f", &parsedQ, &parsedS)
				if n == 2 {
					q = parsedQ
					s = parsedS
				}
			}

			// Capture screen.
			b64, w, h := captureScreenAndSize(q, s)

			resp := map[string]interface{}{"payload": b64, "width": w, "height": h}
			jsonBytes, _ := json.Marshal(resp)
			conn.Write(jsonBytes)
			conn.Write([]byte("\n"))

		} else if cmdChar == 'I' {
			// Handle input event: strip the leading 'I' and parse the JSON payload.
			jsonStr := lineStr[1:]
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(jsonStr), &data); err == nil {
				handleInputEvent(data)
			}
		}
	}
}

// safeWriteJSON writes a JSON message to a WebSocket connection in a thread-safe manner.
func safeWriteJSON(conn *websocket.Conn, v interface{}) error {
	wsWriteMutex.Lock()
	defer wsWriteMutex.Unlock()
	return conn.WriteJSON(v)
}
