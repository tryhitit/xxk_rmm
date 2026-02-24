package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

const CryptoKey = "0123456789ABCDEF0123456789ABCDEF"

type SafeWebConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

type SafeAgentConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

// SafeAgentConn helper methods
func (s *SafeAgentConn) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Close()
}

func (s *SafeAgentConn) WriteJSON(v interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteJSON(v)
}

func (s *SafeAgentConn) ReadJSON(v interface{}) error {
	return s.conn.ReadJSON(v)
}

var (
	sessionToken string
	config       ServerConfig
	agentConns   = make(map[string]*SafeAgentConn)
	agentLock    sync.RWMutex
	webClients   sync.Map
	downloadChs  = make(map[string]chan []byte)
	dlLock       sync.Mutex
	db           *sql.DB

	// Track connection errors to prevent log flooding
	lastConnectErrorLogged = make(map[string]bool)
	logMutex               sync.Mutex

	// WebSocket upgrader
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

// Data structure definitions

// Group struct
type Group struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ParentID  string `json:"parent_id"` // Empty string means root node
	SortOrder int    `json:"sort_order"`
}

type SavedClient struct {
	ID        string `json:"id"`         // Unique hardware ID
	IP        string `json:"ip"`         // Display IP
	Password  string `json:"password"`   // Connection password
	GroupID   string `json:"group_id"`   // Stores Group.ID
	Alias     string `json:"alias"`      // Alias/hostname
	Mode      string `json:"mode"`       // Connection mode: "active" or "passive"
	SortOrder int    `json:"sort_order"` // Sort weight
}

type ServerConfig struct {
	WebAddr       string        `json:"web_addr"`            // Web listen address
	WebPort       string        `json:"web_port"`            // Web listen port
	WebPassword   string        `json:"web_password"`        // Web login password
	DefaultCPort  string        `json:"default_client_port"` // Default client port
	DefaultCPass  string        `json:"default_client_pass"` // Default client connection password
	FileThreshold int           `json:"file_threshold"`      // Large file threshold (MB)
	TempFileTTL   int           `json:"temp_file_ttl"`       // Temp file retention time (minutes)
	Clients       []SavedClient `json:"clients"`
	Groups        []Group       `json:"groups"` // Changed to struct slice
	DBPath        string        `json:"db_path"`
}

type BatchCommand struct {
	Command string `json:"command"`
}

type BatchFile struct {
	LocalPath  string `json:"local_path"`
	RemotePath string `json:"remote_path"`
	Data       string `json:"data"` // base64
	Overwrite  bool   `json:"overwrite"`
	Run        bool   `json:"run"`
	RunAsAdmin bool   `json:"run_as_admin"`
}

type BatchTask struct {
	Targets  []string       `json:"targets"`
	Commands []BatchCommand `json:"commands"`
	Files    []BatchFile    `json:"files"`
}

// Main entry point
func main() {
	// Initialize session token
	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	sessionToken = hex.EncodeToString(tokenBytes)

	// Load config and database
	loadConfig()
	initDatabase()

	// Ensure temp upload directory exists
	os.MkdirAll("./temp_uploads", 0755)

	// Start temp file cleanup goroutine
	go startTempFileCleaner()

	// Start auto-connect background task
	go autoConnectLoop()

	// Configure Gin web server
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.LoadHTMLGlob("templates/*")
	// Increase upload file size limit (e.g., 2GB)
	r.MaxMultipartMemory = 2048 << 20

	// Static file serving
	r.StaticFS("/downloads", http.Dir("./temp_uploads"))

	// Public routes (no auth)

	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	r.POST("/api/login", func(c *gin.Context) {
		var req struct {
			Password string `json:"password"`
		}
		if err := c.BindJSON(&req); err != nil {
			return
		}

		if req.Password == config.WebPassword {
			c.SetCookie("rmm_sess", sessionToken, 3600*24, "/", "", false, true)
			c.JSON(200, gin.H{"status": "ok"})
		} else {
			c.JSON(401, gin.H{"error": "Incorrect password"})
		}
	})

	// Agent reverse connection endpoint
	r.GET("/ws", func(c *gin.Context) {
		handleAgentWS(c.Writer, c.Request)
	})

	// Protected routes (auth required)

	authorized := r.Group("/")
	authorized.Use(AuthMiddleware())
	{
		authorized.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "index.html", gin.H{
				"DefaultPort":   config.DefaultCPort,
				"DefaultPass":   config.DefaultCPass,
				"FileThreshold": config.FileThreshold,
				"TempFileTTL":   config.TempFileTTL,
			})
		})

		authorized.GET("/logout", func(c *gin.Context) {
			c.SetCookie("rmm_sess", "", -1, "/", "", false, true)
			c.Redirect(http.StatusFound, "/login")
		})

		authorized.GET("/ws/web", func(c *gin.Context) {
			handleWebWS(c.Writer, c.Request)
		})

		api := authorized.Group("/api")
		{
			api.POST("/config/update_settings", func(c *gin.Context) {
				var req struct {
					FileThreshold int `json:"file_threshold"`
					TempFileTTL   int `json:"temp_file_ttl"`
				}
				if err := c.BindJSON(&req); err != nil {
					c.JSON(400, gin.H{"error": "Invalid parameters"})
					return
				}
				agentLock.Lock()
				config.FileThreshold = req.FileThreshold
				config.TempFileTTL = req.TempFileTTL
				agentLock.Unlock()
				go saveConfig()
				c.JSON(200, gin.H{"status": "ok"})
			})

			api.GET("/clients", func(c *gin.Context) {
				type ClientView struct {
					SavedClient
					IsOnline bool `json:"is_online"`
				}
				var view []ClientView
				agentLock.RLock()

				clientsCopy := make([]SavedClient, len(config.Clients))
				copy(clientsCopy, config.Clients)

				sort.Slice(clientsCopy, func(i, j int) bool {
					return clientsCopy[i].SortOrder < clientsCopy[j].SortOrder
				})

				for _, saved := range clientsCopy {
					key := saved.ID
					if key == "" {
						key = saved.IP
					}
					_, online := agentConns[key]
					view = append(view, ClientView{SavedClient: saved, IsOnline: online})
				}
				agentLock.RUnlock()
				c.JSON(200, view)
			})

			// Client reorder endpoint
			api.POST("/client/reorder", func(c *gin.Context) {
				var req struct {
					Updates []struct {
						ID        string `json:"id"`
						SortOrder int    `json:"sort_order"`
					} `json:"updates"`
				}
				if err := c.BindJSON(&req); err != nil {
					return
				}

				agentLock.Lock()
				for _, update := range req.Updates {
					for i := range config.Clients {
						if config.Clients[i].ID == update.ID || (config.Clients[i].ID == "" && config.Clients[i].IP == update.ID) {
							config.Clients[i].SortOrder = update.SortOrder
							break
						}
					}
				}
				agentLock.Unlock()

				go saveConfig()
				broadcastRefresh()
				c.JSON(200, gin.H{"status": "ok"})
			})

			api.GET("/groups", func(c *gin.Context) {
				agentLock.RLock()
				sortedGroups := make([]Group, len(config.Groups))
				copy(sortedGroups, config.Groups)
				sort.Slice(sortedGroups, func(i, j int) bool {
					return sortedGroups[i].SortOrder < sortedGroups[j].SortOrder
				})
				agentLock.RUnlock()
				c.JSON(200, sortedGroups)
			})

			api.POST("/group/add", func(c *gin.Context) {
				var req struct {
					Name     string `json:"name"`
					ParentID string `json:"parent_id"`
				}
				if err := c.BindJSON(&req); err != nil {
					return
				}

				agentLock.Lock()
				defer agentLock.Unlock()

				newID := fmt.Sprintf("grp_%d", time.Now().UnixNano())

				maxOrder := 0
				for _, g := range config.Groups {
					if g.ParentID == req.ParentID && g.SortOrder > maxOrder {
						maxOrder = g.SortOrder
					}
				}

				newGroup := Group{
					ID:        newID,
					Name:      req.Name,
					ParentID:  req.ParentID,
					SortOrder: maxOrder + 10,
				}
				config.Groups = append(config.Groups, newGroup)
				go saveConfig()
				broadcastGroups()
				c.JSON(200, gin.H{"status": "ok", "id": newID})
			})

			api.POST("/group/update", func(c *gin.Context) {
				var req struct {
					ID        string  `json:"id"`
					Name      string  `json:"name"`       // Optional: rename
					ParentID  *string `json:"parent_id"`  // Optional: move parent node (pointer to distinguish whether to update)
					SortOrder *int    `json:"sort_order"` // Optional: reorder
				}
				if err := c.BindJSON(&req); err != nil {
					return
				}

				agentLock.Lock()
				for i := range config.Groups {
					if config.Groups[i].ID == req.ID {
						if req.Name != "" {
							config.Groups[i].Name = req.Name
						}
						if req.ParentID != nil {
							config.Groups[i].ParentID = *req.ParentID
						}
						if req.SortOrder != nil {
							config.Groups[i].SortOrder = *req.SortOrder
						}
						break
					}
				}
				agentLock.Unlock()
				go saveConfig()
				broadcastGroups()
				c.JSON(200, gin.H{"status": "ok"})
			})

			api.POST("/group/delete", func(c *gin.Context) {
				var req struct {
					ID string `json:"id"`
				}
				if err := c.BindJSON(&req); err != nil {
					return
				}

				agentLock.Lock()
				defer agentLock.Unlock()

				// Filter out the group to be deleted
				var newGroups []Group
				for _, g := range config.Groups {
					if g.ID != req.ID {
						// If it's a child group, clear ParentID (becomes root node)
						if g.ParentID == req.ID {
							g.ParentID = ""
						}
						newGroups = append(newGroups, g)
					}
				}
				config.Groups = newGroups

				// Move hosts in this group to default (GroupID="")
				for i, cl := range config.Clients {
					if cl.GroupID == req.ID {
						config.Clients[i].GroupID = ""
					}
				}

				go saveConfig()
				broadcastGroups()
				broadcastRefresh()
				c.JSON(200, gin.H{"status": "ok"})
			})

			api.POST("/client/add", func(c *gin.Context) {
				var req SavedClient
				if err := c.BindJSON(&req); err != nil {
					return
				}
				if req.ID == "" {
					req.ID = req.IP
				}
				addOrUpdateClient(req)
				broadcastRefresh()
				if req.Mode == "active" {
					go connectToAgent(req)
				}
				c.JSON(200, gin.H{"status": "ok"})
			})

			api.POST("/client/remove", func(c *gin.Context) {
				var req struct {
					IP string `json:"ip"`
				}
				if err := c.BindJSON(&req); err != nil {
					return
				}
				removeClient(req.IP)
				agentLock.Lock()
				if conn, ok := agentConns[req.IP]; ok {
					conn.Close()
					delete(agentConns, req.IP)
				}
				agentLock.Unlock()
				broadcastRefresh()
				c.JSON(200, gin.H{"status": "removed"})
			})

			api.POST("/generate_config", func(c *gin.Context) {
				var req struct {
					Port          string `json:"port"`
					Password      string `json:"password"`
					Autostart     bool   `json:"autostart"`
					PassiveMode   bool   `json:"passive_mode"`
					ServerAddr    string `json:"server_addr"`
					ServerPort    string `json:"server_port"`
					ServerPass    string `json:"server_pass"`
					CheckInterval int    `json:"check_interval"`
				}
				if err := c.BindJSON(&req); err != nil {
					return
				}
				jsonBytes, _ := json.Marshal(req)
				encrypted, _ := encrypt(jsonBytes, []byte(CryptoKey))
				c.Header("Content-Disposition", "attachment; filename=config.dat")
				c.Data(200, "application/octet-stream", encrypted)
			})

			api.POST("/send", func(c *gin.Context) {
				var msg map[string]interface{}
				if err := c.BindJSON(&msg); err != nil {
					return
				}
				sendToAgent(msg)
				c.JSON(200, gin.H{"status": "sent"})
			})

			api.POST("/file/upload", func(c *gin.Context) {
				clientID := c.PostForm("client_id")
				path := c.PostForm("path")
				file, header, err := c.Request.FormFile("file")
				if err != nil {
					c.JSON(400, gin.H{"error": "bad file"})
					return
				}
				data, _ := ioutil.ReadAll(file)
				encoded := base64.StdEncoding.EncodeToString(data)
				targetPath := filepath.Join(path, header.Filename)
				sendToAgent(map[string]interface{}{
					"target_id": clientID, "type": "file_upload",
					"payload": map[string]string{"path": targetPath, "data": encoded},
				})
				c.JSON(200, gin.H{"status": "ok"})
			})

			api.POST("/file/stage", func(c *gin.Context) {
				file, err := c.FormFile("file")
				if err != nil {
					c.JSON(400, gin.H{"error": "File receive failed"})
					return
				}
				fileName := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)
				savePath := filepath.Join("./temp_uploads", fileName)
				if err := c.SaveUploadedFile(file, savePath); err != nil {
					c.JSON(500, gin.H{"error": "File save failed"})
					return
				}
				downloadUrl := fmt.Sprintf("/downloads/%s", fileName)
				c.JSON(200, gin.H{"status": "ok", "url": downloadUrl, "filename": file.Filename})
			})

			api.GET("/file/download", func(c *gin.Context) {
				clientID := c.Query("client_id")
				path := c.Query("path")
				ch := make(chan []byte)
				dlLock.Lock()
				downloadChs[clientID] = ch
				dlLock.Unlock()
				sendToAgent(map[string]interface{}{"target_id": clientID, "type": "file_download", "payload": path})
				select {
				case data := <-ch:
					c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(path)))
					c.Data(200, "application/octet-stream", data)
				case <-time.After(15 * time.Second):
					c.String(504, "Timeout")
				}
				dlLock.Lock()
				delete(downloadChs, clientID)
				dlLock.Unlock()
			})

			api.POST("/batch/execute", func(c *gin.Context) {
				var task BatchTask
				if err := c.BindJSON(&task); err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}
				go executeBatchTask(task)
				c.JSON(200, gin.H{"status": "started"})
			})

			api.GET("/usb/records", func(c *gin.Context) {
				clientID := c.Query("client_id")
				keyword := c.Query("keyword")
				startDate := c.Query("start_date")
				endDate := c.Query("end_date")
				page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
				pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
				offset := (page - 1) * pageSize

				query := "SELECT timestamp, client_ip, action, device_name, volume_id, model FROM usb_records WHERE 1=1"
				countQuery := "SELECT COUNT(*) FROM usb_records WHERE 1=1"
				var args []interface{}

				if clientID != "" {
					query += " AND client_ip = ?"
					countQuery += " AND client_ip = ?"
					args = append(args, clientID)
				}
				if keyword != "" {
					like := "%" + keyword + "%"
					query += " AND (device_name LIKE ? OR model LIKE ? OR volume_id LIKE ?)"
					countQuery += " AND (device_name LIKE ? OR model LIKE ? OR volume_id LIKE ?)"
					args = append(args, like, like, like)
				}
				if startDate != "" {
					query += " AND timestamp >= ?"
					countQuery += " AND timestamp >= ?"
					args = append(args, startDate+" 00:00:00")
				}
				if endDate != "" {
					query += " AND timestamp <= ?"
					countQuery += " AND timestamp <= ?"
					args = append(args, endDate+" 23:59:59")
				}

				var total int
				if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}

				query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
				args = append(args, pageSize, offset)

				rows, err := db.Query(query, args...)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}
				defer rows.Close()

				var records []map[string]interface{}
				for rows.Next() {
					var t, ip, act, dev, vol, mod string
					rows.Scan(&t, &ip, &act, &dev, &vol, &mod)
					records = append(records, map[string]interface{}{"timestamp": t, "client_ip": ip, "action": act, "device_name": dev, "volume_id": vol, "model": mod})
				}
				c.JSON(200, gin.H{"total": total, "page": page, "data": records})
			})
		}
	}

	listenAddr := config.WebAddr + ":" + config.WebPort
	log.Printf("Server running at http://%s", listenAddr)
	if err := r.Run(listenAddr); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("rmm_sess")
		if err != nil || cookie != sessionToken {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func handleAgentWS(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth-Pass") != config.DefaultCPass {
		http.Error(w, "Unauthorized", 403)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	var msg map[string]interface{}
	if err := conn.ReadJSON(&msg); err != nil {
		conn.Close()
		return
	}
	if msgType, _ := msg["type"].(string); msgType != "register" {
		conn.Close()
		return
	}
	payload, ok := msg["payload"].(map[string]interface{})
	if !ok {
		conn.Close()
		return
	}

	// Get client-sent information
	uniqueID, _ := payload["id"].(string)
	displayIP, _ := payload["ip"].(string)
	alias, _ := payload["alias"].(string)
	groupName, _ := payload["group"].(string)
	mode, _ := payload["mode"].(string)

	if uniqueID == "" {
		uniqueID = displayIP
	}
	if uniqueID == "" {
		uniqueID = r.RemoteAddr
	}
	if mode == "" {
		mode = "passive"
	}

	// Convert group name to group ID
	var targetGID string
	agentLock.RLock() // Read lock to find group
	for _, g := range config.Groups {
		if g.Name == groupName {
			targetGID = g.ID
			break
		}
	}
	agentLock.RUnlock()

	agentLock.Lock()
	if oldConn, exists := agentConns[uniqueID]; exists {
		oldConn.Close()
	}
	agentConns[uniqueID] = &SafeAgentConn{conn: conn}

	found := false
	for i, c := range config.Clients {
		if c.ID == uniqueID || (c.ID == "" && c.IP == uniqueID) {
			config.Clients[i].ID = uniqueID
			config.Clients[i].IP = displayIP
			config.Clients[i].Mode = "passive"
			if config.Clients[i].Alias == "" {
				config.Clients[i].Alias = alias
			}

			if config.Clients[i].GroupID == "" && targetGID != "" {
				config.Clients[i].GroupID = targetGID
			}

			found = true
			break
		}
	}
	if !found {
		newClient := SavedClient{
			ID:        uniqueID,
			IP:        displayIP,
			Password:  config.DefaultCPass,
			GroupID:   targetGID,
			Alias:     alias,
			Mode:      "passive",
			SortOrder: 0,
		}
		config.Clients = append(config.Clients, newClient)
		go saveConfig()
	} else {
		go saveConfig()
	}
	agentLock.Unlock()
	broadcastRefresh()

	defer func() {
		agentLock.Lock()
		if safeConn, ok := agentConns[uniqueID]; ok && safeConn.conn == conn {
			delete(agentConns, uniqueID)
		}
		agentLock.Unlock()
		conn.Close()
		broadcastRefresh()
	}()

	for {
		var data map[string]interface{}
		err := conn.ReadJSON(&data)
		if err != nil {
			break
		}
		msgType, _ := data["type"].(string)

		if msgType == "download_progress" {
			data["client_id"] = uniqueID
			webClients.Range(func(key, val interface{}) bool {
				swc := val.(*SafeWebConn)
				swc.mu.Lock()
				swc.conn.WriteJSON(data)
				swc.mu.Unlock()
				return true
			})
			continue
		}
		if msgType == "usb_record" {
			if record, ok := data["payload"].(map[string]interface{}); ok {
				saveUSBRecord(uniqueID, record)
			}
			continue
		}
		if msgType == "usb_records" {
			if records, ok := data["payload"].([]interface{}); ok {
				for _, r := range records {
					if record, ok := r.(map[string]interface{}); ok {
						saveUSBRecord(uniqueID, record)
					}
				}
			}
			continue
		}
		if msgType == "file_download_data" {
			pl, ok := data["payload"].(map[string]interface{})
			if ok {
				if dStr, ok := pl["data"].(string); ok {
					raw, _ := base64.StdEncoding.DecodeString(dStr)
					dlLock.Lock()
					if ch, has := downloadChs[uniqueID]; has {
						ch <- raw
					}
					dlLock.Unlock()
				}
			}
			continue
		}
		data["client_id"] = uniqueID
		webClients.Range(func(key, val interface{}) bool {
			swc := val.(*SafeWebConn)
			swc.mu.Lock()
			swc.conn.WriteJSON(data)
			swc.mu.Unlock()
			return true
		})
	}
}

func handleWebWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	safeConn := &SafeWebConn{conn: ws}
	webClients.Store(ws, safeConn)
	broadcastRefresh()
	broadcastGroups()
	go triggerImmediateCheck()
	defer webClients.Delete(ws)

	for {
		var msg map[string]interface{}
		if err := ws.ReadJSON(&msg); err != nil {
			break
		}
		msgType, _ := msg["type"].(string)

		if msgType == "forward_batch" {
			targets, _ := msg["targets"].([]interface{})
			msgBody, _ := msg["payload"].(map[string]interface{})

			for _, t := range targets {
				if targetID, ok := t.(string); ok {
					agentLock.RLock()
					safeConn, exists := agentConns[targetID]
					agentLock.RUnlock()
					if exists {
						safeConn.WriteJSON(msgBody)
					}
				}
			}
		}
		if msgType == "forward_to_agent" {
			if payload, ok := msg["payload"].(map[string]interface{}); ok {
				targetID, _ := msg["target_id"].(string)
				if targetID != "" {
					payload["target_id"] = targetID
					sendToAgent(payload)
				}
			}
		}
	}
}

func initDatabase() {
	if config.DBPath == "" {
		config.DBPath = "./rmm_data.db"
	}
	db, _ = sql.Open("sqlite3", config.DBPath)
	db.Exec(`CREATE TABLE IF NOT EXISTS usb_records (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, client_ip TEXT NOT NULL, action TEXT NOT NULL, device_name TEXT NOT NULL, volume_id TEXT, model TEXT)`)
	db.Exec(`ALTER TABLE usb_records ADD COLUMN model TEXT`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_client_ip ON usb_records(client_ip)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_timestamp ON usb_records(timestamp)`)
}

func executeBatchTask(task BatchTask) {
	for _, targetID := range task.Targets {
		for _, cmd := range task.Commands {
			sendToAgent(map[string]interface{}{"target_id": targetID, "type": "cmd", "payload": cmd.Command})
			time.Sleep(200 * time.Millisecond)
		}
		for _, file := range task.Files {
			remotePath := file.RemotePath
			if strings.HasSuffix(remotePath, "\\") || (len(remotePath) == 2 && remotePath[1] == ':') {
				fileName := filepath.Base(file.LocalPath)
				remotePath = filepath.Join(remotePath, fileName)
			}
			payload := map[string]interface{}{"path": remotePath, "data": file.Data}
			if file.Run {
				payload["run"] = true
				payload["run_as_admin"] = file.RunAsAdmin
			}
			sendToAgent(map[string]interface{}{"target_id": targetID, "type": "file_upload", "payload": payload})
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func autoConnectLoop() {
	for {
		time.Sleep(30 * time.Second)
		triggerImmediateCheck()
	}
}

func startTempFileCleaner() {
	uploadDir := "./temp_uploads"
	checkInterval := 10 * time.Minute
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	agentLock.RLock()
	ttl := config.TempFileTTL
	agentLock.RUnlock()
	if ttl <= 0 {
		ttl = 60
	}
	cleanFiles(uploadDir, time.Duration(ttl)*time.Minute)

	for range ticker.C {
		agentLock.RLock()
		ttlMinutes := config.TempFileTTL
		agentLock.RUnlock()
		if ttlMinutes <= 0 {
			ttlMinutes = 60
		}
		cleanFiles(uploadDir, time.Duration(ttlMinutes)*time.Minute)
	}
}

func cleanFiles(dir string, ttl time.Duration) {
	files, _ := os.ReadDir(dir)
	now := time.Now()
	for _, file := range files {
		info, err := file.Info()
		if err == nil && now.Sub(info.ModTime()) > ttl {
			os.Remove(filepath.Join(dir, file.Name()))
		}
	}
}

func triggerImmediateCheck() {
	agentLock.RLock()
	clientsCopy := make([]SavedClient, len(config.Clients))
	copy(clientsCopy, config.Clients)
	agentLock.RUnlock()
	for _, c := range clientsCopy {
		if c.Mode == "passive" {
			continue
		}
		targetID := c.ID
		if targetID == "" {
			targetID = c.IP
		}
		agentLock.RLock()
		_, ok := agentConns[targetID]
		agentLock.RUnlock()
		if !ok {
			go connectToAgent(c)
		}
	}
}

func connectToAgent(c SavedClient) {
	connectURL := c.IP
	if !strings.Contains(connectURL, ":") && config.DefaultCPort != "" {
		connectURL += ":" + config.DefaultCPort
	}
	u := url.URL{Scheme: "ws", Host: connectURL, Path: "/ws"}
	h := http.Header{}
	h.Add("X-Auth-Pass", c.Password)
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), h)
	connKey := c.ID
	if connKey == "" {
		connKey = c.IP
	}

	if err != nil {
		logMutex.Lock()
		logged := lastConnectErrorLogged[connKey]
		lastConnectErrorLogged[connKey] = true
		logMutex.Unlock()
		if !logged {
			log.Printf("Connect failed %s: %v", connKey, err)
		}
		return
	}
	logMutex.Lock()
	lastConnectErrorLogged[connKey] = false
	logMutex.Unlock()

	agentLock.Lock()
	agentConns[connKey] = &SafeAgentConn{conn: conn}
	agentLock.Unlock()
	broadcastRefresh()

	defer func() {
		agentLock.Lock()
		if safeConn, ok := agentConns[connKey]; ok {
			delete(agentConns, connKey)
			agentLock.Unlock()
			safeConn.Close()
		} else {
			agentLock.Unlock()
		}
		broadcastRefresh()
	}()

	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}
		msgType, _ := msg["type"].(string)

		if msgType == "download_progress" {
			msg["client_id"] = connKey
			webClients.Range(func(key, val interface{}) bool {
				swc := val.(*SafeWebConn)
				swc.mu.Lock()
				swc.conn.WriteJSON(msg)
				swc.mu.Unlock()
				return true
			})
			continue
		}
		if msgType == "usb_record" {
			if record, ok := msg["payload"].(map[string]interface{}); ok {
				saveUSBRecord(connKey, record)
			}
		}
		if msg["type"] == "id_report" {
			payload, _ := msg["payload"].(map[string]interface{})
			realID, _ := payload["id"].(string)
			if realID != "" && realID != connKey {
				agentLock.Lock()
				found := false
				for i, c := range config.Clients {
					if c.ID == connKey {
						config.Clients[i].ID = realID
						found = true
						break
					}
				}
				if safeConn, ok := agentConns[connKey]; ok {
					delete(agentConns, connKey)
					agentConns[realID] = safeConn
				}
				agentLock.Unlock()
				if found {
					connKey = realID
					go saveConfig()
					broadcastRefresh()
				}
			}
			continue
		}
		if msg["type"] == "file_download_data" {
			pl := msg["payload"].(map[string]interface{})
			if dStr, ok := pl["data"].(string); ok {
				raw, _ := base64.StdEncoding.DecodeString(dStr)
				dlLock.Lock()
				if ch, has := downloadChs[connKey]; has {
					ch <- raw
				}
				dlLock.Unlock()
			}
			continue
		}
		msg["client_id"] = connKey
		webClients.Range(func(key, val interface{}) bool {
			swc := val.(*SafeWebConn)
			swc.mu.Lock()
			swc.conn.WriteJSON(msg)
			swc.mu.Unlock()
			return true
		})
	}
}

func saveUSBRecord(clientID string, record map[string]interface{}) {
	t, _ := record["timestamp"].(string)
	a, _ := record["action"].(string)
	d, _ := record["device_name"].(string)
	v, _ := record["volume_id"].(string)
	m, _ := record["model"].(string)
	db.Exec(`INSERT INTO usb_records (timestamp, client_ip, action, device_name, volume_id, model) VALUES (?, ?, ?, ?, ?, ?)`, t, clientID, a, d, v, m)
}

func sendToAgent(msg map[string]interface{}) {
	targetID := msg["target_id"].(string)
	agentLock.RLock()
	safeConn, ok := agentConns[targetID]
	agentLock.RUnlock()
	if ok {
		safeConn.WriteJSON(msg)
	}
}

func broadcastRefresh() {
	webClients.Range(func(key, val interface{}) bool {
		swc := val.(*SafeWebConn)
		swc.mu.Lock()
		swc.conn.WriteJSON(map[string]interface{}{"type": "refresh_list"})
		swc.mu.Unlock()
		return true
	})
}
func broadcastGroups() {
	webClients.Range(func(key, val interface{}) bool {
		swc := val.(*SafeWebConn)
		swc.mu.Lock()
		swc.conn.WriteJSON(map[string]interface{}{"type": "groups", "payload": config.Groups})
		swc.mu.Unlock()
		return true
	})
}

func loadConfig() {
	f, err := os.Open("server_config.json")
	if err != nil {
		config = ServerConfig{
			WebAddr: "0.0.0.0", WebPort: "8080", WebPassword: "admin",
			DefaultCPort: "9000", DefaultCPass: "123456",
			FileThreshold: 10, TempFileTTL: 60,
			Groups: []Group{{ID: "default", Name: "Default Group", SortOrder: 0}},
			DBPath: "./rmm_data.db",
		}
		saveConfig()
		return
	}
	defer f.Close()

	// Try reading as map[string]interface{} to detect legacy config format
	rawBytes, _ := ioutil.ReadAll(f)
	var rawMap map[string]interface{}
	json.Unmarshal(rawBytes, &rawMap)

	// Detect if groups is a string array
	isLegacy := false
	if gVal, ok := rawMap["groups"]; ok {
		if _, ok := gVal.([]interface{})[0].(string); ok {
			isLegacy = true
		}
	}

	// Handle migration
	if isLegacy {
		type LegacyConfig struct {
			ServerConfig          // embed
			Groups       []string `json:"groups"`
		}
		var legacy LegacyConfig
		json.Unmarshal(rawBytes, &legacy)

		config = legacy.ServerConfig
		config.Groups = []Group{}

		// Build Name -> ID mapping
		nameToID := make(map[string]string)

		// Migrate groups
		for i, gName := range legacy.Groups {
			gid := fmt.Sprintf("grp_legacy_%d", i)
			nameToID[gName] = gid
			config.Groups = append(config.Groups, Group{
				ID: gid, Name: gName, SortOrder: i * 10,
			})
		}

		// Migrate clients (clients Group in Raw Map is still a string name)
		type LegacyClient struct {
			SavedClient
			Group string `json:"group"` // Old field name
		}
		var rawClients struct {
			Clients []LegacyClient `json:"clients"`
		}
		json.Unmarshal(rawBytes, &rawClients)

		config.Clients = []SavedClient{}
		for _, lc := range rawClients.Clients {
			newC := lc.SavedClient
			if gid, ok := nameToID[lc.Group]; ok {
				newC.GroupID = gid
			} else {
				newC.GroupID = ""
			}
			config.Clients = append(config.Clients, newC)
		}

		log.Println("Config migrated to nested groups structure.")
		saveConfig()

	} else {
		json.Unmarshal(rawBytes, &config)
	}

	if config.FileThreshold <= 0 {
		config.FileThreshold = 10
	}
	if config.TempFileTTL <= 0 {
		config.TempFileTTL = 60
	}
}

func saveConfig() {
	agentLock.RLock()
	d, _ := json.MarshalIndent(config, "", "  ")
	agentLock.RUnlock()
	ioutil.WriteFile("server_config.json", d, 0644)
}

func addOrUpdateClient(c SavedClient) {
	agentLock.Lock()
	defer agentLock.Unlock()

	maxOrder := 0
	for _, exist := range config.Clients {
		if exist.SortOrder > maxOrder {
			maxOrder = exist.SortOrder
		}
	}

	found := false
	for i, exist := range config.Clients {
		if (c.ID != "" && exist.ID == c.ID) || (c.ID == "" && exist.IP == c.IP) {
			if c.Mode == "" {
				c.Mode = exist.Mode
			}
			if c.SortOrder == 0 {
				c.SortOrder = exist.SortOrder
			}
			config.Clients[i] = c
			found = true
			break
		}
	}
	if !found {
		if c.Mode == "" {
			c.Mode = "active"
		}
		if c.SortOrder == 0 {
			c.SortOrder = maxOrder + 10
		}
		config.Clients = append(config.Clients, c)
	}
	go saveConfig()
}

func removeClient(idOrIp string) {
	agentLock.Lock()
	defer agentLock.Unlock()
	var newClients []SavedClient
	for _, c := range config.Clients {
		if c.ID != idOrIp && c.IP != idOrIp {
			newClients = append(newClients, c)
		}
	}
	config.Clients = newClients
	d, _ := json.MarshalIndent(config, "", "  ")
	ioutil.WriteFile("server_config.json", d, 0644)
}

func encrypt(data, key []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}
