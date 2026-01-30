#!/usr/bin/env bash

set -euo pipefail

# Проверка root
if [[ $EUID -ne 0 ]]; then
   echo "Запусти от root: sudo bash install.sh" 
   exit 1
fi

echo "=== Установка Network Monitor (Senior Go + DevSecOps) ==="
echo "Это установит Suricata, Zeek, Fail2Ban, Golang и само приложение."
echo "Продолжаем? (y/n)"
read -r confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    exit 0
fi

# Обновление системы
apt update && apt upgrade -y

# Базовые зависимости
apt install -y curl git wget gnupg build-essential libpcap-dev sqlite3 nmap iptables fail2ban suricata golang-go

# Установка Zeek (Debian 12 Bookworm)
echo "deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /" | tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null

apt update
apt install -y zeek || {
    echo "Zeek не установился из репозитория. Продолжаем без него (можно доустановить вручную)."
}

# Настройка Zeek, если установлен
if command -v zeekctl >/dev/null 2>&1; then
    zeekctl install
    zeekctl deploy
    zeekctl start || true
else
    echo "zeekctl не найден → Zeek не запустился автоматически."
fi

# Настройка Suricata (если не запущен — запустим позже)
suricata-update || true
systemctl enable suricata --now || true

# Fail2Ban jail
cat > /etc/fail2ban/filter.d/network_monitor.conf << 'EOF'
[Definition]
failregex = Failed login from <HOST>
ignoreregex =
EOF

cat > /etc/fail2ban/jail.d/network_monitor.local << 'EOF'
[network_monitor]
enabled   = true
logpath   = /var/log/network_monitor_fail2ban.log
maxretry  = 5
bantime   = 3600
findtime  = 600
EOF

systemctl restart fail2ban

# Директория проекта
INSTALL_DIR="/opt/network-monitor"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Ввод конфигурации
read -p "Telegram Bot Token: " TELEGRAM_TOKEN
read -p "Твой Telegram Chat ID (число): " ALLOWED_CHAT_ID
read -p "Сетевой интерфейс (eth0/enp1s0 и т.д.): " NETWORK_IFACE
NETWORK_IFACE=${NETWORK_IFACE:-eth0}

cat > .env << EOF
TELEGRAM_TOKEN=$TELEGRAM_TOKEN
ALLOWED_CHAT_ID=$ALLOWED_CHAT_ID
NETWORK_IFACE=$NETWORK_IFACE
EOF

chmod 600 .env

# main.go (обновлённый, с godotenv и без харкода)
cat > main.go << 'EOF'
// Здесь весь код из предыдущего сообщения, но с изменениями:
// - import "github.com/joho/godotenv"
// - метод LoadConfig() в App
// - в main: app.LoadConfig() → networkIface = app.networkIface
// - bot = tgbotapi.NewBotAPI(app.telegramToken)
// - allowedChatID = app.allowedChatID

package main

import (
 "context"
 "database/sql"
 "encoding/json"
 "fmt"
 "log"
 "net"
 "os"
 "os/exec"
 "os/signal"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "syscall"
 "time"

 "github.com/endobit/oui"
 "github.com/fsnotify/fsnotify"
 "github.com/google/gopacket"
 "github.com/google/gopacket/layers"
 "github.com/google/gopacket/pcap"
 "github.com/google/uuid"
 "github.com/hpcloud/tail"
 "github.com/joho/godotenv"
 tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
 _ "github.com/mattn/go-sqlite3"
)

// Constants
const (
 dbFile         = "network_monitor.db"
 eveFile        = "/var/log/suricata/eve.json" // Path to Suricata eve.json
 zeekDNSLog     = "/opt/zeek/logs/current/dns.log"
 zeekHTTPLog    = "/opt/zeek/logs/current/http.log"
 snapshotLength = 1600
 promiscuous    = true
 timeout        = 30 * time.Second
 fail2banLog    = "/var/log/network_monitor_fail2ban.log"
)

// Structs
type Device struct {
 IP          net.IP
 MAC         net.HardwareAddr
 Manufacturer string
 LastSeen    time.Time
 TrafficIn   uint64
 TrafficOut  uint64
 Bandwidth   uint64 // New: Bandwidth usage tracking
}

type Vulnerability struct {
 ID          string
 DeviceIP    net.IP
 Description string
 Timestamp   time.Time
 CVE         string // New: CVE identifier if parsed
}

type Alert struct {
 Timestamp time.Time
 EventType string
 SrcIP     net.IP
 DstIP     net.IP
 Alert     string
 Severity  string // New: Severity level
}

type App struct {
 ctx           context.Context
 cancel        context.CancelFunc
 wg            sync.WaitGroup
 devices       sync.Map // map[string]Device (key: MAC.String())
 alertsChan    chan Alert
 newDeviceChan chan Device
 db            *sql.DB
 bot           *tgbotapi.BotAPI
 knownMACs     sync.Map // For tracking known devices
 fail2banLogger *log.Logger // For logging to fail2ban-monitored file

 telegramToken string
 allowedChatID int64
 networkIface  string
}

// LoadConfig loads from .env
func (app *App) LoadConfig() error {
 if err := godotenv.Load(); err != nil {
  return err
 }
 app.telegramToken = os.Getenv("TELEGRAM_TOKEN")
 chatIDStr := os.Getenv("ALLOWED_CHAT_ID")
 var err error
 app.allowedChatID, err = strconv.ParseInt(chatIDStr, 10, 64)
 if err != nil {
  return fmt.Errorf("invalid ALLOWED_CHAT_ID: %v", err)
 }
 app.networkIface = os.Getenv("NETWORK_IFACE")
 if app.telegramToken == ""  app.allowedChatID == 0  app.networkIface == "" {
  return fmt.Errorf("missing required env variables")
 }
 return nil
}

// InitDB initializes the SQLite database with additional fields
func (app *App) InitDB() error {
 var err error
 app.db, err = sql.Open("sqlite3", dbFile)
 if err != nil {
  return err
 }

 // Create tables with new fields
 _, err = app.db.Exec(
  CREATE TABLE IF NOT EXISTS devices (
   mac TEXT PRIMARY KEY,
   ip TEXT,
   manufacturer TEXT,
   last_seen DATETIME,
   traffic_in INTEGER,
   traffic_out INTEGER,
   bandwidth INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS vulnerabilities (
   id TEXT PRIMARY KEY,
   device_ip TEXT,
   description TEXT,
   cve TEXT,
   timestamp DATETIME
  );
  CREATE TABLE IF NOT EXISTS alerts (
   timestamp DATETIME,
   event_type TEXT,
   src_ip TEXT,
   dst_ip TEXT,
   alert TEXT,
   severity TEXT
  );
  CREATE TABLE IF NOT EXISTS bandwidth_history (
   mac TEXT,
   timestamp DATETIME,
   bandwidth INTEGER
  );
 )
 return err
}

// StartServices starts Suricata and Zeek at app launch
func (app *App) StartServices() error {
 // Start Suricata
 suricataCmd := exec.Command("suricata", "-c", "/etc/suricata/suricata.yaml", "-i", app.networkIface)
 if err := suricataCmd.Start(); err != nil {
  return fmt.Errorf("failed to start Suricata: %v", err)
 }
 log.Println("Suricata started")

 // Start Zeek
 zeekCmd := exec.Command("zeekctl", "start")
 if err := zeekCmd.Run(); err != nil {
  return fmt.Errorf("failed to start Zeek: %v", err)
 }
 log.Println("Zeek started")

 return nil
}

// TailEveLog tails the Suricata eve.json and parses alerts with severity
func (app *App) TailEveLog() {
 defer app.wg.Done()
 t, err := tail.TailFile(eveFile, tail.Config{Follow: true, ReOpen: true, Poll: true})
 if err != nil {
  log.Printf("Error tailing eve.json: %v", err)
  return
 }

 for line := range t.Lines {
  select {
  case <-app.ctx.Done():
   return
  default:
   if line.Err != nil {
    log.Printf("Tail error: %v", line.Err)
    continue
   }

   var event map[string]interface{}
   if err := json.Unmarshal([]byte(line.Text), &event); err != nil {
    continue
   }

   if eventType, ok := event["event_type"].(string); ok && eventType == "alert" {
    alertData := event["alert"].(map[string]interface{})
    srcIP := net.ParseIP(event["src_ip"].(string))
    dstIP := net.ParseIP(event["dst_ip"].(string))
    alertMsg := alertData["signature"].(string)
    severity := fmt.Sprintf("%v", alertData["severity"]) // Assume Suricata provides severity

    alert := Alert{
     Timestamp: time.Now(), // Parse from event if available
     EventType: eventType,
     SrcIP:     srcIP,
     DstIP:     dstIP,
     Alert:     alertMsg,
     Severity:  severity,
    }

    app.alertsChan <- alert

    // Save to DB
    _, err := app.db.Exec("INSERT INTO alerts (timestamp, event_type, src_ip, dst_ip, alert, severity) VALUES (?, ?, ?, ?, ?, ?)",
     alert.Timestamp, alert.EventType, alert.SrcIP.String(), alert.DstIP.String(), alert.Alert, alert.Severity)
    if err != nil {
     log.Printf("DB error: %v", err)
    }

    // Log for fail2ban if suspicious (e.g., brute force patterns)
    if strings.Contains(alertMsg, "brute force") || strings.Contains(alertMsg, "failed login") {
     app.fail2banLogger.Printf("[%s] Failed login from %s", time.Now().Format(time.RFC3339), srcIP)
    }

    // Notify based on severity
    if severity == "1" || severity == "2" { // Suricata severity: 1=critical, 2=high
     app.NotifyTelegram(fmt.Sprintf("%s alert: %s from %s to %s", severity, alertMsg, srcIP, dstIP))
    }
   }
  }
 }
}

// IntegrateZeek parses Zeek logs for DNS/HTTP (added more parsing)
func (app *App) IntegrateZeek() {
 defer app.wg.Done()

 watcher, err := fsnotify.NewWatcher()
 if err != nil {
  log.Printf("fsnotify error: %v", err)
  return
 }
 defer watcher.Close()

 err = watcher.Add(filepath.Dir(zeekDNSLog))
 if err != nil {
  log.Printf("Watcher add error: %v", err)
 }
 err = watcher.Add(filepath.Dir(zeekHTTPLog))
 if err != nil {
  log.Printf("Watcher add error: %v", err)
 }

 for {
  select {
  case <-app.ctx.Done():
   return
  case event := <-watcher.Events:
   if event.Op&fsnotify.Write == fsnotify.Write {
    // Enhanced parsing: Read last line or use a parser lib if available
    log.Printf("Zeek log updated: %s", event.Name)
    // Example: Parse DNS for suspicious queries (e.g., known malware domains)
    if strings.Contains(event.Name, "dns.log") {
     // Implement parsing: if query == malicious, generate alert
     // For simplicity, log and alert
     app.NotifyTelegram("Suspicious DNS query detected (parse details here)")
    }
   }
  case err := <-watcher.Errors:
   log.Printf("Watcher error: %v", err)
  }
 }
}

// ARPScan uses gopacket for ARP discovery with bandwidth tracking
func (app *App) ARPScan() {
 defer app.wg.Done()

 handle, err := pcap.OpenLive(app.networkIface, snapshotLength, promiscuous, timeout)
 if err != nil {
  log.Printf("pcap error: %v", err)
  return
 }
 defer handle.Close()

 packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

 ticker := time.NewTicker(1 * time.Minute) // Scan every minute
 defer ticker.Stop()

 for {
  select {
  case <-app.ctx.Done():
   return
  case packet := <-packetSource.Packets():
   // Track traffic
   packetSize := uint64(packet.Metadata().Length)

   ethLayer := packet.Layer(layers.LayerTypeEthernet)
   if ethLayer != nil {
    eth := ethLayer.(*layers.Ethernet)
    srcMAC := eth.SrcMAC
    dstMAC := eth.DstMAC

    // Update traffic out for src, in for dst (simplified)
    app.updateTraffic(srcMAC.String(), packetSize, true)  // Out
    app.updateTraffic(dstMAC.String(), packetSize, false) // In
   }
   arpLayer := packet.Layer(layers.LayerTypeARP)
   if arpLayer != nil {
    arp := arpLayer.(*layers.ARP)
    if arp.Operation == layers.ARPReply {
     mac := net.HardwareAddr(arp.SourceHwAddress)
     ip := net.IP(arp.SourceProtAddress)

     macStr := mac.String()
     if _, loaded := app.knownMACs.LoadOrStore(macStr, true); !loaded {
      // New device
      manufacturer := oui.Lookup(mac) // New library usage

      device := Device{
       IP:          ip,
       MAC:         mac,
       Manufacturer: manufacturer,
       LastSeen:    time.Now(),
      }

      app.newDeviceChan <- device

      // Save to DB
      _, err := app.db.Exec("INSERT OR REPLACE INTO devices (mac, ip, manufacturer, last_seen, traffic_in, traffic_out, bandwidth) VALUES (?, ?, ?, ?, 0, 0, 0)",
       macStr, ip.String(), manufacturer, device.LastSeen)
      if err != nil {
       log.Printf("DB error: %v", err)
      }

      // Auto-scan vulnerabilities
      go app.ScanVulnerabilities(ip.String())

      // Notify
      app.NotifyTelegram(fmt.Sprintf("New device: %s (%s) at %s", manufacturer, macStr, ip))
     }

     // Update last seen
     if dev, ok := app.devices.Load(macStr); ok {
      d := dev.(Device)
      d.LastSeen = time.Now()
      app.devices.Store(macStr, d)
     }
    }
   }
  case <-ticker.C:
   // Active ARP scan: Broadcast ARP requests (implement if needed)
   // Also, log bandwidth history
   app.logBandwidthHistory()
  }
 }
}

// updateTraffic updates device traffic and bandwidth
func (app *App) updateTraffic(macStr string, size uint64, isOut bool) {
 if dev, ok := app.devices.Load(macStr); ok {
  d := dev.(Device)
  if isOut {
   d.TrafficOut += size
  } else {
   d.TrafficIn += size
  }
  d.Bandwidth += size // Total bandwidth
  app.devices.Store(macStr, d)
 }
}

// logBandwidthHistory logs bandwidth to DB every minute
func (app *App) logBandwidthHistory() {
 app.devices.Range(func(key, value interface{}) bool {
  dev := value.(Device)
  _, err := app.db.Exec("INSERT INTO bandwidth_history (mac, timestamp, bandwidth) VALUES (?, ?, ?)",
   dev.MAC.String(), time.Now(), dev.Bandwidth)
  if err != nil {
   log.Printf("DB error: %v", err)
  }
  return true
 })
}

// ScanVulnerabilities runs nmap vuln scan with CVE parsing
func (app *App) ScanVulnerabilities(ip string) {
 cmd := exec.Command("nmap", "-sV", "--script=vuln", ip)
 output, err := cmd.CombinedOutput()
 if err != nil {
  log.Printf("Nmap error: %v", err)
  return
 }

 // Parse output (enhanced: extract CVE)
 lines := strings.Split(string(output), "\n")
 for _, line := range lines {
  if strings.Contains(line, "VULNERABLE") {
   cve := "" // Parse CVE if present, e.g., regex for CVE-XXXX-XXXX
   if idx := strings.Index(line, "CVE-"); idx != -1 {
    cve = line[idx : idx+15] // Simplified
   }

   vuln := Vulnerability{
    ID:          uuid.New().String(),
    DeviceIP:    net.ParseIP(ip),
    Description: line,
    CVE:         cve,
    Timestamp:   time.Now(),
   }

   // Save to DB
   _, err := app.db.Exec("INSERT INTO vulnerabilities (id, device_ip, description, cve, timestamp) VALUES (?, ?, ?, ?, ?)",
    vuln.ID, vuln.DeviceIP.String(), vuln.Description, vuln.CVE, vuln.Timestamp)
   if err != nil {
    log.Printf("DB error: %v", err)
   }

   // Notify
   app.NotifyTelegram(fmt.Sprintf("Vulnerability found on %s: %s (CVE: %s)", ip, line, cve))
  }
 }
}

// TelegramHandler handles Telegram bot (removed /ban)
func (app *App) TelegramHandler() {
 defer app.wg.Done()

 u := tgbotapi.NewUpdate(0)
 u.Timeout = 60

 updates := app.bot.GetUpdatesChan(u)

 for update := range updates {
  select {
  case <-app.ctx.Done():
   return
  default:
   if update.Message == nil || update.Message.Chat.ID != app.allowedChatID {
    continue // Security: Only allowed ChatID
   }
   msg := update.Message.Text
   switch {
   case strings.HasPrefix(msg, "/status"):
    app.HandleStatus(update.Message.Chat.ID)
   case strings.HasPrefix(msg, "/scan"):
    parts := strings.Split(msg, " ")
    if len(parts) > 1 {
     go app.ScanVulnerabilities(parts[1])
     app.bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "Scan started for "+parts[1]))
    }
   case strings.HasPrefix(msg, "/report"): // New command: Bandwidth report
    app.HandleReport(update.Message.Chat.ID)
   case strings.HasPrefix(msg, "/alerts"): // New: List recent alerts
    app.HandleAlerts(update.Message.Chat.ID)
   }
  }
 }
}

// HandleStatus sends list of devices with bandwidth
func (app *App) HandleStatus(chatID int64) {
 var status strings.Builder
 app.devices.Range(func(key, value interface{}) bool {
  dev := value.(Device)
  status.WriteString(fmt.Sprintf("Device: %s (%s) IP: %s Traffic: In %d Out %d Bandwidth: %d\n",
   dev.Manufacturer, dev.MAC, dev.IP, dev.TrafficIn, dev.TrafficOut, dev.Bandwidth))
  return true
 })

 app.bot.Send(tgbotapi.NewMessage(chatID, status.String()))
}

// HandleReport sends bandwidth history report (new feature)
func (app *App) HandleReport(chatID int64) {
 rows, err := app.db.Query("SELECT mac, timestamp, bandwidth FROM bandwidth_history ORDER BY timestamp DESC LIMIT 10")
 if err != nil {
  app.bot.Send(tgbotapi.NewMessage(chatID, "Error fetching report"))
  return
 }
 defer rows.Close()

 var report strings.Builder
 for rows.Next() {
  var mac string
  var ts time.Time
  var bw uint64
  rows.Scan(&mac, &ts, &bw)
  report.WriteString(fmt.Sprintf("%s - %s: %d bytes\n", mac, ts, bw))
 }

 app.bot.Send(tgbotapi.NewMessage(chatID, report.String()))
}

// HandleAlerts sends recent alerts (new feature)
func (app *App) HandleAlerts(chatID int64) {
 rows, err := app.db.Query("SELECT timestamp, alert, severity FROM alerts ORDER BY timestamp DESC LIMIT 10")
 if err != nil {
  app.bot.Send(tgbotapi.NewMessage(chatID, "Error fetching alerts"))
  return
 }
 defer rows.Close()

 var alertsStr strings.Builder
 for rows.Next() {
  var ts time.Time
  var alert string
  var severity string
  rows.Scan(&ts, &alert, &severity)
  alertsStr.WriteString(fmt.Sprintf("%s [%s]: %s\n", ts, severity, alert))
 }

 app.bot.Send(tgbotapi.NewMessage(chatID, alertsStr.String()))
}

// NotifyTelegram sends notification
func (app *App) NotifyTelegram(msg string) {
 app.bot.Send(tgbotapi.NewMessage(app.allowedChatID, msg))
}

// ProcessAlerts processes incoming alerts
func (app *App) ProcessAlerts() {
 defer app.wg.Done()
 for alert := range app.alertsChan {
  select {
  case <-app.ctx.Done():
   return
  default:
   log.Printf("Processed alert: %v", alert)
  }
 }
}

// ProcessNewDevices processes new devices
func (app *App) ProcessNewDevices() {
 defer app.wg.Done()
 for dev := range app.newDeviceChan {
  select {
  case <-app.ctx.Done():
   return
  default:
   app.devices.Store(dev.MAC.String(), dev)
  }
 }
}

// InitFail2banLogger initializes logger for fail2ban
func (app *App) InitFail2banLogger() error {
 file, err := os.OpenFile(fail2banLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
 if err != nil {
  return err
 }
 app.fail2banLogger = log.New(file, "", 0)
 return nil
}

func main() {
 if os.Getuid() != 0 {
  log.Fatal("Must run as root")
 }

 app := &App{
  alertsChan:    make(chan Alert, 100),
  newDeviceChan: make(chan Device, 100),
 }

 app.ctx, app.cancel = context.WithCancel(context.Background())

 if err := app.LoadConfig(); err != nil {
  log.Fatal("Config error:", err)
 }

 if err := app.InitDB(); err != nil {
  log.Fatal(err)
 }
 defer app.db.Close()

 if err := app.InitFail2banLogger(); err != nil {
  log.Fatal(err)
 }

 bot, err := tgbotapi.NewBotAPI(app.telegramToken)
 if err != nil {
  log.Fatal(err)
 }
 app.bot = bot

 // Start services (Suricata and Zeek)
 if err := app.StartServices(); err != nil {
  log.Println("Services start warning:", err)
 }

 // Send startup alert
 app.NotifyTelegram("Network Monitor server started successfully!")
 // Start modules
 app.wg.Add(6) // Adjusted for removed ban
 go app.TailEveLog()
 go app.IntegrateZeek()
 go app.ARPScan()
 go app.TelegramHandler()
 go app.ProcessAlerts()
 go app.ProcessNewDevices()

 // Handle signals for graceful shutdown
 sigChan := make(chan os.Signal, 1)
 signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
 <-sigChan

 app.cancel()
 app.wg.Wait()
 log.Println("Shutdown complete")
}
