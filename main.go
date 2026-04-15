package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type TemplateVM struct {
	Nombre        string
	Descripcion   string
	PlantillaBase string
	LlaveGenerada bool
	NombreLlave   string
}

type DiscoCompartido struct {
	Nombre           string
	Ruta             string
	PlantillaOrigen  string
	SistemaOperativo string
	Estado           string
	ConectadoA       string
	TieneSO          bool
	Tipo             string
}

// NUEVA ESTRUCTURA: Máquina Virtual de Usuario
type UserVM struct {
	Nombre        string
	Descripcion   string
	PlantillaBase string
	DiscoAsignado string
	DiscoTieneSO  bool
	LlaveGenerada bool
	NombreLlave   string
}

type ServiceDeployment struct {
	VMName          string
	ServiceName     string
	RuntimeBinary   string
	NatRuleName     string
	AppHostPort     string
	AppGuestPort    string
	AppEndpoint     string
	DestinationPath string
	StartCommand    string
	CounterFile     string
	ZipFilename     string
	Status          string
	Enabled         string
	LastLogTail     string
	LastChecked     string
}

var ListaDiscos []DiscoCompartido
var ListaUserVMs []UserVM // Lista para el nuevo dashboard
var ListaServicios []ServiceDeployment
var LlavesSshActivas bool = false

var (
	templatesDB []TemplateVM
	dbMutex     sync.Mutex
	tmpl        *template.Template
)

const vboxCommandTimeout = 12 * time.Second
const vboxCreateDiskTimeout = 10 * time.Minute
const sshBootTimeout = 2 * time.Minute
const diskSizeNewMB = 5120
const diskSizeMinCloneMB = 10240

var allowedRuntimeBinaries = map[string]bool{
	"python3": true,
	"node":    true,
	"bash":    true,
	"java":    true,
	"go":      true,
}

type PageData struct {
	Templates     []TemplateVM
	Discos        []DiscoCompartido
	UserVMs       []UserVM // Pasamos los usuarios al HTML
	Services      []ServiceDeployment
	LlavesActivas bool
	Error         string
	Info          string
}

type AppState struct {
	Templates        []TemplateVM        `json:"templates"`
	Discos           []DiscoCompartido   `json:"discos"`
	UserVMs          []UserVM            `json:"user_vms"`
	Services         []ServiceDeployment `json:"services"`
	LlavesSshActivas bool                `json:"llaves_ssh_activas"`
}

const appStateFile = "estado_dashboard.json"

func init() {
	funcMap := template.FuncMap{
		"contains": strings.Contains,
	}
	tmpl = template.Must(template.New("index.html").Funcs(funcMap).ParseFiles("templates/index.html"))
}

func saveAppStateLocked() error {
	state := AppState{
		Templates:        templatesDB,
		Discos:           ListaDiscos,
		UserVMs:          ListaUserVMs,
		Services:         ListaServicios,
		LlavesSshActivas: LlavesSshActivas,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := appStateFile + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	// En Windows, os.Rename puede fallar si el destino ya existe.
	if err := os.Remove(appStateFile); err != nil && !os.IsNotExist(err) {
		return err
	}

	return os.Rename(tmpPath, appStateFile)
}

func normalizeLoadedStateLocked() {
	for i := range ListaServicios {
		if strings.TrimSpace(ListaServicios[i].NatRuleName) == "" && strings.TrimSpace(ListaServicios[i].ServiceName) != "" {
			ListaServicios[i].NatRuleName = buildServiceNatRuleName(ListaServicios[i].ServiceName)
		}

		hostPort := strings.TrimSpace(ListaServicios[i].AppHostPort)
		if hostPort != "" {
			if strings.TrimSpace(ListaServicios[i].AppEndpoint) == "" {
				ListaServicios[i].AppEndpoint = fmt.Sprintf("http://127.0.0.1:%s", hostPort)
			}
			if strings.TrimSpace(ListaServicios[i].AppGuestPort) == "" {
				ListaServicios[i].AppGuestPort = inferGuestAppPortForRuntime(ListaServicios[i].StartCommand, ListaServicios[i].RuntimeBinary)
			}
		}
	}
}

func loadAppState() error {
	data, err := os.ReadFile(appStateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state AppState
	if err := json.Unmarshal(data, &state); err != nil {
		corruptPath := fmt.Sprintf("%s.corrupt-%d", appStateFile, time.Now().Unix())
		_ = os.Rename(appStateFile, corruptPath)
		return err
	}

	dbMutex.Lock()
	templatesDB = state.Templates
	ListaDiscos = state.Discos
	ListaUserVMs = state.UserVMs
	ListaServicios = state.Services
	LlavesSshActivas = state.LlavesSshActivas
	if !LlavesSshActivas {
		for _, t := range templatesDB {
			if t.LlaveGenerada {
				LlavesSshActivas = true
				break
			}
		}
	}
	normalizeLoadedStateLocked()
	dbMutex.Unlock()

	return nil
}

func getVBoxKeysPath() string {
	homeDir, _ := os.UserHomeDir()
	path := filepath.Join(homeDir, "VirtualBox VMs", "Llaves root")
	os.MkdirAll(path, os.ModePerm)
	return path
}

func getDiskPath(nombreDisco string) string {
	homeDir, _ := os.UserHomeDir()
	// Crea una carpeta para los discos dentro de la ruta por defecto de VirtualBox
	path := filepath.Join(homeDir, "VirtualBox VMs", "Discos Compartidos")
	os.MkdirAll(path, os.ModePerm)
	return filepath.Join(path, nombreDisco+".vdi")
}

func cleanupDiskTargetPath(path string) {
	// Evita fallos por VERR_ALREADY_EXISTS cuando hay restos de intentos anteriores.
	runVBoxManage("closemedium", "disk", path, "--delete")
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
	}
}

func hasConfiguredKeys() bool {
	if LlavesSshActivas {
		return true
	}
	for _, t := range templatesDB {
		if t.LlaveGenerada {
			return true
		}
	}
	return false
}

func inferGuestOS(base string) string {
	baseLower := strings.ToLower(base)
	if strings.Contains(baseLower, "ubuntu") {
		return "Ubuntu_64"
	}
	if strings.Contains(baseLower, "debi") {
		return "Debian_64"
	}
	if strings.Contains(baseLower, "mint") {
		return "Linux_64"
	}
	return "Ubuntu_64"
}

func normalizeRuntimeBinary(raw string) string {
	b := strings.ToLower(strings.TrimSpace(raw))
	if b == "python" {
		return "python3"
	}
	if b == "" {
		return "python3"
	}
	return b
}

func isAllowedRuntimeBinary(binary string) bool {
	_, ok := allowedRuntimeBinaries[binary]
	return ok
}

func firstToken(command string) string {
	parts := strings.Fields(strings.TrimSpace(command))
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func getTemplateByName(nombre string) (TemplateVM, bool) {
	for _, t := range templatesDB {
		if t.Nombre == nombre {
			return t, true
		}
	}
	return TemplateVM{}, false
}

func getDiskByName(nombre string) (DiscoCompartido, bool) {
	for _, d := range ListaDiscos {
		if d.Nombre == nombre {
			return d, true
		}
	}
	return DiscoCompartido{}, false
}

func resolveTemplateMainDiskPath(vmName string) (string, error) {
	out, err := runVBoxManage("showvminfo", vmName, "--machinereadable")
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if !strings.Contains(l, "-0-0") {
			continue
		}
		parts := strings.SplitN(l, "=", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.Trim(parts[1], "\"")
		if strings.HasSuffix(strings.ToLower(value), ".vdi") || strings.HasSuffix(strings.ToLower(value), ".vmdk") {
			return value, nil
		}
	}

	return "", fmt.Errorf("no se encontró un disco principal (port 0, device 0) para la plantilla")
}

func parseDiskUsage(output string) (string, string) {
	lineRegex := regexp.MustCompile(`(?i)^In use by VMs:\s*(.*)$`)
	for _, line := range strings.Split(output, "\n") {
		match := lineRegex.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) < 2 {
			continue
		}

		inUse := strings.TrimSpace(match[1])
		if inUse == "" || strings.EqualFold(inUse, "none") || strings.EqualFold(inUse, "<none>") || strings.EqualFold(inUse, "No") {
			return "Desconectado", "Ninguna"
		}

		parts := strings.Split(inUse, ",")
		vmNames := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if idx := strings.Index(p, "("); idx > 0 {
				p = strings.TrimSpace(p[:idx])
			}
			if p != "" {
				vmNames = append(vmNames, p)
			}
		}

		if len(vmNames) == 0 {
			return "Conectado", inUse
		}

		sort.Strings(vmNames)
		return "Conectado", strings.Join(vmNames, ", ")
	}

	return "Desconectado", "Ninguna"
}

func parseDiskCapacityMB(output string) int {
	lineRegex := regexp.MustCompile(`(?i)^Capacity:\s*([0-9]+)\s*MBytes`)
	for _, line := range strings.Split(output, "\n") {
		match := lineRegex.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 2 {
			continue
		}
		var capMB int
		if _, err := fmt.Sscanf(match[1], "%d", &capMB); err == nil {
			return capMB
		}
	}
	return 0
}

func updateDiskStatusLocked(index int) {
	if index < 0 || index >= len(ListaDiscos) {
		return
	}
	out, err := runVBoxManage("showmediuminfo", "disk", ListaDiscos[index].Ruta)
	if err != nil {
		ListaDiscos[index].Estado = "Estado desconocido"
		ListaDiscos[index].ConectadoA = "No disponible"
		return
	}

	estado, conectadoA := parseDiskUsage(string(out))
	ListaDiscos[index].Estado = estado
	ListaDiscos[index].ConectadoA = conectadoA
}

func refreshAllDisksStatusLocked() {
	for i := range ListaDiscos {
		updateDiskStatusLocked(i)
	}
}

func runVBoxManage(args ...string) ([]byte, error) {
	log.Printf("[CMD][VBoxManage] Ejecutando: VBoxManage %s", strings.Join(args, " "))
	ctx, cancel := context.WithTimeout(context.Background(), vboxCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "VBoxManage", args...)
	out, err := cmd.CombinedOutput()
	if strings.TrimSpace(string(out)) != "" {
		log.Printf("[CMD][VBoxManage] Salida: %s", strings.TrimSpace(string(out)))
	}
	if ctx.Err() == context.DeadlineExceeded {
		log.Printf("[CMD][VBoxManage] Timeout: VBoxManage %s", strings.Join(args, " "))
		return out, fmt.Errorf("timeout ejecutando VBoxManage: %s", strings.Join(args, " "))
	}
	if err != nil {
		log.Printf("[CMD][VBoxManage] Error: %v", err)
	} else {
		log.Printf("[CMD][VBoxManage] OK")
	}

	return out, err
}

func runVBoxManageWithTimeout(timeout time.Duration, args ...string) ([]byte, error) {
	log.Printf("[CMD][VBoxManage] Ejecutando (timeout=%s): VBoxManage %s", timeout, strings.Join(args, " "))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "VBoxManage", args...)
	out, err := cmd.CombinedOutput()
	if strings.TrimSpace(string(out)) != "" {
		log.Printf("[CMD][VBoxManage] Salida: %s", strings.TrimSpace(string(out)))
	}
	if ctx.Err() == context.DeadlineExceeded {
		log.Printf("[CMD][VBoxManage] Timeout: VBoxManage %s", strings.Join(args, " "))
		return out, fmt.Errorf("timeout ejecutando VBoxManage: %s", strings.Join(args, " "))
	}
	if err != nil {
		log.Printf("[CMD][VBoxManage] Error: %v", err)
	} else {
		log.Printf("[CMD][VBoxManage] OK")
	}

	return out, err
}

func isVMPoweredOff(vmName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "VBoxManage", "showvminfo", vmName, "--machinereadable")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), `vmstate="poweroff"`)
}

func shutdownVMGracefully(vmName string) {
	logFlow("VM-SHUTDOWN", "Intentando apagado graceful de vm=%s", vmName)
	if _, err := runVBoxManage("controlvm", vmName, "acpipowerbutton"); err == nil {
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			if isVMPoweredOff(vmName) {
				logFlow("VM-SHUTDOWN", "VM apagada por ACPI vm=%s", vmName)
				return
			}
			time.Sleep(2 * time.Second)
		}
	}

	logFlow("VM-SHUTDOWN", "Fallback a poweroff forzado vm=%s", vmName)
	runVBoxManage("controlvm", vmName, "poweroff")
}

func runSSHCommandLogged(session *ssh.Session, command string) error {
	log.Printf("[CMD][SSH] Ejecutando: %s", command)
	err := session.Run(command)
	if err != nil {
		log.Printf("[CMD][SSH] Error: %v", err)
	} else {
		log.Printf("[CMD][SSH] OK")
	}
	return err
}

func runSSHCommandWithOutputLogged(session *ssh.Session, command string) ([]byte, error) {
	log.Printf("[CMD][SSH] Ejecutando (output): %s", command)
	out, err := session.CombinedOutput(command)
	if strings.TrimSpace(string(out)) != "" {
		log.Printf("[CMD][SSH] Salida: %s", strings.TrimSpace(string(out)))
	}
	if err != nil {
		log.Printf("[CMD][SSH] Error: %v", err)
	} else {
		log.Printf("[CMD][SSH] OK")
	}
	return out, err
}

func logFlow(flow string, format string, args ...interface{}) {
	if len(args) == 0 {
		log.Printf("[FLUJO][%s] %s", flow, format)
		return
	}
	log.Printf("[FLUJO][%s] %s", flow, fmt.Sprintf(format, args...))
}

func shellSingleQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func deleteNatRuleIfExists(vmName string, ruleName string) {
	out, err := runVBoxManage("modifyvm", vmName, "--natpf1", "delete", ruleName)
	if err != nil {
		detail := strings.ToLower(strings.TrimSpace(string(out)))
		if !strings.Contains(detail, "e_invalidarg") {
			logFlow("SERVICE", "No fue posible eliminar regla NAT %s en vm=%s: %s", ruleName, vmName, strings.TrimSpace(string(out)))
		}
	}
}

func deleteNatRuleIfExistsRuntimeAware(vmName string, ruleName string) {
	if ruleName == "" {
		return
	}
	for attempt := 1; attempt <= 5; attempt++ {
		out, err := runVBoxManage("controlvm", vmName, "natpf1", "delete", ruleName)
		if err == nil {
			return
		}

		detail := strings.ToLower(strings.TrimSpace(string(out)))
		if strings.Contains(detail, "e_invalidarg") {
			return
		}
		if strings.Contains(detail, "already locked for a session") || strings.Contains(detail, "being unlocked") || strings.Contains(detail, "vbox_e_invalid_object_state") {
			time.Sleep(2 * time.Second)
			continue
		}

		out2, err2 := runVBoxManage("modifyvm", vmName, "--natpf1", "delete", ruleName)
		if err2 == nil {
			return
		}

		detail2 := strings.ToLower(strings.TrimSpace(string(out2)))
		if strings.Contains(detail2, "e_invalidarg") {
			return
		}
		if strings.Contains(detail2, "already locked for a session") || strings.Contains(detail2, "being unlocked") || strings.Contains(detail2, "vbox_e_invalid_object_state") {
			time.Sleep(2 * time.Second)
			continue
		}

		logFlow("SERVICE", "No fue posible eliminar regla NAT %s en vm=%s: %s", ruleName, vmName, strings.TrimSpace(string(out2)))
		return
	}

	logFlow("SERVICE", "No fue posible eliminar regla NAT %s en vm=%s tras reintentos por lock", ruleName, vmName)
}

func setNatRuleRuntimeAware(vmName string, ruleSpec string) error {
	for attempt := 1; attempt <= 5; attempt++ {
		if out, err := runVBoxManage("controlvm", vmName, "natpf1", ruleSpec); err == nil {
			return nil
		} else {
			detail := strings.ToLower(strings.TrimSpace(string(out)))
			if strings.Contains(detail, "already locked for a session") || strings.Contains(detail, "being unlocked") || strings.Contains(detail, "vbox_e_invalid_object_state") {
				time.Sleep(2 * time.Second)
				continue
			}

			if strings.Contains(detail, "is not currently running") || strings.Contains(detail, "invalid machine state") {
				if out2, err2 := runVBoxManage("modifyvm", vmName, "--natpf1", ruleSpec); err2 != nil {
					detail2 := strings.ToLower(strings.TrimSpace(string(out2)))
					if strings.Contains(detail2, "already locked for a session") || strings.Contains(detail2, "being unlocked") || strings.Contains(detail2, "vbox_e_invalid_object_state") {
						time.Sleep(2 * time.Second)
						continue
					}
					return fmt.Errorf("%s", strings.TrimSpace(string(out2)))
				}
				return nil
			}

			if out2, err2 := runVBoxManage("modifyvm", vmName, "--natpf1", ruleSpec); err2 != nil {
				detail2 := strings.ToLower(strings.TrimSpace(string(out2)))
				if strings.Contains(detail2, "already locked for a session") || strings.Contains(detail2, "being unlocked") || strings.Contains(detail2, "vbox_e_invalid_object_state") {
					time.Sleep(2 * time.Second)
					continue
				}
				return fmt.Errorf("%s", strings.TrimSpace(string(out2)))
			}
			return nil
		}
	}

	return fmt.Errorf("no fue posible configurar regla NAT por lock de VM tras varios reintentos")
}

func inferGuestAppPort(startCommand string) string {
	return inferGuestAppPortForRuntime(startCommand, "")
}

func inferGuestAppPortForRuntime(startCommand string, runtimeBinary string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)--port(?:=|\s+)(\d{2,5})`),
		regexp.MustCompile(`(?i)-p\s+(\d{2,5})`),
		regexp.MustCompile(`(?i)\bport(?:=|\s+)(\d{2,5})\b`),
		regexp.MustCompile(`:(\d{2,5})\b`),
	}
	for _, re := range patterns {
		m := re.FindStringSubmatch(startCommand)
		if len(m) >= 2 {
			candidate := strings.TrimSpace(m[1])
			if candidate != "" {
				return candidate
			}
		}
	}

	rt := strings.ToLower(strings.TrimSpace(runtimeBinary))
	if rt == "python" || rt == "python3" {
		// Valor por defecto típico en apps Python/Flask cuando no hay puerto explícito.
		return "5000"
	}

	if strings.Contains(strings.ToLower(startCommand), "flask") {
		return "5000"
	}

	return "8080"
}

func buildServiceNatRuleName(serviceName string) string {
	safe := strings.NewReplacer(".", "_", "-", "_", " ", "_").Replace(strings.TrimSuffix(serviceName, ".service"))
	if safe == "" {
		safe = "service"
	}
	if len(safe) > 35 {
		safe = safe[:35]
	}
	return "regla_app_" + safe
}

func prepareVMUserSSHEndpoint(vmName string, ruleName string) (string, error) {
	port, err := getFreeLocalPort()
	if err != nil {
		return "", err
	}

	rule := ruleName
	if rule == "" {
		rule = "regla_service_ssh"
	}
	deleteNatRuleIfExistsRuntimeAware(vmName, rule)

	if err := setNatRuleRuntimeAware(vmName, fmt.Sprintf("%s,tcp,127.0.0.1,%s,,22", rule, port)); err != nil {
		return "", fmt.Errorf("no fue posible configurar NAT PF para SSH: %s", err.Error())
	}

	if out, err := runVBoxManage("startvm", vmName, "--type", "headless"); err != nil {
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		if !strings.Contains(msg, "already") && !strings.Contains(msg, "running") {
			return "", fmt.Errorf("no fue posible iniciar la VM: %s", strings.TrimSpace(string(out)))
		}
	}

	return fmt.Sprintf("127.0.0.1:%s", port), nil
}

func uploadBytesOverSSH(client *ssh.Client, remotePath string, data []byte) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}

	go func() {
		_, _ = stdin.Write(data)
		_ = stdin.Close()
	}()

	cmd := fmt.Sprintf("cat > %s", shellSingleQuote(remotePath))
	log.Printf("[CMD][SSH] Subiendo archivo: %s", remotePath)
	if err := session.Run(cmd); err != nil {
		log.Printf("[CMD][SSH] Error subiendo archivo %s: %v", remotePath, err)
		return err
	}
	log.Printf("[CMD][SSH] Archivo subido correctamente: %s", remotePath)
	return nil
}

func upsertServiceDeploymentLocked(dep ServiceDeployment) {
	for i := range ListaServicios {
		if ListaServicios[i].VMName == dep.VMName && ListaServicios[i].ServiceName == dep.ServiceName {
			ListaServicios[i] = dep
			return
		}
	}
	ListaServicios = append(ListaServicios, dep)
}

func getFreeLocalPort() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("no fue posible obtener un puerto libre")
	}

	return fmt.Sprintf("%d", addr.Port), nil
}

func openSSHClientWithPasswords(host string, user string, passwords []string) (*ssh.Client, error) {
	for _, pwd := range passwords {
		sshConfig := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(pwd),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
		}

		client, err := ssh.Dial("tcp", host, sshConfig)
		if err == nil {
			log.Printf("[CMD][SSH] Conexion por password exitosa -> host=%s user=%s", host, user)
			return client, nil
		}
		log.Printf("[CMD][SSH] Conexion por password fallida -> host=%s user=%s err=%v", host, user, err)
	}

	return nil, fmt.Errorf("no fue posible autenticar por SSH con las credenciales disponibles")
}

func waitForSSHClient(host string, user string, passwords []string, timeout time.Duration) (*ssh.Client, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		client, err := openSSHClientWithPasswords(host, user, passwords)
		if err == nil {
			return client, nil
		}
		time.Sleep(5 * time.Second)
	}

	return nil, fmt.Errorf("la MV no quedó accesible por SSH dentro del tiempo esperado")
}

func openSSHClientWithPrivateKey(host string, user string, privateKeyPEM []byte) (*ssh.Client, error) {
	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("no fue posible parsear la llave privada generada: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		log.Printf("[CMD][SSH] Conexion por llave fallida -> host=%s user=%s err=%v", host, user, err)
		return nil, err
	}
	log.Printf("[CMD][SSH] Conexion por llave exitosa -> host=%s user=%s", host, user)

	return client, nil
}

func waitForSSHClientWithPrivateKey(host string, user string, privateKeyPEM []byte, timeout time.Duration) (*ssh.Client, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		client, err := openSSHClientWithPrivateKey(host, user, privateKeyPEM)
		if err == nil {
			return client, nil
		}
		time.Sleep(5 * time.Second)
	}

	return nil, fmt.Errorf("no fue posible validar acceso SSH por llave dentro del tiempo esperado")
}

func publicAuthorizedKeyFromPrivateKeyPEM(privateKeyPEM []byte) (string, error) {
	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("no fue posible parsear llave privada para derivar clave pública: %w", err)
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if pub == "" {
		return "", fmt.Errorf("no fue posible derivar una clave pública válida")
	}
	return pub, nil
}

func renderIndexWithErrorLocked(w http.ResponseWriter, errMsg string) {
	tmpl.Execute(w, PageData{
		Templates:     templatesDB,
		Discos:        ListaDiscos,
		UserVMs:       ListaUserVMs,
		Services:      ListaServicios,
		LlavesActivas: hasConfiguredKeys(),
		Error:         errMsg,
	})
}

func redirectWithError(w http.ResponseWriter, r *http.Request, errMsg string) {
	http.Redirect(w, r, "/?error="+url.QueryEscape(errMsg), http.StatusSeeOther)
}

func redirectWithInfo(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/?info="+url.QueryEscape(msg), http.StatusSeeOther)
}

func runServer() {
	if err := loadAppState(); err != nil {
		log.Printf("[STATE] No se pudo cargar %s: %v", appStateFile, err)
	} else {
		log.Printf("[STATE] Estado cargado desde %s", appStateFile)
		dbMutex.Lock()
		refreshAllDisksStatusLocked()
		if err := saveAppStateLocked(); err != nil {
			log.Printf("[STATE] No se pudo guardar estado reconciliado: %v", err)
		}
		dbMutex.Unlock()
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/add", handleAddTemplate)
	http.HandleFunc("/create-key", handleCreateKey)
	http.HandleFunc("/download-key", handleDownloadKey)

	// Rutas para la gestión de discos
	http.HandleFunc("/create-disk", handleCreateDisk)
	http.HandleFunc("/connect-disk", handleConnectDisk)
	http.HandleFunc("/disconnect-disk", handleDisconnectDisk)
	http.HandleFunc("/delete-disk", handleDeleteDisk)

	// Rutas para las Máquinas de Usuario
	http.HandleFunc("/create-user-vm", handleCreateUserVM)
	http.HandleFunc("/create-user-key", handleCreateUserKey)
	http.HandleFunc("/verify-user-access", handleVerifyUserAccess)
	http.HandleFunc("/delete-user-vm", handleDeleteUserVM)

	// Rutas para Fase 2: gestión de servicios
	http.HandleFunc("/deploy-service", handleDeployService)
	http.HandleFunc("/service-action", handleServiceAction)
	http.HandleFunc("/reset-state", handleResetState)

	fmt.Println("Servidor corriendo en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleResetState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	dbMutex.Lock()
	templatesDB = nil
	ListaDiscos = nil
	ListaUserVMs = nil
	ListaServicios = nil
	LlavesSshActivas = false
	dbMutex.Unlock()

	if err := os.Remove(appStateFile); err != nil && !os.IsNotExist(err) {
		redirectWithError(w, r, "No fue posible eliminar el archivo de persistencia: "+err.Error())
		return
	}

	redirectWithInfo(w, r, "Persistencia limpiada: se eliminó estado_dashboard.json y se reinició el estado del dashboard.")
}

func main() {
	runServer()
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	dbMutex.Lock()
	data := PageData{
		Templates:     templatesDB,
		Discos:        ListaDiscos,
		UserVMs:       ListaUserVMs,
		Services:      ListaServicios,
		LlavesActivas: hasConfiguredKeys(),
		Error:         strings.TrimSpace(r.URL.Query().Get("error")),
		Info:          strings.TrimSpace(r.URL.Query().Get("info")),
	}
	dbMutex.Unlock()
	tmpl.Execute(w, data)
}

func handleAddTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombre := strings.TrimSpace(r.FormValue("nombre"))
	descripcion := strings.TrimSpace(r.FormValue("descripcion"))
	base := strings.TrimSpace(r.FormValue("base"))
	if nombre == "" || descripcion == "" || base == "" {
		redirectWithError(w, r, "Debes suministrar nombre, descripción y plantilla base para la máquina virtual base.")
		return
	}

	dbMutex.Lock()
	defer dbMutex.Unlock()

	for _, t := range templatesDB {
		if strings.EqualFold(t.Nombre, nombre) {
			renderIndexWithErrorLocked(w, "Error: Ya existe una plantilla con el nombre '"+nombre+"'.")
			return
		}
	}

	nuevaPlantilla := TemplateVM{
		Nombre:        nombre,
		Descripcion:   descripcion,
		PlantillaBase: base,
		LlaveGenerada: false,
	}

	templatesDB = append(templatesDB, nuevaPlantilla)
	if err := saveAppStateLocked(); err != nil {
		renderIndexWithErrorLocked(w, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleCreateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombrePlantilla := strings.TrimSpace(r.FormValue("nombre"))
	logFlow("CREATE-KEY-ROOT", "Inicio solicitud para plantilla=%s", nombrePlantilla)
	if nombrePlantilla == "" {
		redirectWithError(w, r, "Debes indicar la máquina virtual base para generar las llaves root.")
		return
	}

	dbMutex.Lock()
	defer dbMutex.Unlock()
	templateFound := false

	for i, t := range templatesDB {
		if t.Nombre != nombrePlantilla {
			continue
		}
		templateFound = true
		if t.LlaveGenerada {
			renderIndexWithErrorLocked(w, "La máquina virtual base seleccionada ya tiene llaves root generadas.")
			return
		}

		if t.Nombre == nombrePlantilla && !t.LlaveGenerada {

			rootPassword := "1234"
			vmIP := "127.0.0.1"
			vmPort := "2224"

			fmt.Printf("Preparando red para MV: %s...\n", t.PlantillaBase)
			runVBoxManage("modifyvm", t.PlantillaBase, "--natpf1", "delete", "regla_ssh")

			if outPort, errPort := runVBoxManage("modifyvm", t.PlantillaBase, "--natpf1", "regla_ssh,tcp,127.0.0.1,2224,,22"); errPort != nil {
				fmt.Printf("Advertencia al configurar puerto: %v\nDetalles: %s\n", errPort, string(outPort))
			}

			fmt.Printf("Encendiendo MV: %s...\n", t.PlantillaBase)
			if outStart, err := runVBoxManage("startvm", t.PlantillaBase, "--type", "headless"); err != nil {
				fmt.Printf("Error al encender MV: %v\nDetalles: %s\n", err, string(outStart))
			}

			fmt.Println("Esperando a que la MV inicie (60 segundos)...")
			time.Sleep(60 * time.Second)

			privateKey, _ := rsa.GenerateKey(rand.Reader, 3072)
			nombreLlavePrivada := fmt.Sprintf("rsa_%s.pem", t.Nombre)
			rutaArchivo := filepath.Join(getVBoxKeysPath(), nombreLlavePrivada)

			llavePEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			})
			os.WriteFile(rutaArchivo, llavePEM, 0600)

			publicRsaKey, _ := ssh.NewPublicKey(&privateKey.PublicKey)
			pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

			sshConfig := &ssh.ClientConfig{
				User: "root",
				Auth: []ssh.AuthMethod{
					ssh.Password(rootPassword),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			}

			target := fmt.Sprintf("%s:%s", vmIP, vmPort)
			log.Printf("[CMD][SSH] Dial directo -> host=%s user=root", target)
			client, err := ssh.Dial("tcp", target, sshConfig)
			if err != nil {
				fmt.Printf("Fallo conexión SSH: %v.\n", err)
				runVBoxManage("controlvm", t.PlantillaBase, "poweroff")
				renderIndexWithErrorLocked(w, "No fue posible conectar por SSH a la máquina virtual base para inyectar llaves root.")
				return
			} else {
				log.Printf("[CMD][SSH] Dial directo exitoso -> host=%s user=root", target)
				defer client.Close()
				session, err := client.NewSession()
				if err != nil {
					runVBoxManage("controlvm", t.PlantillaBase, "poweroff")
					renderIndexWithErrorLocked(w, "No fue posible abrir sesión SSH en la máquina virtual base.")
					return
				}
				defer session.Close()
				comandoSSH := fmt.Sprintf(`mkdir -p /root/.ssh && echo "%s" >> /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys`, strings.TrimSpace(string(pubKeyBytes)))

				if err := runSSHCommandLogged(session, comandoSSH); err != nil {
					runVBoxManage("controlvm", t.PlantillaBase, "poweroff")
					renderIndexWithErrorLocked(w, "No fue posible inyectar la llave root en la máquina virtual base.")
					return
				}
				fmt.Println("¡Llave inyectada exitosamente en la MV!")
				LlavesSshActivas = true
				runVBoxManage("controlvm", t.PlantillaBase, "poweroff")
			}

			templatesDB[i].LlaveGenerada = true
			templatesDB[i].NombreLlave = nombreLlavePrivada
			if err := saveAppStateLocked(); err != nil {
				renderIndexWithErrorLocked(w, "No fue posible persistir el estado en disco: "+err.Error())
				return
			}
			logFlow("CREATE-KEY-ROOT", "Llaves root generadas correctamente para plantilla=%s", nombrePlantilla)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	if !templateFound {
		renderIndexWithErrorLocked(w, "La máquina virtual base seleccionada no existe en el dashboard.")
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDownloadKey(w http.ResponseWriter, r *http.Request) {
	nombreLlave := r.URL.Query().Get("nombre")
	if nombreLlave == "" {
		http.Error(w, "Nombre de llave no especificado", http.StatusBadRequest)
		return
	}

	rutaArchivo := filepath.Join(getVBoxKeysPath(), nombreLlave)

	if _, err := os.Stat(rutaArchivo); os.IsNotExist(err) {
		http.Error(w, "La llave no existe", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+nombreLlave)
	w.Header().Set("Content-Type", "application/x-pem-file")
	http.ServeFile(w, r, rutaArchivo)
}

// ==========================================
// FUNCIONES DE DISCOS COMPARTIDOS
// ==========================================

func handleCreateDisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombreDisco := strings.TrimSpace(r.FormValue("nombre_disco"))
	plantillaOrigen := strings.TrimSpace(r.FormValue("plantilla_origen"))
	tipoDisco := strings.TrimSpace(r.FormValue("tipo_disco"))
	logFlow("CREATE-DISK", "Inicio solicitud nombre=%s plantilla=%s tipo=%s", nombreDisco, plantillaOrigen, tipoDisco)
	if tipoDisco == "" {
		tipoDisco = "nuevo"
	}

	dbMutex.Lock()
	defer dbMutex.Unlock()

	if !hasConfiguredKeys() || nombreDisco == "" {
		redirectWithError(w, r, "Debes configurar llaves de autenticación y nombre del disco para continuar.")
		return
	}

	for _, d := range ListaDiscos {
		if strings.EqualFold(d.Nombre, nombreDisco) {
			renderIndexWithErrorLocked(w, "Error: Ya existe un disco con el nombre '"+nombreDisco+"'.")
			return
		}
	}

	so := "Desconocido"
	plantillaConLlave := false
	for _, t := range templatesDB {
		if t.Nombre == plantillaOrigen {
			so = t.PlantillaBase
			plantillaConLlave = t.LlaveGenerada
			break
		}
	}
	if plantillaOrigen == "" || !plantillaConLlave {
		renderIndexWithErrorLocked(w, "Debes seleccionar una máquina virtual base con llaves root configuradas para crear el disco multiconexión.")
		return
	}

	ruta := ""
	tieneSO := false
	tipoRegistrado := "nuevo"

	if tipoDisco == "plantilla" {
		t, ok := getTemplateByName(plantillaOrigen)
		if !ok {
			renderIndexWithErrorLocked(w, "No se encontró la plantilla base seleccionada.")
			return
		}

		srcPath, err := resolveTemplateMainDiskPath(t.PlantillaBase)
		if err != nil {
			renderIndexWithErrorLocked(w, "No fue posible ubicar el disco principal de la plantilla: "+err.Error())
			return
		}

		// Si la plantilla tiene snapshots, el disco puede ser diferencial.
		// En ese caso clonamos a un VDI normal para poder usar tipo shareable.
		ruta = getDiskPath(nombreDisco)
		cleanupDiskTargetPath(ruta)
		if out, err := runVBoxManageWithTimeout(vboxCreateDiskTimeout, "clonemedium", "disk", srcPath, ruta, "--format", "VDI", "--variant", "Standard"); err != nil {
			detail := strings.TrimSpace(string(out))
			if strings.Contains(detail, "VERR_DISK_FULL") {
				renderIndexWithErrorLocked(w, "No hay espacio suficiente en disco para clonar la plantilla. Libera espacio o mueve la carpeta de VirtualBox a una unidad con más capacidad.")
				return
			}
			if strings.Contains(detail, "VERR_ALREADY_EXISTS") {
				renderIndexWithErrorLocked(w, "El archivo destino del disco ya existe y no pudo reemplazarse automáticamente. Elimina el archivo VDI previo e intenta de nuevo.")
				return
			}
			if detail == "" {
				detail = err.Error()
			} else {
				detail = detail + " | " + err.Error()
			}
			renderIndexWithErrorLocked(w, "Error al clonar el disco de plantilla: "+detail)
			return
		}

		if infoOut, infoErr := runVBoxManage("showmediuminfo", "disk", ruta); infoErr == nil {
			capMB := parseDiskCapacityMB(string(infoOut))
			if capMB > 0 && capMB < diskSizeMinCloneMB {
				if out, err := runVBoxManage("modifymedium", "disk", ruta, "--resize", fmt.Sprintf("%d", diskSizeMinCloneMB)); err != nil {
					renderIndexWithErrorLocked(w, "Error al expandir el disco clonado a 10GB: "+strings.TrimSpace(string(out)))
					return
				}
			}
		}

		if out, err := runVBoxManage("modifymedium", "disk", ruta, "--type", "shareable"); err != nil {
			detail := strings.TrimSpace(string(out))
			if strings.Contains(strings.ToLower(detail), "dynamic medium storage unit") {
				// Shareable exige disco fijo en VirtualBox. Reintentamos en formato Fixed.
				cleanupDiskTargetPath(ruta)

				if outFixed, errFixed := runVBoxManageWithTimeout(vboxCreateDiskTimeout, "clonemedium", "disk", srcPath, ruta, "--format", "VDI", "--variant", "Fixed"); errFixed != nil {
					detailFixed := strings.TrimSpace(string(outFixed))
					if strings.Contains(detailFixed, "VERR_DISK_FULL") {
						renderIndexWithErrorLocked(w, "No hay espacio suficiente para crear un disco shareable desde plantilla. Para multiconexión real VirtualBox requiere disco fijo; libera espacio e intenta de nuevo.")
						return
					}
					if strings.Contains(detailFixed, "VERR_ALREADY_EXISTS") {
						renderIndexWithErrorLocked(w, "El archivo destino del disco ya existe y no pudo reemplazarse automáticamente. Elimina el archivo VDI previo e intenta de nuevo.")
						return
					}
					if detailFixed == "" {
						detailFixed = errFixed.Error()
					} else {
						detailFixed = detailFixed + " | " + errFixed.Error()
					}
					renderIndexWithErrorLocked(w, "Error al recrear el disco de plantilla en formato fijo: "+detailFixed)
					return
				}

				if outShare, errShare := runVBoxManage("modifymedium", "disk", ruta, "--type", "shareable"); errShare != nil {
					renderIndexWithErrorLocked(w, "Error al preparar el disco fijo de plantilla como multiconexión: "+strings.TrimSpace(string(outShare)))
					return
				}
			} else {
				renderIndexWithErrorLocked(w, "Error al preparar el disco clonado de plantilla como multiconexión: "+detail)
				return
			}
		}

		tieneSO = true
		tipoRegistrado = "plantilla"
	} else {
		ruta = getDiskPath(nombreDisco)
		if out, err := runVBoxManageWithTimeout(vboxCreateDiskTimeout, "createmedium", "disk", "--filename", ruta, "--size", fmt.Sprintf("%d", diskSizeNewMB), "--format", "VDI", "--variant", "Fixed"); err != nil {
			detail := strings.TrimSpace(string(out))
			if detail == "" {
				detail = err.Error()
			} else {
				detail = detail + " | " + err.Error()
			}
			renderIndexWithErrorLocked(w, "Error al crear el disco: "+detail)
			return
		}

		if out, err := runVBoxManage("modifymedium", "disk", ruta, "--type", "shareable"); err != nil {
			renderIndexWithErrorLocked(w, "Error al marcar el disco como multiconexión: "+strings.TrimSpace(string(out)))
			return
		}

		tieneSO = false
		tipoRegistrado = "nuevo"
	}

	ListaDiscos = append(ListaDiscos, DiscoCompartido{
		Nombre:           nombreDisco,
		Ruta:             ruta,
		PlantillaOrigen:  plantillaOrigen,
		SistemaOperativo: so,
		Estado:           "Desconectado",
		ConectadoA:       "Ninguna",
		TieneSO:          tieneSO,
		Tipo:             tipoRegistrado,
	})
	updateDiskStatusLocked(len(ListaDiscos) - 1)
	if err := saveAppStateLocked(); err != nil {
		renderIndexWithErrorLocked(w, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	logFlow("CREATE-DISK", "Disco registrado correctamente nombre=%s ruta=%s tipo=%s", nombreDisco, ruta, tipoRegistrado)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDeleteDisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombreDisco := strings.TrimSpace(r.FormValue("disco"))
	if nombreDisco == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	dbMutex.Lock()
	discoPath := getDiskPath(nombreDisco)
	vms := make([]string, 0, len(ListaUserVMs))
	if d, ok := getDiskByName(nombreDisco); ok {
		discoPath = d.Ruta
	}
	for _, vm := range ListaUserVMs {
		vms = append(vms, vm.Nombre)
	}
	dbMutex.Unlock()

	for _, vmName := range vms {
		runVBoxManage("storageattach", vmName, "--storagectl", "SATA Controller", "--port", "1", "--device", "0", "--medium", "none")
	}

	runVBoxManage("closemedium", "disk", discoPath, "--delete")

	dbMutex.Lock()
	var nuevaLista []DiscoCompartido
	for _, d := range ListaDiscos {
		if d.Nombre != nombreDisco {
			nuevaLista = append(nuevaLista, d)
		}
	}
	ListaDiscos = nuevaLista
	for i := range ListaUserVMs {
		if ListaUserVMs[i].DiscoAsignado == nombreDisco {
			ListaUserVMs[i].DiscoAsignado = "Sin disco"
			ListaUserVMs[i].DiscoTieneSO = false
		}
	}
	if err := saveAppStateLocked(); err != nil {
		dbMutex.Unlock()
		redirectWithError(w, r, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	dbMutex.Unlock()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleConnectDisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombreDisco := strings.TrimSpace(r.FormValue("disco"))
	targetVM := strings.TrimSpace(r.FormValue("target_vm")) // Ahora capturamos la MV de usuario desde el comboBox
	logFlow("CONNECT-DISK", "Solicitud disco=%s vm=%s", nombreDisco, targetVM)
	if nombreDisco == "" || targetVM == "" {
		redirectWithError(w, r, "Debes seleccionar un disco y una máquina virtual de usuario para conectar.")
		return
	}

	dbMutex.Lock()
	discoExiste := false
	vmExiste := false
	for _, d := range ListaDiscos {
		if d.Nombre == nombreDisco {
			discoExiste = true
			break
		}
	}
	for _, mv := range ListaUserVMs {
		if mv.Nombre == targetVM {
			vmExiste = true
			break
		}
	}
	dbMutex.Unlock()

	if !discoExiste || !vmExiste {
		redirectWithError(w, r, "El disco o la máquina virtual de usuario ya no existen.")
		return
	}

	diskPath := getDiskPath(nombreDisco)
	diskHasSO := false
	if d, ok := getDiskByName(nombreDisco); ok {
		diskPath = d.Ruta
		diskHasSO = d.TieneSO
	}

	if out, err := runVBoxManage("storageattach", targetVM, "--storagectl", "SATA Controller", "--port", "1", "--device", "0", "--type", "hdd", "--medium", diskPath, "--mtype", "shareable"); err != nil {
		redirectWithError(w, r, "No fue posible conectar el disco: "+strings.TrimSpace(string(out)))
		return
	}

	dbMutex.Lock()
	for i := range ListaDiscos {
		if ListaDiscos[i].Nombre == nombreDisco {
			updateDiskStatusLocked(i)
		}
	}
	for i := range ListaUserVMs {
		if ListaUserVMs[i].Nombre == targetVM {
			ListaUserVMs[i].DiscoAsignado = nombreDisco
			ListaUserVMs[i].DiscoTieneSO = diskHasSO
		}
	}
	if err := saveAppStateLocked(); err != nil {
		dbMutex.Unlock()
		redirectWithError(w, r, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	dbMutex.Unlock()
	logFlow("CONNECT-DISK", "Conexión aplicada disco=%s vm=%s", nombreDisco, targetVM)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDisconnectDisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombreDisco := strings.TrimSpace(r.FormValue("disco"))
	targetVM := strings.TrimSpace(r.FormValue("target_vm")) // Capturamos la MV de usuario
	if targetVM == "" {
		redirectWithError(w, r, "Debes seleccionar una máquina virtual de usuario para desconectar el disco.")
		return
	}

	if out, err := runVBoxManage("storageattach", targetVM, "--storagectl", "SATA Controller", "--port", "1", "--device", "0", "--medium", "none"); err != nil {
		redirectWithError(w, r, "No fue posible desconectar el disco: "+strings.TrimSpace(string(out)))
		return
	}

	dbMutex.Lock()
	for i := range ListaDiscos {
		if ListaDiscos[i].Nombre == nombreDisco {
			updateDiskStatusLocked(i)
		}
	}
	for i := range ListaUserVMs {
		if ListaUserVMs[i].Nombre == targetVM && ListaUserVMs[i].DiscoAsignado == nombreDisco {
			ListaUserVMs[i].DiscoAsignado = "Sin disco"
			ListaUserVMs[i].DiscoTieneSO = false
		}
	}
	if err := saveAppStateLocked(); err != nil {
		dbMutex.Unlock()
		redirectWithError(w, r, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	dbMutex.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ==========================================
// FUNCIONES DE MÁQUINAS DE USUARIO
// ==========================================

func handleCreateUserVM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombreDisco := r.FormValue("disco")
	plantillaOrigen := r.FormValue("plantilla") // Solo lo usamos como referencia de nombre

	nombreMV := strings.TrimSpace(r.FormValue("nombre_mv"))
	descripcion := strings.TrimSpace(r.FormValue("descripcion"))
	logFlow("CREATE-USER-VM", "Inicio solicitud nombreMV=%s disco=%s plantilla=%s", nombreMV, nombreDisco, plantillaOrigen)
	if nombreMV == "" || descripcion == "" {
		redirectWithError(w, r, "Debes ingresar nombre y descripción para crear la máquina virtual de usuario.")
		return
	}

	dbMutex.Lock()
	for _, mv := range ListaUserVMs {
		if strings.EqualFold(mv.Nombre, nombreMV) {
			dbMutex.Unlock()
			redirectWithError(w, r, "Ya existe una máquina virtual de usuario con ese nombre.")
			return
		}
	}

	discoEncontrado := false
	discoTieneSO := false
	discoPath := getDiskPath(nombreDisco)
	for _, d := range ListaDiscos {
		if d.Nombre == nombreDisco {
			discoEncontrado = true
			discoTieneSO = d.TieneSO
			discoPath = d.Ruta
			break
		}
	}
	dbMutex.Unlock()

	if !discoEncontrado {
		redirectWithError(w, r, "El disco seleccionado no existe o fue eliminado.")
		return
	}

	// 1. Obtener la ruta raíz y forzar la creación de la carpeta GrupoUsuarios
	homeDir, _ := os.UserHomeDir()
	grupoUsuariosPath := filepath.Join(homeDir, "VirtualBox VMs", "GrupoUsuarios")
	os.MkdirAll(grupoUsuariosPath, os.ModePerm)

	fmt.Printf("\n--- CREANDO MV DE USUARIO NUEVA: %s ---\n", nombreMV)

	guestOS := inferGuestOS(plantillaOrigen)

	// 2. CREAR una máquina NUEVA desde cero (NO clonar)
	outCreate, errCreate := runVBoxManage("createvm", "--name", nombreMV, "--ostype", guestOS, "--basefolder", grupoUsuariosPath, "--groups", "/GrupoUsuarios", "--register")

	if errCreate != nil {
		fmt.Printf("ERROR AL CREAR MV NUEVA: %v\nDetalles: %s\n", errCreate, string(outCreate))
		redirectWithError(w, r, "Error al crear la máquina virtual en VirtualBox.")
		return
	}
	fmt.Println("MV Nueva creada y registrada exitosamente.")

	if outResources, errResources := runVBoxManage("modifyvm", nombreMV, "--memory", "2048", "--cpus", "2", "--nic1", "nat"); errResources != nil {
		fmt.Printf("Advertencia al configurar recursos de la MV: %v\nDetalles: %s\n", errResources, string(outResources))
	}

	// 3. Crear un controlador SATA (Las máquinas nuevas vienen "peladas", necesitan esto para conectar el disco)
	outCtl, errCtl := runVBoxManage("storagectl", nombreMV, "--name", "SATA Controller", "--add", "sata", "--controller", "IntelAhci")
	if errCtl != nil {
		fmt.Printf("Advertencia al crear controlador SATA: %v\nDetalles: %s\n", errCtl, string(outCtl))
	}

	// 4. Adjuntar el disco multiconexión al controlador recién creado
	outStorage, errStorage := runVBoxManage("storageattach", nombreMV, "--storagectl", "SATA Controller", "--port", "1", "--device", "0", "--type", "hdd", "--medium", discoPath, "--mtype", "shareable")

	if errStorage != nil {
		fmt.Printf("Error al adjuntar el disco: %v\nDetalles: %s\n", errStorage, string(outStorage))
		runVBoxManage("unregistervm", nombreMV, "--delete")
		redirectWithError(w, r, "No fue posible asociar el disco multiconexión a la nueva máquina virtual.")
		return
	}
	fmt.Println("Disco compartido adjuntado correctamente.")

	// 5. Guardar en tu base de datos de memoria
	dbMutex.Lock()
	ListaUserVMs = append(ListaUserVMs, UserVM{
		Nombre:        nombreMV,
		Descripcion:   descripcion,
		PlantillaBase: plantillaOrigen, // Aquí guardamos el nombre de la plantilla como pediste
		DiscoAsignado: nombreDisco,
		DiscoTieneSO:  discoTieneSO,
		LlaveGenerada: false,
	})
	for i := range ListaDiscos {
		if ListaDiscos[i].Nombre == nombreDisco {
			updateDiskStatusLocked(i)
		}
	}
	if err := saveAppStateLocked(); err != nil {
		dbMutex.Unlock()
		redirectWithError(w, r, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	dbMutex.Unlock()

	fmt.Println("Proceso terminado. Actualizando interfaz...")
	logFlow("CREATE-USER-VM", "MV de usuario creada nombreMV=%s disco=%s", nombreMV, nombreDisco)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleCreateUserKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombreMV := strings.TrimSpace(r.FormValue("nombre"))
	logFlow("CREATE-USER-KEY", "Inicio solicitud para vm=%s", nombreMV)
	if nombreMV == "" {
		redirectWithError(w, r, "Nombre de máquina virtual de usuario no válido.")
		return
	}

	dbMutex.Lock()
	idx := -1
	for i := range ListaUserVMs {
		if ListaUserVMs[i].Nombre == nombreMV {
			idx = i
			break
		}
	}
	if idx == -1 {
		dbMutex.Unlock()
		renderIndexWithErrorLocked(w, "La máquina virtual de usuario indicada no existe.")
		return
	}

	mv := ListaUserVMs[idx]
	if mv.DiscoAsignado == "" || mv.DiscoAsignado == "Sin disco" {
		dbMutex.Unlock()
		renderIndexWithErrorLocked(w, "La MV no tiene disco multiconexión asociado. No se puede crear usuario con llaves.")
		return
	}

	if mv.LlaveGenerada {
		dbMutex.Unlock()
		renderIndexWithErrorLocked(w, "Esta MV de usuario ya tiene llaves generadas.")
		return
	}

	discoAsignado, ok := getDiskByName(mv.DiscoAsignado)
	if !ok {
		dbMutex.Unlock()
		renderIndexWithErrorLocked(w, "El disco asignado a la MV de usuario ya no existe en el dashboard.")
		return
	}
	if !discoAsignado.TieneSO {
		dbMutex.Unlock()
		renderIndexWithErrorLocked(w, "No se puede crear usuario y llaves: el disco asignado es nuevo y no tiene sistema operativo. Usa un disco de plantilla.")
		return
	}
	dbMutex.Unlock()

	vmIP := "127.0.0.1"
	vmPort, portErr := getFreeLocalPort()
	if portErr != nil {
		renderIndexWithErrorLocked(w, "No fue posible reservar un puerto local para SSH de la MV de usuario.")
		return
	}

	fmt.Printf("Configurando red para MV de Usuario: %s...\n", mv.Nombre)
	runVBoxManage("modifyvm", mv.Nombre, "--natpf1", "delete", "regla_ssh")
	runVBoxManage("modifyvm", mv.Nombre, "--natpf1", "delete", "regla_ssh_user")
	if out, err := runVBoxManage("modifyvm", mv.Nombre, "--natpf1", fmt.Sprintf("regla_ssh_user,tcp,127.0.0.1,%s,,22", vmPort)); err != nil {
		renderIndexWithErrorLocked(w, "No fue posible configurar el reenvío SSH para la MV de usuario: "+strings.TrimSpace(string(out)))
		return
	}

	fmt.Printf("Encendiendo MV de Usuario: %s...\n", mv.Nombre)
	runVBoxManage("startvm", mv.Nombre, "--type", "headless")

	privateKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	nombreLlavePrivada := fmt.Sprintf("rsa_user_%s.pem", mv.Nombre)
	rutaArchivo := filepath.Join(getVBoxKeysPath(), nombreLlavePrivada)

	llavePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	os.WriteFile(rutaArchivo, llavePEM, 0600)

	publicRsaKey, _ := ssh.NewPublicKey(&privateKey.PublicKey)
	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	host := fmt.Sprintf("%s:%s", vmIP, vmPort)
	passwords := []string{"1234", "nicolas"}
	client, err := waitForSSHClient(host, "root", passwords, sshBootTimeout)
	if err != nil {
		runVBoxManage("controlvm", mv.Nombre, "poweroff")
		renderIndexWithErrorLocked(w, "No fue posible establecer conexión SSH a la MV de usuario. Verifica que el sistema del disco tenga SSH habilitado, que root por contraseña esté permitido y la contraseña sea válida.")
		return
	}
	defer client.Close()

	session, sessErr := client.NewSession()
	if sessErr != nil {
		runVBoxManage("controlvm", mv.Nombre, "poweroff")
		renderIndexWithErrorLocked(w, "No fue posible abrir sesión SSH en la MV de usuario.")
		return
	}
	defer session.Close()

	pubKeyValue := strings.TrimSpace(string(pubKeyBytes))
	if pubKeyValue == "" {
		runVBoxManage("controlvm", mv.Nombre, "poweroff")
		renderIndexWithErrorLocked(w, "No fue posible derivar la llave pública del usuario para inyectarla en la MV.")
		return
	}
	comandoSSH := fmt.Sprintf(`set -e; id -u usuario_mv >/dev/null 2>&1 || useradd -m -s /bin/bash usuario_mv; usermod -s /bin/bash usuario_mv >/dev/null 2>&1 || true; usermod -U usuario_mv >/dev/null 2>&1 || true; chage -E -1 usuario_mv >/dev/null 2>&1 || true; user_home="$(getent passwd usuario_mv 2>/dev/null | cut -d: -f6)"; [ -n "$user_home" ] || user_home="$(eval echo ~usuario_mv 2>/dev/null)"; [ -n "$user_home" ] || user_home="/home/usuario_mv"; user_group="$(id -gn usuario_mv 2>/dev/null || echo usuario_mv)"; mkdir -p "$user_home" "$user_home/.ssh"; chown -R usuario_mv:"$user_group" "$user_home"; chmod 755 "$user_home"; chmod 700 "$user_home/.ssh"; printf '%%s\n' %s > "$user_home/.ssh/authorized_keys"; chown usuario_mv:"$user_group" "$user_home/.ssh/authorized_keys"; chmod 600 "$user_home/.ssh/authorized_keys"; test -s "$user_home/.ssh/authorized_keys"; grep -qxF %s "$user_home/.ssh/authorized_keys"; echo KEY_INJECT_OK`, shellSingleQuote(pubKeyValue), shellSingleQuote(pubKeyValue))

	provisionOut, provisionErr := runSSHCommandWithOutputLogged(session, comandoSSH)
	if provisionErr != nil || !strings.Contains(string(provisionOut), "KEY_INJECT_OK") {
		runVBoxManage("controlvm", mv.Nombre, "poweroff")
		renderIndexWithErrorLocked(w, "No fue posible crear el usuario Linux con llaves en la MV.")
		return
	}

	diagCmd := `user_home="$(getent passwd usuario_mv | cut -d: -f6)"; [ -n "$user_home" ] || user_home="/home/usuario_mv"; echo DIAG_USER_HOME=$user_home; getent passwd usuario_mv || true; ls -ld "$user_home" "$user_home/.ssh" "$user_home/.ssh/authorized_keys" 2>/dev/null || true; stat -c 'DIAG_PERM %U:%G %a %n' "$user_home" "$user_home/.ssh" "$user_home/.ssh/authorized_keys" 2>/dev/null || true; grep -Ei '^(PubkeyAuthentication|AuthorizedKeysFile|AllowUsers|DenyUsers|PasswordAuthentication|PermitRootLogin)' /etc/ssh/sshd_config 2>/dev/null || true`
	diagSession, diagSessionErr := client.NewSession()
	if diagSessionErr == nil {
		_, _ = runSSHCommandWithOutputLogged(diagSession, diagCmd)
		diagSession.Close()
	}
	fmt.Println("¡Usuario creado y llave inyectada!")

	// Verificacion final: autenticar con el usuario creado y la llave privada recien generada.
	verifyClient, verifyErr := waitForSSHClientWithPrivateKey(host, "usuario_mv", llavePEM, 45*time.Second)
	if verifyErr != nil {
		logFlow("CREATE-USER-KEY", "Fallo validación por llave para vm=%s: %v", nombreMV, verifyErr)
		runVBoxManage("controlvm", mv.Nombre, "poweroff")
		renderIndexWithErrorLocked(w, "Se creó el usuario pero no se pudo validar el acceso SSH con llave. Verifica que PubkeyAuthentication esté habilitado en la MV y reintenta.")
		return
	}
	verifySession, verifySessionErr := verifyClient.NewSession()
	if verifySessionErr != nil {
		verifyClient.Close()
		runVBoxManage("controlvm", mv.Nombre, "poweroff")
		renderIndexWithErrorLocked(w, "No fue posible abrir sesión de verificación SSH con el usuario creado.")
		return
	}
	verificationCmd := "whoami && mkdir -p /home/usuario_mv/verificacion_ssh && date > /home/usuario_mv/verificacion_ssh/ultima_validacion.txt && test -s /home/usuario_mv/verificacion_ssh/ultima_validacion.txt && echo INTERACCION_OK"
	verifyOut, runErr := runSSHCommandWithOutputLogged(verifySession, verificationCmd)
	verifyText := strings.TrimSpace(string(verifyOut))
	if runErr != nil || !strings.Contains(verifyText, "INTERACCION_OK") || !strings.Contains(verifyText, "usuario_mv") {
		verifySession.Close()
		verifyClient.Close()
		runVBoxManage("controlvm", mv.Nombre, "poweroff")
		renderIndexWithErrorLocked(w, "La autenticación por llave funcionó, pero la interacción de prueba del usuario en la MV falló. Verifica permisos del usuario y shell.")
		return
	}
	verifySession.Close()
	verifyClient.Close()

	shutdownVMGracefully(mv.Nombre)

	dbMutex.Lock()
	if idx >= 0 && idx < len(ListaUserVMs) && ListaUserVMs[idx].Nombre == nombreMV {
		ListaUserVMs[idx].LlaveGenerada = true
		ListaUserVMs[idx].NombreLlave = nombreLlavePrivada
	}
	if err := saveAppStateLocked(); err != nil {
		dbMutex.Unlock()
		renderIndexWithErrorLocked(w, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	dbMutex.Unlock()
	logFlow("CREATE-USER-KEY", "Usuario y llaves creados/verificados para vm=%s llave=%s", nombreMV, nombreLlavePrivada)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDeleteUserVM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombreMV := strings.TrimSpace(r.FormValue("nombre"))
	if nombreMV == "" {
		redirectWithError(w, r, "Nombre de máquina virtual de usuario no válido.")
		return
	}

	dbMutex.Lock()
	vmExiste := false
	for _, mv := range ListaUserVMs {
		if mv.Nombre == nombreMV {
			vmExiste = true
			break
		}
	}
	dbMutex.Unlock()

	if !vmExiste {
		redirectWithError(w, r, "La máquina virtual de usuario ya no existe.")
		return
	}

	// Requisito del Parcial: "Eliminar MV"
	runVBoxManage("unregistervm", nombreMV, "--delete")

	dbMutex.Lock()
	var nuevaLista []UserVM
	for _, mv := range ListaUserVMs {
		if mv.Nombre != nombreMV {
			nuevaLista = append(nuevaLista, mv)
		}
	}
	ListaUserVMs = nuevaLista
	if err := saveAppStateLocked(); err != nil {
		dbMutex.Unlock()
		redirectWithError(w, r, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	dbMutex.Unlock()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleVerifyUserAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombreMV := strings.TrimSpace(r.FormValue("nombre"))
	logFlow("VERIFY-USER-ACCESS", "Inicio verificación manual vm=%s", nombreMV)
	if nombreMV == "" {
		redirectWithError(w, r, "Nombre de máquina virtual de usuario no válido para verificación.")
		return
	}

	dbMutex.Lock()
	idx := -1
	for i := range ListaUserVMs {
		if ListaUserVMs[i].Nombre == nombreMV {
			idx = i
			break
		}
	}
	if idx == -1 {
		dbMutex.Unlock()
		redirectWithError(w, r, "La máquina virtual de usuario indicada no existe.")
		return
	}
	vm := ListaUserVMs[idx]
	dbMutex.Unlock()

	if !vm.LlaveGenerada || strings.TrimSpace(vm.NombreLlave) == "" {
		redirectWithError(w, r, "La MV seleccionada no tiene llave de usuario generada. Primero crea usuario y llaves.")
		return
	}

	rutaLlave := filepath.Join(getVBoxKeysPath(), vm.NombreLlave)
	llavePEM, readErr := os.ReadFile(rutaLlave)
	if readErr != nil {
		redirectWithError(w, r, "No fue posible leer la llave privada del usuario para verificar acceso SSH.")
		return
	}

	vmPort, portErr := getFreeLocalPort()
	if portErr != nil {
		redirectWithError(w, r, "No fue posible reservar un puerto local para verificación SSH.")
		return
	}

	runVBoxManage("modifyvm", vm.Nombre, "--natpf1", "delete", "regla_ssh_user")
	runVBoxManage("modifyvm", vm.Nombre, "--natpf1", "delete", "regla_ssh_user_verify")
	if out, err := runVBoxManage("modifyvm", vm.Nombre, "--natpf1", fmt.Sprintf("regla_ssh_user_verify,tcp,127.0.0.1,%s,,22", vmPort)); err != nil {
		redirectWithError(w, r, "No fue posible configurar reenvío SSH para la verificación: "+strings.TrimSpace(string(out)))
		return
	}

	if out, err := runVBoxManage("startvm", vm.Nombre, "--type", "headless"); err != nil {
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		if !strings.Contains(msg, "already") && !strings.Contains(msg, "running") {
			redirectWithError(w, r, "No fue posible iniciar la MV para verificar acceso SSH: "+strings.TrimSpace(string(out)))
			return
		}
	}

	host := fmt.Sprintf("127.0.0.1:%s", vmPort)
	verifyClient, verifyErr := waitForSSHClientWithPrivateKey(host, "usuario_mv", llavePEM, sshBootTimeout)
	if verifyErr != nil {
		logFlow("VERIFY-USER-ACCESS", "Fallo autenticación por llave vm=%s: %v", nombreMV, verifyErr)

		rootClient, rootErr := waitForSSHClient(host, "root", []string{"1234", "nicolas"}, 30*time.Second)
		if rootErr == nil {
			rootSession, rootSessionErr := rootClient.NewSession()
			if rootSessionErr == nil {
				diagCmd := `user_home="$(getent passwd usuario_mv | cut -d: -f6)"; [ -n "$user_home" ] || user_home="/home/usuario_mv"; echo DIAG_USER_HOME=$user_home; getent passwd usuario_mv || true; ls -ld "$user_home" "$user_home/.ssh" "$user_home/.ssh/authorized_keys" 2>/dev/null || true; stat -c 'DIAG_PERM %U:%G %a %n' "$user_home" "$user_home/.ssh" "$user_home/.ssh/authorized_keys" 2>/dev/null || true; grep -Ei '^(PubkeyAuthentication|AuthorizedKeysFile|AllowUsers|DenyUsers|PasswordAuthentication|PermitRootLogin)' /etc/ssh/sshd_config 2>/dev/null || true`
				_, _ = runSSHCommandWithOutputLogged(rootSession, diagCmd)
				rootSession.Close()
			}
			rootClient.Close()
		}

		shutdownVMGracefully(vm.Nombre)
		redirectWithError(w, r, "La verificación SSH falló: no fue posible autenticarse con el usuario y llave generados. Recomendación: vuelve a ejecutar 'Crear Usuario y Llaves' para regenerar y reinyectar una llave consistente.")
		return
	}

	verifySession, verifySessionErr := verifyClient.NewSession()
	if verifySessionErr != nil {
		verifyClient.Close()
		shutdownVMGracefully(vm.Nombre)
		redirectWithError(w, r, "La verificación SSH falló: no fue posible abrir sesión del usuario.")
		return
	}

	verificationCmd := "whoami && echo HOME_PATH=$HOME && mkdir -p \"$HOME\"/verificacion_manual && date > \"$HOME\"/verificacion_manual/ultima_prueba.txt && test -s \"$HOME\"/verificacion_manual/ultima_prueba.txt && echo INTERACCION_MANUAL_OK"
	verifyOut, runErr := runSSHCommandWithOutputLogged(verifySession, verificationCmd)
	verifyText := strings.TrimSpace(string(verifyOut))
	homePath := ""
	for _, line := range strings.Split(verifyText, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "HOME_PATH=") {
			homePath = strings.TrimSpace(strings.TrimPrefix(l, "HOME_PATH="))
			break
		}
	}
	verifySession.Close()
	verifyClient.Close()
	shutdownVMGracefully(vm.Nombre)

	if runErr != nil || !strings.Contains(verifyText, "INTERACCION_MANUAL_OK") || !strings.Contains(verifyText, "usuario_mv") || homePath == "" {
		redirectWithError(w, r, "La autenticación funcionó, pero la interacción manual de prueba falló dentro de la VM.")
		return
	}
	logFlow("VERIFY-USER-ACCESS", "Verificación OK vm=%s home=%s", nombreMV, homePath)

	redirectWithInfo(w, r, "Verificación exitosa: conexión SSH e interacción completadas. HOME del usuario: "+homePath)
}

func handleDeployService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := r.ParseMultipartForm(128 << 20); err != nil {
		redirectWithError(w, r, "No fue posible procesar el formulario de despliegue.")
		return
	}

	vmName := strings.TrimSpace(r.FormValue("vm_name"))
	serviceName := strings.TrimSpace(r.FormValue("service_name"))
	runtimeBinary := normalizeRuntimeBinary(r.FormValue("runtime_binary"))
	destination := strings.TrimSpace(r.FormValue("destination_path"))
	startCommand := strings.TrimSpace(r.FormValue("start_command"))
	counterFile := strings.TrimSpace(r.FormValue("counter_file"))
	if counterFile == "" {
		counterFile = "app_runs.log"
	}

	if vmName == "" || serviceName == "" || destination == "" || startCommand == "" {
		redirectWithError(w, r, "Debes suministrar VM, nombre de servicio, carpeta destino y comando de inicio.")
		return
	}
	if !isAllowedRuntimeBinary(runtimeBinary) {
		redirectWithError(w, r, "El binario/runtime seleccionado no está permitido por el servidor.")
		return
	}
	if !strings.EqualFold(firstToken(startCommand), runtimeBinary) {
		redirectWithError(w, r, "El comando de inicio debe comenzar con el runtime seleccionado (por ejemplo: "+runtimeBinary+" ...).")
		return
	}
	if !strings.HasSuffix(strings.ToLower(serviceName), ".service") {
		serviceName += ".service"
	}

	vmWasRunning := !isVMPoweredOff(vmName)
	natRuleName := buildServiceNatRuleName(serviceName)
	sshRuleName := "regla_service_ssh"
	tmpService := fmt.Sprintf("/tmp/%s", serviceName)
	remoteZip := ""
	runScriptPath := ""
	deployCompleted := false
	cleanupDestination := false
	cleanupService := false
	var rootClient *ssh.Client

	zipFile, zipHeader, err := r.FormFile("app_zip")
	if err != nil {
		redirectWithError(w, r, "Debes adjuntar un archivo ZIP con la aplicación.")
		return
	}
	defer zipFile.Close()

	if !strings.HasSuffix(strings.ToLower(zipHeader.Filename), ".zip") {
		redirectWithError(w, r, "El archivo suministrado debe estar en formato .zip.")
		return
	}

	zipBytes, readErr := io.ReadAll(zipFile)
	if readErr != nil || len(zipBytes) == 0 {
		redirectWithError(w, r, "No fue posible leer el contenido del ZIP o está vacío.")
		return
	}

	dbMutex.Lock()
	vmFound := false
	keyName := ""
	for _, vm := range ListaUserVMs {
		if vm.Nombre == vmName {
			vmFound = true
			keyName = vm.NombreLlave
			break
		}
	}
	dbMutex.Unlock()

	if !vmFound || keyName == "" {
		redirectWithError(w, r, "La VM seleccionada no existe o no tiene llave de usuario generada.")
		return
	}

	keyPath := filepath.Join(getVBoxKeysPath(), keyName)
	privateKeyPEM, keyErr := os.ReadFile(keyPath)
	if keyErr != nil {
		redirectWithError(w, r, "No fue posible leer la llave privada de la VM seleccionada.")
		return
	}

	host, hostErr := prepareVMUserSSHEndpoint(vmName, sshRuleName)
	if hostErr != nil {
		redirectWithError(w, r, hostErr.Error())
		return
	}

	defer func() {
		if rootClient != nil {
			_ = rootClient.Close()
		}
	}()

	defer func() {
		if deployCompleted {
			return
		}

		deleteNatRuleIfExistsRuntimeAware(vmName, natRuleName)
		deleteNatRuleIfExistsRuntimeAware(vmName, sshRuleName)

		if rootClient != nil {
			if cleanupService {
				cleanupSvcCmd := fmt.Sprintf("systemctl stop %s 2>/dev/null || true; systemctl disable %s 2>/dev/null || true; rm -f /etc/systemd/system/%s %s; systemctl daemon-reload || true", shellSingleQuote(serviceName), shellSingleQuote(serviceName), shellSingleQuote(serviceName), shellSingleQuote(tmpService))
				_, _ = runSSHCommandWithOutputLoggedFromClient(rootClient, cleanupSvcCmd)
			}

			if cleanupDestination && destination != "" {
				cleanupDirCmd := fmt.Sprintf("rm -rf %s", shellSingleQuote(destination))
				_, _ = runSSHCommandWithOutputLoggedFromClient(rootClient, cleanupDirCmd)
			}

			if remoteZip != "" {
				cleanupZipCmd := fmt.Sprintf("rm -f %s", shellSingleQuote(remoteZip))
				_, _ = runSSHCommandWithOutputLoggedFromClient(rootClient, cleanupZipCmd)
			}
		}

		if !vmWasRunning {
			shutdownVMGracefully(vmName)
		}
	}()

	userClient, userErr := waitForSSHClientWithPrivateKey(host, "usuario_mv", privateKeyPEM, sshBootTimeout)
	if userErr != nil {
		redirectWithError(w, r, "No fue posible conectar por SSH con usuario_mv para desplegar la aplicación.")
		return
	}
	defer userClient.Close()

	rootClient, rootErr := waitForSSHClient(host, "root", []string{"1234", "nicolas"}, 45*time.Second)
	if rootErr != nil {
		redirectWithError(w, r, "No fue posible conectar por SSH como root para preparar dependencias del despliegue.")
		return
	}

	if _, depErr := runSSHCommandWithOutputLoggedFromClient(rootClient, "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y unzip"); depErr != nil {
		redirectWithError(w, r, "No fue posible instalar unzip en la VM para procesar el archivo ZIP.")
		return
	}

	safeService := strings.NewReplacer(".", "_", "-", "_", " ", "_").Replace(strings.TrimSuffix(serviceName, ".service"))
	remoteZip = fmt.Sprintf("/tmp/%s_%d.zip", safeService, time.Now().Unix())
	if upErr := uploadBytesOverSSH(userClient, remoteZip, zipBytes); upErr != nil {
		redirectWithError(w, r, "No fue posible subir el archivo ZIP a la VM.")
		return
	}

	if _, cmdErr := runSSHCommandWithOutputLoggedFromClient(userClient,
		fmt.Sprintf("mkdir -p %s && unzip -o %s -d %s", shellSingleQuote(destination), shellSingleQuote(remoteZip), shellSingleQuote(destination))); cmdErr != nil {
		redirectWithError(w, r, "No fue posible descomprimir la aplicación en la carpeta destino.")
		return
	}
	cleanupDestination = true

	runScriptPath = filepath.ToSlash(filepath.Join(destination, fmt.Sprintf("run_%s.sh", safeService)))
	execStart := startCommand
	if runtimeBinary == "python3" {
		execStart = fmt.Sprintf(".venv/bin/python3 %s", strings.TrimSpace(strings.TrimPrefix(startCommand, "python3")))
	}
	runScriptContent := fmt.Sprintf("#!/usr/bin/env bash\nset -e\ncd %s\nCOUNTER_FILE=%s\nif [ -f \"$COUNTER_FILE\" ]; then\n  LAST=\"$(tail -n 1 \"$COUNTER_FILE\" | awk '{print $1}')\"\n  if [[ \"$LAST\" =~ ^[0-9]+$ ]]; then NEXT=$((LAST+1)); else NEXT=1; fi\nelse\n  NEXT=1\nfi\necho \"${NEXT} - $(date '+%%Y-%%m-%%d %%H:%%M:%%S')\" >> \"$COUNTER_FILE\"\nexec %s\n", shellSingleQuote(destination), shellSingleQuote(counterFile), execStart)
	if upErr := uploadBytesOverSSH(userClient, runScriptPath, []byte(runScriptContent)); upErr != nil {
		redirectWithError(w, r, "No fue posible subir el script de ejecución a la VM.")
		return
	}
	if _, cmdErr := runSSHCommandWithOutputLoggedFromClient(userClient, fmt.Sprintf("chmod +x %s", shellSingleQuote(runScriptPath))); cmdErr != nil {
		redirectWithError(w, r, "No fue posible asignar permisos al script de ejecución.")
		return
	}

	dependencyInstallMsg := ""
	if runtimeBinary == "python3" {
		if _, depErr := runSSHCommandWithOutputLoggedFromClient(rootClient, "export DEBIAN_FRONTEND=noninteractive; apt-get install -y python3 python3-pip python3-venv"); depErr != nil {
			redirectWithError(w, r, "No fue posible preparar Python/pip en la VM para instalar dependencias.")
			return
		}

		installReqCmd := fmt.Sprintf("su - usuario_mv -c %s", shellSingleQuote(fmt.Sprintf("cd %s && python3 -m venv .venv && .venv/bin/python -m pip install --upgrade pip && if [ -f requirements.txt ]; then .venv/bin/pip install -r requirements.txt; else echo 'requirements.txt no encontrado'; fi", shellSingleQuote(destination))))
		if _, depErr := runSSHCommandWithOutputLoggedFromClient(rootClient, installReqCmd); depErr != nil {
			redirectWithError(w, r, "No fue posible crear el entorno virtual e instalar dependencias Python desde requirements.txt.")
			return
		}
		dependencyInstallMsg = " Entorno virtual Python creado e instalación de dependencias ejecutada (si requirements.txt existía)."
	}

	serviceContent := fmt.Sprintf("[Unit]\nDescription=Servicio %s\nAfter=network.target\n\n[Service]\nType=simple\nUser=usuario_mv\nWorkingDirectory=%s\nExecStart=/bin/bash %s\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n", strings.TrimSuffix(serviceName, ".service"), destination, runScriptPath)
	if upErr := uploadBytesOverSSH(rootClient, tmpService, []byte(serviceContent)); upErr != nil {
		redirectWithError(w, r, "No fue posible subir el archivo .service a la VM.")
		return
	}

	installCmd := fmt.Sprintf("install -m 644 %s /etc/systemd/system/%s && systemctl daemon-reload", shellSingleQuote(tmpService), shellSingleQuote(serviceName))
	if _, cmdErr := runSSHCommandWithOutputLoggedFromClient(rootClient, installCmd); cmdErr != nil {
		redirectWithError(w, r, "No fue posible instalar/recargar el servicio en systemd.")
		return
	}
	cleanupService = true

	appGuestPort := inferGuestAppPortForRuntime(startCommand, runtimeBinary)

	dbMutex.Lock()
	previousHostPort := ""
	for _, s := range ListaServicios {
		if s.VMName == vmName && s.ServiceName == serviceName && strings.TrimSpace(s.AppHostPort) != "" {
			previousHostPort = strings.TrimSpace(s.AppHostPort)
			break
		}
	}
	dbMutex.Unlock()

	appHostPort := previousHostPort
	if appHostPort == "" {
		generatedHostPort, portErr := getFreeLocalPort()
		if portErr != nil {
			redirectWithError(w, r, "No fue posible reservar un puerto local para exponer la aplicación.")
			return
		}
		appHostPort = generatedHostPort
	}

	deleteNatRuleIfExistsRuntimeAware(vmName, natRuleName)
	appRuleSpec := fmt.Sprintf("%s,tcp,127.0.0.1,%s,,%s", natRuleName, appHostPort, appGuestPort)
	if err := setNatRuleRuntimeAware(vmName, appRuleSpec); err != nil {
		redirectWithError(w, r, "No fue posible configurar el reenvío automático de puertos para la aplicación: "+err.Error())
		return
	}
	appEndpoint := fmt.Sprintf("http://127.0.0.1:%s", appHostPort)

	statusOut, _ := runSSHCommandWithOutputLoggedFromClient(rootClient, fmt.Sprintf("systemctl is-active %s 2>/dev/null || true", shellSingleQuote(serviceName)))
	enabledOut, _ := runSSHCommandWithOutputLoggedFromClient(rootClient, fmt.Sprintf("systemctl is-enabled %s 2>/dev/null || true", shellSingleQuote(serviceName)))
	logOut, _ := runSSHCommandWithOutputLoggedFromClient(userClient, fmt.Sprintf("tail -n 20 %s 2>/dev/null || true", shellSingleQuote(filepath.ToSlash(filepath.Join(destination, counterFile)))))

	dbMutex.Lock()
	upsertServiceDeploymentLocked(ServiceDeployment{
		VMName:          vmName,
		ServiceName:     serviceName,
		RuntimeBinary:   runtimeBinary,
		NatRuleName:     natRuleName,
		AppHostPort:     appHostPort,
		AppGuestPort:    appGuestPort,
		AppEndpoint:     appEndpoint,
		DestinationPath: destination,
		StartCommand:    startCommand,
		CounterFile:     counterFile,
		ZipFilename:     zipHeader.Filename,
		Status:          strings.TrimSpace(string(statusOut)),
		Enabled:         strings.TrimSpace(string(enabledOut)),
		LastLogTail:     strings.TrimSpace(string(logOut)),
		LastChecked:     time.Now().Format("2006-01-02 15:04:05"),
	})
	if err := saveAppStateLocked(); err != nil {
		dbMutex.Unlock()
		redirectWithError(w, r, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	dbMutex.Unlock()
	deleteNatRuleIfExistsRuntimeAware(vmName, sshRuleName)
	deployCompleted = true

	redirectWithInfo(w, r, "Despliegue completado: ZIP cargado, servicio instalado y puerto de aplicación publicado en "+appEndpoint+"."+dependencyInstallMsg)
}

func runSSHCommandWithOutputLoggedFromClient(client *ssh.Client, command string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	return runSSHCommandWithOutputLogged(session, command)
}

func handleServiceAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	vmName := strings.TrimSpace(r.FormValue("vm_name"))
	serviceName := strings.TrimSpace(r.FormValue("service_name"))
	action := strings.TrimSpace(strings.ToLower(r.FormValue("action")))
	logFlow("SERVICE-ACTION", "Inicio acción=%s vm=%s servicio=%s", action, vmName, serviceName)
	if vmName == "" || serviceName == "" || action == "" {
		redirectWithError(w, r, "Datos insuficientes para la acción del servicio.")
		return
	}
	vmWasRunning := !isVMPoweredOff(vmName)

	dbMutex.Lock()
	idx := -1
	var dep ServiceDeployment
	for i := range ListaServicios {
		if ListaServicios[i].VMName == vmName && ListaServicios[i].ServiceName == serviceName {
			idx = i
			dep = ListaServicios[i]
			break
		}
	}
	dbMutex.Unlock()

	if idx == -1 {
		logFlow("SERVICE-ACTION", "No existe despliegue registrado vm=%s servicio=%s", vmName, serviceName)
		redirectWithError(w, r, "No existe un despliegue registrado para esa VM y servicio.")
		return
	}

	host, hostErr := prepareVMUserSSHEndpoint(vmName, "regla_service_ssh")
	if hostErr != nil {
		logFlow("SERVICE-ACTION", "Error preparando endpoint SSH vm=%s servicio=%s err=%v", vmName, serviceName, hostErr)
		redirectWithError(w, r, hostErr.Error())
		return
	}
	logFlow("SERVICE-ACTION", "Endpoint SSH listo vm=%s host=%s", vmName, host)

	rootClient, rootErr := waitForSSHClient(host, "root", []string{"1234", "nicolas"}, 45*time.Second)
	if rootErr != nil {
		logFlow("SERVICE-ACTION", "Error conexión SSH root vm=%s servicio=%s err=%v", vmName, serviceName, rootErr)
		redirectWithError(w, r, "No fue posible conectar por SSH como root para gestionar el servicio.")
		return
	}
	defer rootClient.Close()
	defer deleteNatRuleIfExistsRuntimeAware(vmName, "regla_service_ssh")

	if action == "delete-app" {
		logFlow("SERVICE-ACTION", "Eliminando aplicación vm=%s servicio=%s", vmName, serviceName)

		cleanupCmd := fmt.Sprintf("systemctl stop %s 2>/dev/null || true; systemctl disable %s 2>/dev/null || true; rm -f /etc/systemd/system/%s /tmp/%s; systemctl daemon-reload || true; rm -rf %s", shellSingleQuote(serviceName), shellSingleQuote(serviceName), shellSingleQuote(serviceName), shellSingleQuote(serviceName), shellSingleQuote(dep.DestinationPath))
		if _, err := runSSHCommandWithOutputLoggedFromClient(rootClient, cleanupCmd); err != nil {
			logFlow("SERVICE-ACTION", "Error limpiando servicio/carpeta vm=%s servicio=%s err=%v", vmName, serviceName, err)
			redirectWithError(w, r, "No fue posible eliminar completamente servicio/carpeta de la aplicación.")
			return
		}

		natRuleName := strings.TrimSpace(dep.NatRuleName)
		if natRuleName == "" {
			natRuleName = buildServiceNatRuleName(serviceName)
		}
		deleteNatRuleIfExistsRuntimeAware(vmName, natRuleName)

		dbMutex.Lock()
		nuevaLista := make([]ServiceDeployment, 0, len(ListaServicios))
		for i := range ListaServicios {
			if !(ListaServicios[i].VMName == vmName && ListaServicios[i].ServiceName == serviceName) {
				nuevaLista = append(nuevaLista, ListaServicios[i])
			}
		}
		ListaServicios = nuevaLista
		if err := saveAppStateLocked(); err != nil {
			dbMutex.Unlock()
			logFlow("SERVICE-ACTION", "Error persistiendo eliminación vm=%s servicio=%s err=%v", vmName, serviceName, err)
			redirectWithError(w, r, "Se eliminó en VM, pero no se pudo persistir el estado local: "+err.Error())
			return
		}
		dbMutex.Unlock()

		if !vmWasRunning {
			shutdownVMGracefully(vmName)
		}

		logFlow("SERVICE-ACTION", "Aplicación eliminada vm=%s servicio=%s", vmName, serviceName)
		redirectWithInfo(w, r, "Aplicación eliminada: servicio, carpeta y configuración de red removidos.")
		return
	}

	if action == "start" || action == "stop" || action == "restart" || action == "enable" || action == "disable" {
		cmd := fmt.Sprintf("systemctl %s %s", action, shellSingleQuote(serviceName))
		logFlow("SERVICE-ACTION", "Ejecutando systemctl acción=%s vm=%s servicio=%s", action, vmName, serviceName)
		if _, err := runSSHCommandWithOutputLoggedFromClient(rootClient, cmd); err != nil {
			logFlow("SERVICE-ACTION", "Error en systemctl acción=%s vm=%s servicio=%s err=%v", action, vmName, serviceName, err)
			redirectWithError(w, r, "No fue posible ejecutar la acción systemd solicitada.")
			return
		}

		counterName := strings.TrimSpace(dep.CounterFile)
		if counterName == "" {
			counterName = "app_runs.log"
		}
		counterPath := filepath.ToSlash(filepath.Join(dep.DestinationPath, counterName))
		actionUpper := strings.ToUpper(action)
		appendActionLogCmd := fmt.Sprintf("su - usuario_mv -c %s", shellSingleQuote(fmt.Sprintf("set -e; mkdir -p %s; touch %s; LAST=$(tail -n 1 %s 2>/dev/null | awk '{print $1}'); if [[ \"$LAST\" =~ ^[0-9]+$ ]]; then NEXT=$((LAST+1)); else NEXT=1; fi; echo \"${NEXT} - ACTION_%s - $(date '+%%Y-%%m-%%d %%H:%%M:%%S')\" >> %s", shellSingleQuote(dep.DestinationPath), shellSingleQuote(counterPath), shellSingleQuote(counterPath), actionUpper, shellSingleQuote(counterPath))))
		if _, err := runSSHCommandWithOutputLoggedFromClient(rootClient, appendActionLogCmd); err != nil {
			logFlow("SERVICE-ACTION", "Error registrando acción en counter_file vm=%s servicio=%s action=%s err=%v", vmName, serviceName, action, err)
			redirectWithError(w, r, "La acción se ejecutó, pero no se pudo registrar evidencia en el archivo de trazas.")
			return
		}
	}

	statusOut, _ := runSSHCommandWithOutputLoggedFromClient(rootClient, fmt.Sprintf("systemctl is-active %s 2>/dev/null || true", shellSingleQuote(serviceName)))
	enabledOut, _ := runSSHCommandWithOutputLoggedFromClient(rootClient, fmt.Sprintf("systemctl is-enabled %s 2>/dev/null || true", shellSingleQuote(serviceName)))

	keyPath := filepath.Join(getVBoxKeysPath(), "")
	dbMutex.Lock()
	for _, vm := range ListaUserVMs {
		if vm.Nombre == vmName {
			keyPath = filepath.Join(getVBoxKeysPath(), vm.NombreLlave)
			break
		}
	}
	dbMutex.Unlock()

	privateKeyPEM, keyErr := os.ReadFile(keyPath)
	var tailText string
	if keyErr == nil {
		if userClient, userErr := waitForSSHClientWithPrivateKey(host, "usuario_mv", privateKeyPEM, 20*time.Second); userErr == nil {
			defer userClient.Close()
			logOut, _ := runSSHCommandWithOutputLoggedFromClient(userClient, fmt.Sprintf("tail -n 20 %s 2>/dev/null || true", shellSingleQuote(filepath.ToSlash(filepath.Join(dep.DestinationPath, dep.CounterFile)))))
			tailText = strings.TrimSpace(string(logOut))
		} else {
			logFlow("SERVICE-ACTION", "No se pudo leer tail de ejecución vm=%s servicio=%s err=%v", vmName, serviceName, userErr)
		}
	} else {
		logFlow("SERVICE-ACTION", "No se pudo leer llave de usuario para tail vm=%s servicio=%s err=%v", vmName, serviceName, keyErr)
	}

	dbMutex.Lock()
	for i := range ListaServicios {
		if ListaServicios[i].VMName == vmName && ListaServicios[i].ServiceName == serviceName {
			ListaServicios[i].Status = strings.TrimSpace(string(statusOut))
			ListaServicios[i].Enabled = strings.TrimSpace(string(enabledOut))
			if tailText != "" {
				ListaServicios[i].LastLogTail = tailText
			}
			ListaServicios[i].LastChecked = time.Now().Format("2006-01-02 15:04:05")
		}
	}
	if err := saveAppStateLocked(); err != nil {
		dbMutex.Unlock()
		logFlow("SERVICE-ACTION", "Error persistiendo estado vm=%s servicio=%s err=%v", vmName, serviceName, err)
		redirectWithError(w, r, "No fue posible persistir el estado en disco: "+err.Error())
		return
	}
	dbMutex.Unlock()
	logFlow("SERVICE-ACTION", "Acción finalizada acción=%s vm=%s servicio=%s estado=%s habilitado=%s", action, vmName, serviceName, strings.TrimSpace(string(statusOut)), strings.TrimSpace(string(enabledOut)))

	redirectWithInfo(w, r, "Acción aplicada al servicio y estado actualizado.")
}
