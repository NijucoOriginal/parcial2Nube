package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
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

var ListaDiscos []DiscoCompartido
var ListaUserVMs []UserVM // Lista para el nuevo dashboard
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

type PageData struct {
	Templates     []TemplateVM
	Discos        []DiscoCompartido
	UserVMs       []UserVM // Pasamos los usuarios al HTML
	LlavesActivas bool
	Error         string
	Info          string
}

// ==========================================
// PERSISTENCIA DE DATOS
// ==========================================
type AppState struct {
	Templates        []TemplateVM      `json:"templates"`
	Discos           []DiscoCompartido `json:"discos"`
	UserVMs          []UserVM          `json:"user_vms"`
	LlavesSshActivas bool              `json:"llaves_activas"`
}

func saveDB() {
	state := AppState{
		Templates:        templatesDB,
		Discos:           ListaDiscos,
		UserVMs:          ListaUserVMs,
		LlavesSshActivas: LlavesSshActivas,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err == nil {
		os.WriteFile("database.json", data, 0644)
	}
}

func loadDB() {
	data, err := os.ReadFile("database.json")
	if err == nil {
		var state AppState
		if err := json.Unmarshal(data, &state); err == nil {
			templatesDB = state.Templates
			ListaDiscos = state.Discos
			ListaUserVMs = state.UserVMs
			LlavesSshActivas = state.LlavesSshActivas
		}
	}
}

func init() {
	funcMap := template.FuncMap{
		"contains": strings.Contains,
	}
	tmpl = template.Must(template.New("index.html").Funcs(funcMap).ParseFiles("templates/index.html"))
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

func main() {
	loadDB() // <--- AGREGA ESTA LÍNEA AQUÍ

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

	// Rutas para Despliegue y systemd
	http.HandleFunc("/deploy", handleDeploy)
	http.HandleFunc("/service-action", handleServiceAction)
	http.HandleFunc("/get-logs", handleGetLogs)

	fmt.Println("Servidor corriendo en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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
	saveDB()
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

			rootPassword := "nicolas"
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
			saveDB()
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
	saveDB()
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
	saveDB()
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
	saveDB()
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
	saveDB()
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
	saveDB()
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
	saveDB()
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
	saveDB()
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

// ==========================================
// FUNCIONES DE DESPLIEGUE Y SYSTEMD (PARCIAL 2)
// ==========================================

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Aumentar el límite de tamaño para la subida (ej. 10MB)
	r.ParseMultipartForm(10 << 20)

	targetVM := strings.TrimSpace(r.FormValue("target_vm"))
	rutaDestino := strings.TrimSpace(r.FormValue("ruta_destino"))
	nombreServicio := strings.TrimSpace(r.FormValue("nombre_servicio"))
	parametros := strings.TrimSpace(r.FormValue("parametros"))

	if targetVM == "" || rutaDestino == "" || nombreServicio == "" {
		redirectWithError(w, r, "Faltan datos obligatorios para el despliegue.")
		return
	}

	// Leer el archivo .zip subido
	file, _, err := r.FormFile("app_zip")
	if err != nil {
		redirectWithError(w, r, "Error al leer el archivo .zip subido.")
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		redirectWithError(w, r, "Error al procesar el archivo .zip.")
		return
	}
	// Codificamos en Base64 para transferirlo de forma segura por la terminal SSH
	zipBase64 := base64.StdEncoding.EncodeToString(fileBytes)

	// Configurar red e iniciar MV si no está encendida
	vmPort, _ := getFreeLocalPort()
	runVBoxManage("modifyvm", targetVM, "--natpf1", "delete", "regla_ssh_deploy")
	runVBoxManage("modifyvm", targetVM, "--natpf1", fmt.Sprintf("regla_ssh_deploy,tcp,127.0.0.1,%s,,22", vmPort))
	runVBoxManage("startvm", targetVM, "--type", "headless")

	// Conectar como root (necesario para systemd)
	host := fmt.Sprintf("127.0.0.1:%s", vmPort)
	client, err := waitForSSHClient(host, "root", []string{"1234", "nicolas"}, 30*time.Second)
	if err != nil {
		redirectWithError(w, r, "No fue posible conectar por SSH como root para desplegar la app.")
		return
	}
	defer client.Close()

	session, _ := client.NewSession()
	defer session.Close()

	// 1. Instalar unzip, crear directorio, decodificar ZIP y extraer
	deployCmd := fmt.Sprintf(`
        apt-get update && apt-get install -y unzip;
        mkdir -p %s;
        echo "%s" | base64 -d > /tmp/app.zip;
        unzip -o /tmp/app.zip -d %s;
        chmod +x %s/*.sh
    `, rutaDestino, zipBase64, rutaDestino, rutaDestino)

	if err := runSSHCommandLogged(session, deployCmd); err != nil {
		redirectWithError(w, r, "Error al transferir o descomprimir la aplicación en la MV.")
		return
	}

	// 2. Crear archivo .service de systemd
	if !strings.HasSuffix(nombreServicio, ".service") {
		nombreServicio += ".service"
	}

	// Aseguramos de ejecutar el script en bash. Asumimos que el script se llama app.sh
	execStart := fmt.Sprintf("/bin/bash %s/app.sh %s", rutaDestino, parametros)

	serviceContent := fmt.Sprintf(`[Unit]
Description=Aplicacion Desplegada Automaticamente - %s
After=network.target

[Service]
Type=simple
ExecStart=%s
WorkingDirectory=%s
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, nombreServicio, execStart, rutaDestino)

	serviceBase64 := base64.StdEncoding.EncodeToString([]byte(serviceContent))

	serviceSession, _ := client.NewSession()
	defer serviceSession.Close()

	// Inyectar el servicio, recargar systemd y arrancar
	serviceCmd := fmt.Sprintf(`
        echo "%s" | base64 -d > /etc/systemd/system/%s;
        systemctl daemon-reload;
        systemctl enable %s;
        systemctl start %s
    `, serviceBase64, nombreServicio, nombreServicio, nombreServicio)

	if err := runSSHCommandLogged(serviceSession, serviceCmd); err != nil {
		redirectWithError(w, r, "Error al crear o iniciar el servicio systemd.")
		return
	}

	redirectWithInfo(w, r, "¡Aplicación desplegada y servicio systemd configurado exitosamente!")
}

func handleServiceAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	targetVM := strings.TrimSpace(r.FormValue("target_vm"))
	nombreServicio := strings.TrimSpace(r.FormValue("nombre_servicio"))
	accion := strings.TrimSpace(r.FormValue("accion"))

	if targetVM == "" || nombreServicio == "" || accion == "" {
		redirectWithError(w, r, "Faltan datos para ejecutar la acción.")
		return
	}

	vmPort, _ := getFreeLocalPort()
	runVBoxManage("modifyvm", targetVM, "--natpf1", "delete", "regla_ssh_action")
	runVBoxManage("modifyvm", targetVM, "--natpf1", fmt.Sprintf("regla_ssh_action,tcp,127.0.0.1,%s,,22", vmPort))

	host := fmt.Sprintf("127.0.0.1:%s", vmPort)
	client, err := waitForSSHClient(host, "root", []string{"1234", "nicolas"}, 15*time.Second)
	if err != nil {
		redirectWithError(w, r, "No hay conexión con la MV. Asegúrate de que esté encendida.")
		return
	}
	defer client.Close()

	session, _ := client.NewSession()
	defer session.Close()

	var comando string
	if accion == "status" {
		comando = fmt.Sprintf("systemctl status %s", nombreServicio)
	} else {
		comando = fmt.Sprintf("systemctl %s %s", accion, nombreServicio)
	}

	out, err := session.CombinedOutput(comando)

	// Si es status, lo mostramos como info aunque devuelva error (systemctl status devuelve código != 0 si no está corriendo)
	mensajeOut := strings.ReplaceAll(string(out), "\n", " | ")
	if accion == "status" {
		redirectWithInfo(w, r, fmt.Sprintf("Status de %s: %s", nombreServicio, string(out)))
		return
	}

	if err != nil {
		redirectWithError(w, r, fmt.Sprintf("Error ejecutando '%s': %s", accion, mensajeOut))
		return
	}

	redirectWithInfo(w, r, fmt.Sprintf("Comando '%s' ejecutado exitosamente en %s.", accion, nombreServicio))
}

func handleGetLogs(w http.ResponseWriter, r *http.Request) {
	targetVM := r.URL.Query().Get("vm")
	logFile := r.URL.Query().Get("file")

	if targetVM == "" || logFile == "" {
		http.Error(w, "Faltan parámetros", http.StatusBadRequest)
		return
	}

	// Buscamos dinámicamente qué puerto tiene abierto esa MV para SSH
	// (buscamos en la configuración de VirtualBox para no crear reglas basura repetidas)
	out, err := runVBoxManage("showvminfo", targetVM, "--machinereadable")
	if err != nil {
		http.Error(w, "MV apagada o inaccesible", http.StatusServiceUnavailable)
		return
	}

	// Expresión para buscar cualquier reenvío al puerto 22
	vmPort := ""
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Forwarding") && strings.Contains(line, ",22") {
			parts := strings.Split(line, ",")
			if len(parts) >= 4 {
				vmPort = parts[3] // El puerto local
				break
			}
		}
	}

	if vmPort == "" {
		http.Error(w, "No hay puerto SSH configurado para esta MV actualmente.", http.StatusServiceUnavailable)
		return
	}

	host := fmt.Sprintf("127.0.0.1:%s", vmPort)
	// Para lectura de logs usamos un timeout muy corto para no colgar la interfaz web
	client, err := openSSHClientWithPasswords(host, "root", []string{"1234", "nicolas"})
	if err != nil {
		http.Error(w, "Esperando a que SSH responda...", http.StatusServiceUnavailable)
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		http.Error(w, "Error de sesión", http.StatusInternalServerError)
		return
	}
	defer session.Close()

	// Ejecutamos 'tail -n 15' equivalente para traer las últimas líneas
	outLogs, errLogs := session.CombinedOutput(fmt.Sprintf("tail -n 15 %s", logFile))
	if errLogs != nil {
		w.Write([]byte(fmt.Sprintf("Esperando a que se cree el archivo log en %s...", logFile)))
		return
	}

	w.Write(outLogs)
}
