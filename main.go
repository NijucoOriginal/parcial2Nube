package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
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

var ListaDiscos []DiscoCompartido
var ListaUserVMs []UserVM // Lista para el nuevo dashboard
var LlavesSshActivas bool = false

var (
	templatesDB []TemplateVM
	dbMutex     sync.Mutex
	tmpl        *template.Template
)

const vboxCommandTimeout = 12 * time.Second
const vboxCreateDiskTimeout = 5 * time.Minute
const sshBootTimeout = 2 * time.Minute
const diskSizeNewMB = 5120
const diskSizeMinCloneMB = 10240

type PageData struct {
	Templates     []TemplateVM
	Discos        []DiscoCompartido
	UserVMs       []UserVM // Pasamos los usuarios al HTML
	LlavesActivas bool
	Error         string
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
	ctx, cancel := context.WithTimeout(context.Background(), vboxCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "VBoxManage", args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("timeout ejecutando VBoxManage: %s", strings.Join(args, " "))
	}

	return out, err
}

func runVBoxManageWithTimeout(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "VBoxManage", args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("timeout ejecutando VBoxManage: %s", strings.Join(args, " "))
	}

	return out, err
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
			return client, nil
		}
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

func main() {
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
	http.HandleFunc("/delete-user-vm", handleDeleteUserVM)

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
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleCreateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	nombrePlantilla := strings.TrimSpace(r.FormValue("nombre"))
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
			exec.Command("VBoxManage", "modifyvm", t.PlantillaBase, "--natpf1", "delete", "regla_ssh").Run()

			errPort := exec.Command("VBoxManage", "modifyvm", t.PlantillaBase, "--natpf1", "regla_ssh,tcp,127.0.0.1,2224,,22").Run()
			if errPort != nil {
				fmt.Printf("Advertencia al configurar puerto: %v\n", errPort)
			}

			fmt.Printf("Encendiendo MV: %s...\n", t.PlantillaBase)
			cmd := exec.Command("VBoxManage", "startvm", t.PlantillaBase, "--type", "headless")
			if err := cmd.Run(); err != nil {
				fmt.Printf("Error al encender MV: %v\n", err)
			}

			fmt.Println("Esperando a que la MV inicie (60 segundos)...")
			time.Sleep(60 * time.Second)

			privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
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
			client, err := ssh.Dial("tcp", target, sshConfig)
			if err != nil {
				fmt.Printf("Fallo conexión SSH: %v.\n", err)
				exec.Command("VBoxManage", "controlvm", t.PlantillaBase, "poweroff").Run()
				renderIndexWithErrorLocked(w, "No fue posible conectar por SSH a la máquina virtual base para inyectar llaves root.")
				return
			} else {
				defer client.Close()
				session, err := client.NewSession()
				if err != nil {
					exec.Command("VBoxManage", "controlvm", t.PlantillaBase, "poweroff").Run()
					renderIndexWithErrorLocked(w, "No fue posible abrir sesión SSH en la máquina virtual base.")
					return
				}
				defer session.Close()
				comandoSSH := fmt.Sprintf(`mkdir -p /root/.ssh && echo "%s" >> /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys`, strings.TrimSpace(string(pubKeyBytes)))

				if err := session.Run(comandoSSH); err != nil {
					exec.Command("VBoxManage", "controlvm", t.PlantillaBase, "poweroff").Run()
					renderIndexWithErrorLocked(w, "No fue posible inyectar la llave root en la máquina virtual base.")
					return
				}
				fmt.Println("¡Llave inyectada exitosamente en la MV!")
				LlavesSshActivas = true
				exec.Command("VBoxManage", "controlvm", t.PlantillaBase, "poweroff").Run()
			}

			templatesDB[i].LlaveGenerada = true
			templatesDB[i].NombreLlave = nombreLlavePrivada
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
		if out, err := runVBoxManageWithTimeout(vboxCreateDiskTimeout, "clonemedium", "disk", srcPath, ruta, "--format", "VDI", "--variant", "Standard"); err != nil {
			detail := strings.TrimSpace(string(out))
			if strings.Contains(detail, "VERR_DISK_FULL") {
				renderIndexWithErrorLocked(w, "No hay espacio suficiente en disco para clonar la plantilla. Libera espacio o mueve la carpeta de VirtualBox a una unidad con más capacidad.")
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
			renderIndexWithErrorLocked(w, "Error al preparar el disco clonado de plantilla como multiconexión: "+strings.TrimSpace(string(out)))
			return
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
	dbMutex.Unlock()
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
	cmdCreate := exec.Command("VBoxManage", "createvm", "--name", nombreMV, "--ostype", guestOS, "--basefolder", grupoUsuariosPath, "--groups", "/GrupoUsuarios", "--register")
	outCreate, errCreate := cmdCreate.CombinedOutput()

	if errCreate != nil {
		fmt.Printf("ERROR AL CREAR MV NUEVA: %v\nDetalles: %s\n", errCreate, string(outCreate))
		redirectWithError(w, r, "Error al crear la máquina virtual en VirtualBox.")
		return
	}
	fmt.Println("MV Nueva creada y registrada exitosamente.")

	cmdResources := exec.Command("VBoxManage", "modifyvm", nombreMV, "--memory", "2048", "--cpus", "2", "--nic1", "nat")
	if outResources, errResources := cmdResources.CombinedOutput(); errResources != nil {
		fmt.Printf("Advertencia al configurar recursos de la MV: %v\nDetalles: %s\n", errResources, string(outResources))
	}

	// 3. Crear un controlador SATA (Las máquinas nuevas vienen "peladas", necesitan esto para conectar el disco)
	cmdCtl := exec.Command("VBoxManage", "storagectl", nombreMV, "--name", "SATA Controller", "--add", "sata", "--controller", "IntelAhci")
	outCtl, errCtl := cmdCtl.CombinedOutput()
	if errCtl != nil {
		fmt.Printf("Advertencia al crear controlador SATA: %v\nDetalles: %s\n", errCtl, string(outCtl))
	}

	// 4. Adjuntar el disco multiconexión al controlador recién creado
	cmdStorage := exec.Command("VBoxManage", "storageattach", nombreMV, "--storagectl", "SATA Controller", "--port", "1", "--device", "0", "--type", "hdd", "--medium", discoPath, "--mtype", "shareable")
	outStorage, errStorage := cmdStorage.CombinedOutput()

	if errStorage != nil {
		fmt.Printf("Error al adjuntar el disco: %v\nDetalles: %s\n", errStorage, string(outStorage))
		exec.Command("VBoxManage", "unregistervm", nombreMV, "--delete").Run()
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
	dbMutex.Unlock()

	fmt.Println("Proceso terminado. Actualizando interfaz...")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleCreateUserKey(w http.ResponseWriter, r *http.Request) {
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

	privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
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

	comandoSSH := fmt.Sprintf(`id -u usuario_mv >/dev/null 2>&1 || useradd -m -s /bin/bash usuario_mv; mkdir -p /home/usuario_mv/.ssh && echo "%s" > /home/usuario_mv/.ssh/authorized_keys && chown -R usuario_mv:usuario_mv /home/usuario_mv/.ssh && chmod 700 /home/usuario_mv/.ssh && chmod 600 /home/usuario_mv/.ssh/authorized_keys`, strings.TrimSpace(string(pubKeyBytes)))

	if err := session.Run(comandoSSH); err != nil {
		runVBoxManage("controlvm", mv.Nombre, "poweroff")
		renderIndexWithErrorLocked(w, "No fue posible crear el usuario Linux con llaves en la MV.")
		return
	}
	fmt.Println("¡Usuario creado y llave inyectada!")

	runVBoxManage("controlvm", mv.Nombre, "poweroff")

	dbMutex.Lock()
	if idx >= 0 && idx < len(ListaUserVMs) && ListaUserVMs[idx].Nombre == nombreMV {
		ListaUserVMs[idx].LlaveGenerada = true
		ListaUserVMs[idx].NombreLlave = nombreLlavePrivada
	}
	dbMutex.Unlock()

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
	exec.Command("VBoxManage", "unregistervm", nombreMV, "--delete").Run()

	dbMutex.Lock()
	var nuevaLista []UserVM
	for _, mv := range ListaUserVMs {
		if mv.Nombre != nombreMV {
			nuevaLista = append(nuevaLista, mv)
		}
	}
	ListaUserVMs = nuevaLista
	dbMutex.Unlock()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
