package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
}

// NUEVA ESTRUCTURA: Máquina Virtual de Usuario
type UserVM struct {
	Nombre        string
	Descripcion   string
	PlantillaBase string
	DiscoAsignado string
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

type PageData struct {
	Templates     []TemplateVM
	Discos        []DiscoCompartido
	UserVMs       []UserVM // Pasamos los usuarios al HTML
	LlavesActivas bool
	Error         string
}

func init() {
	tmpl = template.Must(template.ParseFiles("templates/index.html"))
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
		LlavesActivas: LlavesSshActivas,
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

	dbMutex.Lock()
	defer dbMutex.Unlock()

	for _, t := range templatesDB {
		if strings.EqualFold(t.Nombre, nombre) {
			tmpl.Execute(w, PageData{
				Templates:     templatesDB,
				Discos:        ListaDiscos,
				UserVMs:       ListaUserVMs,
				LlavesActivas: LlavesSshActivas,
				Error:         "Error: Ya existe una plantilla con el nombre '" + nombre + "'.",
			})
			return
		}
	}

	nuevaPlantilla := TemplateVM{
		Nombre:        nombre,
		Descripcion:   r.FormValue("descripcion"),
		PlantillaBase: r.FormValue("base"),
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
	nombrePlantilla := r.FormValue("nombre")

	dbMutex.Lock()
	defer dbMutex.Unlock()

	for i, t := range templatesDB {
		if t.Nombre == nombrePlantilla && !t.LlaveGenerada {

			rootPassword := "nicolas"
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
				return
			} else {
				defer client.Close()
				session, err := client.NewSession()
				if err == nil {
					defer session.Close()
					comandoSSH := fmt.Sprintf(`mkdir -p /root/.ssh && echo "%s" >> /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys`, strings.TrimSpace(string(pubKeyBytes)))

					if err := session.Run(comandoSSH); err == nil {
						fmt.Println("¡Llave inyectada exitosamente en la MV!")
						LlavesSshActivas = true
					}
				}
				exec.Command("VBoxManage", "controlvm", t.PlantillaBase, "poweroff").Run()
			}

			templatesDB[i].LlaveGenerada = true
			templatesDB[i].NombreLlave = nombreLlavePrivada
			break
		}
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
	r.ParseForm()
	nombreDisco := strings.TrimSpace(r.FormValue("nombre_disco"))
	plantillaOrigen := r.FormValue("plantilla_origen")

	if !LlavesSshActivas {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	so := "Desconocido"
	dbMutex.Lock()
	for _, t := range templatesDB {
		if t.Nombre == plantillaOrigen {
			so = t.PlantillaBase
			break
		}
	}
	dbMutex.Unlock()

	ruta := getDiskPath(nombreDisco)
	exec.Command("VBoxManage", "createmedium", "disk", "--filename", ruta, "--size", "1000", "--format", "VDI").Run()
	exec.Command("VBoxManage", "modifyhd", ruta, "--type", "shareable").Run()

	dbMutex.Lock()
	ListaDiscos = append(ListaDiscos, DiscoCompartido{
		Nombre:           nombreDisco,
		Ruta:             ruta,
		PlantillaOrigen:  plantillaOrigen,
		SistemaOperativo: so,
		Estado:           "Desconectado",
	})
	dbMutex.Unlock()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDeleteDisk(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	nombreDisco := r.FormValue("disco")

	exec.Command("VBoxManage", "closemedium", "disk", getDiskPath(nombreDisco), "--delete").Run()

	dbMutex.Lock()
	var nuevaLista []DiscoCompartido
	for _, d := range ListaDiscos {
		if d.Nombre != nombreDisco {
			nuevaLista = append(nuevaLista, d)
		}
	}
	ListaDiscos = nuevaLista
	dbMutex.Unlock()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleConnectDisk(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	nombreDisco := r.FormValue("disco")
	targetVM := r.FormValue("target_vm") // Ahora capturamos la MV de usuario desde el comboBox

	if targetVM != "" {
		exec.Command("VBoxManage", "storageattach", targetVM, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "hdd", "--medium", getDiskPath(nombreDisco)).Run()

		dbMutex.Lock()
		for i := range ListaDiscos {
			if ListaDiscos[i].Nombre == nombreDisco {
				ListaDiscos[i].Estado = "Conectado a " + targetVM
			}
		}
		dbMutex.Unlock()
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDisconnectDisk(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	nombreDisco := r.FormValue("disco")
	targetVM := r.FormValue("target_vm") // Capturamos la MV de usuario

	if targetVM != "" {
		exec.Command("VBoxManage", "storageattach", targetVM, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "hdd", "--medium", "none").Run()

		dbMutex.Lock()
		for i := range ListaDiscos {
			if ListaDiscos[i].Nombre == nombreDisco {
				ListaDiscos[i].Estado = "Desconectado"
			}
		}
		dbMutex.Unlock()
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ==========================================
// FUNCIONES DE MÁQUINAS DE USUARIO
// ==========================================

func handleCreateUserVM(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	nombreDisco := r.FormValue("disco")
	plantillaOrigen := r.FormValue("plantilla") // Solo lo usamos como referencia de nombre

	nombreMV := strings.TrimSpace(r.FormValue("nombre_mv"))
	descripcion := strings.TrimSpace(r.FormValue("descripcion"))

	// 1. Obtener la ruta raíz y forzar la creación de la carpeta GrupoUsuarios
	homeDir, _ := os.UserHomeDir()
	grupoUsuariosPath := filepath.Join(homeDir, "VirtualBox VMs", "GrupoUsuarios")
	os.MkdirAll(grupoUsuariosPath, os.ModePerm)

	fmt.Printf("\n--- CREANDO MV DE USUARIO NUEVA: %s ---\n", nombreMV)

	// 2. CREAR una máquina NUEVA desde cero (NO clonar)
	cmdCreate := exec.Command("VBoxManage", "createvm", "--name", nombreMV, "--basefolder", grupoUsuariosPath, "--groups", "/GrupoUsuarios", "--register")
	outCreate, errCreate := cmdCreate.CombinedOutput()

	if errCreate != nil {
		fmt.Printf("ERROR AL CREAR MV NUEVA: %v\nDetalles: %s\n", errCreate, string(outCreate))
		http.Redirect(w, r, "/?error=Fallo_al_crear_la_MV", http.StatusSeeOther)
		return
	}
	fmt.Println("MV Nueva creada y registrada exitosamente.")

	// 3. Crear un controlador SATA (Las máquinas nuevas vienen "peladas", necesitan esto para conectar el disco)
	cmdCtl := exec.Command("VBoxManage", "storagectl", nombreMV, "--name", "SATA", "--add", "sata", "--controller", "IntelAHCI")
	outCtl, errCtl := cmdCtl.CombinedOutput()
	if errCtl != nil {
		fmt.Printf("Advertencia al crear controlador SATA: %v\nDetalles: %s\n", errCtl, string(outCtl))
	}

	// 4. Adjuntar el disco multiconexión al controlador recién creado
	cmdStorage := exec.Command("VBoxManage", "storageattach", nombreMV, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "hdd", "--medium", getDiskPath(nombreDisco))
	outStorage, errStorage := cmdStorage.CombinedOutput()

	if errStorage != nil {
		fmt.Printf("Error al adjuntar el disco: %v\nDetalles: %s\n", errStorage, string(outStorage))
	} else {
		fmt.Println("Disco compartido adjuntado correctamente.")
	}

	// 5. Guardar en tu base de datos de memoria
	dbMutex.Lock()
	ListaUserVMs = append(ListaUserVMs, UserVM{
		Nombre:        nombreMV,
		Descripcion:   descripcion,
		PlantillaBase: plantillaOrigen, // Aquí guardamos el nombre de la plantilla como pediste
		DiscoAsignado: nombreDisco,
		LlaveGenerada: false,
	})
	dbMutex.Unlock()

	fmt.Println("Proceso terminado. Actualizando interfaz...")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleCreateUserKey(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	nombreMV := r.FormValue("nombre")

	dbMutex.Lock()
	defer dbMutex.Unlock()

	for i, mv := range ListaUserVMs {
		if mv.Nombre == nombreMV && !mv.LlaveGenerada {
			rootPassword := "nicolas"
			vmIP := "127.0.0.1"
			vmPort := "2225" // Usamos puerto 2225 para no chocar con la base

			fmt.Printf("Configurando red para MV de Usuario: %s...\n", mv.Nombre)
			exec.Command("VBoxManage", "modifyvm", mv.Nombre, "--natpf1", "delete", "regla_ssh").Run()
			exec.Command("VBoxManage", "modifyvm", mv.Nombre, "--natpf1", "regla_ssh,tcp,127.0.0.1,2225,,22").Run()

			fmt.Printf("Encendiendo MV de Usuario: %s...\n", mv.Nombre)
			exec.Command("VBoxManage", "startvm", mv.Nombre, "--type", "headless").Run()

			time.Sleep(60 * time.Second)

			privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
			nombreLlavePrivada := fmt.Sprintf("rsa_user_%s.pem", mv.Nombre)
			rutaArchivo := filepath.Join(getVBoxKeysPath(), nombreLlavePrivada)

			llavePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
			os.WriteFile(rutaArchivo, llavePEM, 0600)

			publicRsaKey, _ := ssh.NewPublicKey(&privateKey.PublicKey)
			pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

			sshConfig := &ssh.ClientConfig{
				User: "root", Auth: []ssh.AuthMethod{ssh.Password(rootPassword)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second,
			}

			client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", vmIP, vmPort), sshConfig)
			if err == nil {
				defer client.Close()
				session, _ := client.NewSession()
				defer session.Close()

				// Requisito del Parcial: "Crear usuario (incluye llaves)"
				// Creamos un usuario de linux llamado 'usuario_mv' y le inyectamos la llave en su carpeta
				comandoSSH := fmt.Sprintf(`useradd -m -s /bin/bash usuario_mv && mkdir -p /home/usuario_mv/.ssh && echo "%s" >> /home/usuario_mv/.ssh/authorized_keys && chown -R usuario_mv:usuario_mv /home/usuario_mv/.ssh && chmod 700 /home/usuario_mv/.ssh && chmod 600 /home/usuario_mv/.ssh/authorized_keys`, strings.TrimSpace(string(pubKeyBytes)))

				session.Run(comandoSSH)
				fmt.Println("¡Usuario creado y llave inyectada!")
			}

			exec.Command("VBoxManage", "controlvm", mv.Nombre, "poweroff").Run()

			ListaUserVMs[i].LlaveGenerada = true
			ListaUserVMs[i].NombreLlave = nombreLlavePrivada
			break
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDeleteUserVM(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	nombreMV := r.FormValue("nombre")

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
