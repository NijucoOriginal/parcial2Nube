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

var LlavesSshActivas bool = false

var (
	templatesDB []TemplateVM
	dbMutex     sync.Mutex
	tmpl        *template.Template
)

type PageData struct {
	Templates     []TemplateVM
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

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/add", handleAddTemplate)
	http.HandleFunc("/create-key", handleCreateKey)
	http.HandleFunc("/download-key", handleDownloadKey)

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
