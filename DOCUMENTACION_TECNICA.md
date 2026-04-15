# Documentacion tecnica del parcial

Este documento resume como se implemento cada requisito en la aplicacion, que comandos se usan y como se comunican la maquina anfitriona (Windows) y las maquinas virtuales (VirtualBox).

## 1. Arquitectura general

- Backend: Go (`net/http`) en `main.go`.
- Frontend: plantilla HTML en `templates/index.html`.
- Hipervisor: VirtualBox, controlado por `VBoxManage` desde Go.
- Provisionamiento de llaves y usuarios Linux: SSH (`golang.org/x/crypto/ssh`).

Flujo general:

1. El usuario hace una accion en la interfaz web.
2. El backend recibe un `POST` en un handler.
3. El handler ejecuta comandos `VBoxManage` para crear/configurar recursos.
4. Si corresponde, abre sesion SSH para inyectar llaves o crear usuario.
5. Actualiza estructuras en memoria (`templatesDB`, `ListaDiscos`, `ListaUserVMs`).
6. Redirige al dashboard con estado actualizado.

## 2. Comandos clave usados para cada requisito

### 2.1 Registrar plantilla base y gestion de llaves root

Requisito: crear/registrar plantilla base y generar llaves root para habilitar acciones posteriores.

Comandos usados:

- Configurar NAT Port Forwarding SSH en la VM base:
  - `VBoxManage modifyvm <vm_base> --natpf1 delete regla_ssh`
  - `VBoxManage modifyvm <vm_base> --natpf1 regla_ssh,tcp,127.0.0.1,2224,,22`
- Encender VM base en modo headless:
  - `VBoxManage startvm <vm_base> --type headless`
- Apagar VM base al finalizar:
  - `VBoxManage controlvm <vm_base> poweroff`

Llaves root:

- Se genera par RSA en backend (Go):
  - privada: `rsa_<nombre_template>.pem`
  - publica: se inyecta en `/root/.ssh/authorized_keys`
- Inyeccion por SSH:
  - Usuario: `root`
  - Puerto: `127.0.0.1:2224` (via NAT PF)
  - Comando remoto:
    - `mkdir -p /root/.ssh`
    - append de llave publica en `authorized_keys`
    - `chmod 700 /root/.ssh`
    - `chmod 600 /root/.ssh/authorized_keys`

## 3. Comunicacion maquina anfitriona <-> maquina virtual

La comunicacion se realiza por dos canales:

1. Control de infraestructura (host -> VirtualBox):
   - El backend ejecuta `VBoxManage` con `exec.Command`.
   - Esto crea, modifica, conecta o elimina VMs y discos.

2. Provisionamiento dentro del sistema operativo invitado (host -> guest):
   - Se usa SSH desde Go (`ssh.Dial`) contra `127.0.0.1:<puerto_local>`.
   - El puerto local se reenvia al puerto 22 de la VM usando NAT PF.

Resumen de seguridad/acceso:

- La VM no se expone directamente en red bridge para esta automatizacion.
- Se entra por localhost + port forwarding controlado.
- Luego se inyecta llave para acceso sin password al usuario objetivo.

## 4. Discos multiconexion

Requisito: crear discos multiconexion y conectarlos a varias VMs de usuario.

### 4.1 Creacion de disco nuevo (sin SO)

Comandos:

- Crear disco VDI fijo de 5GB:
  - `VBoxManage createmedium disk --filename <ruta.vdi> --size 5120 --format VDI --variant Fixed`
- Marcar como shareable:
  - `VBoxManage modifymedium disk <ruta.vdi> --type shareable`

Resultado funcional:

- Se registra con `TieneSO=false` y `Tipo=nuevo`.
- Puede conectarse a VMs, pero no permite crear usuario/llaves dentro del guest.

### 4.2 Creacion desde plantilla (con SO)

Comandos:

- Ubicar disco principal de la VM base:
  - `VBoxManage showvminfo <vm_base> --machinereadable`
- Clonar medio:
  - `VBoxManage clonemedium disk <src> <dst> --format VDI --variant Standard`
- Si el clonado queda menor a 10GB, ampliar:
  - `VBoxManage modifymedium disk <dst> --resize 10240`
- Intentar marcar shareable:
  - `VBoxManage modifymedium disk <dst> --type shareable`

Manejo de caso especial:

- Si VirtualBox rechaza shareable por medio dinamico, el sistema reintenta:
  1. cerrar/borrar medio previo
  2. volver a clonar en Fixed
  3. aplicar `--type shareable`

### 4.2.1 Explicacion tecnica: por que fallo en dinamico y por que quedo asi

Durante las pruebas aparecieron estos errores en el flujo de disco con sistema operativo:

- Error de tipo de medio:
  - `Cannot change type ... to 'Shareable' since it is a dynamic medium storage unit`
- Error de espacio insuficiente:
  - `VERR_DISK_FULL` al intentar clonar en `Fixed` en maquinas con poco espacio libre.
- Error por archivo previo existente:
  - `VERR_ALREADY_EXISTS` cuando quedaba un archivo VDI de intentos anteriores.

Causa raiz:

- VirtualBox permite clonar en dinamico (`Standard`) para ahorrar espacio inicial, pero no permite marcar ese disco como `shareable`.
- Para multiconexion real (mismo disco conectado a varias VMs), el medio debe quedar en un formato compatible con `--type shareable`.

Decision final de implementacion:

1. Primer intento de clonado en `Standard` para reducir consumo inicial de almacenamiento.
2. Si al marcar `shareable` falla por ser dinamico, se hace fallback automatico:
   - limpieza del destino (`closemedium --delete` + eliminacion de archivo local)
   - reclonado en `Fixed`
   - nuevo intento de `modifymedium --type shareable`
3. Si falla por espacio (`VERR_DISK_FULL`), se informa al usuario que para multiconexion real debe liberar espacio porque el camino final requiere disco fijo.
4. Si falla por `VERR_ALREADY_EXISTS`, se limpia y se reintenta para evitar bloqueos por residuos de ejecuciones previas.

Con este enfoque se logra equilibrio entre:

- eficiencia inicial (intento dinamico),
- compatibilidad con multiconexion (resultado final shareable),
- y robustez operativa (manejo de errores reales en laboratorio).

### 4.3 Conexion/desconexion de disco en VM de usuario

Comandos:

- Conectar disco:
  - `VBoxManage storageattach <vm_user> --storagectl "SATA Controller" --port 1 --device 0 --type hdd --medium <ruta.vdi> --mtype shareable`
- Desconectar:
  - `VBoxManage storageattach <vm_user> --storagectl "SATA Controller" --port 1 --device 0 --medium none`

Estado del disco:

- Se consulta con:
  - `VBoxManage showmediuminfo disk <ruta.vdi>`
- Se parsea `In use by VMs` para mostrar estado/conectado a.

### 4.4 Eliminacion de disco

Comandos:

1. Desconectar de VMs registradas.
2. Eliminar medio:
   - `VBoxManage closemedium disk <ruta.vdi> --delete`

Tambien se limpia la asignacion en dashboard (`DiscoAsignado="Sin disco"`).

## 5. Creacion de maquinas virtuales de usuario

Requisito: crear MV de usuario y asociar disco multiconexion.

Comandos:

- Crear VM:
  - `VBoxManage createvm --name <vm_user> --ostype <guest_os> --basefolder <GrupoUsuarios> --groups /GrupoUsuarios --register`
- Configurar recursos:
  - `VBoxManage modifyvm <vm_user> --memory 2048 --cpus 2 --nic1 nat`
- Crear controlador SATA:
  - `VBoxManage storagectl <vm_user> --name "SATA Controller" --add sata --controller IntelAhci`
- Adjuntar disco shareable:
  - `VBoxManage storageattach <vm_user> --storagectl "SATA Controller" --port 1 --device 0 --type hdd --medium <ruta.vdi> --mtype shareable`

Eliminacion de VM de usuario:

- `VBoxManage unregistervm <vm_user> --delete`

## 6. Creacion de usuario Linux y llaves en VM de usuario

Requisito: boton "Crear Usuario y Llaves" solo cuando el disco tiene SO.

Validaciones antes de ejecutar:

- La VM existe.
- Tiene disco asignado.
- El disco asignado existe en dashboard.
- `TieneSO=true`.
- La VM aun no tiene llave generada.

Comandos de infraestructura:

- Configurar PF SSH dinamico:
  - `VBoxManage modifyvm <vm_user> --natpf1 delete regla_ssh`
  - `VBoxManage modifyvm <vm_user> --natpf1 delete regla_ssh_user`
  - `VBoxManage modifyvm <vm_user> --natpf1 regla_ssh_user,tcp,127.0.0.1,<puerto_libre>,,22`
- Encender:
  - `VBoxManage startvm <vm_user> --type headless`
- Apagar al terminar:
  - `VBoxManage controlvm <vm_user> poweroff`

Provisionamiento interno por SSH:

- Reintentos hasta timeout para conectar (`waitForSSHClient`).
- Credenciales de fallback configuradas: `1234`, `nicolas`.
- Comando remoto idempotente:
  - crear usuario `usuario_mv` si no existe
  - crear `~usuario_mv/.ssh`
  - escribir `authorized_keys`
  - aplicar owner/permisos

Llave generada:

- privada local: `rsa_user_<nombre_vm>.pem`
- publica: inyectada al usuario `usuario_mv`

### 6.1 Verificacion final de conexion SSH del usuario creado

Adicional al provisionamiento, el sistema ejecuta una validacion final para comprobar que el cliente realmente puede entrar a la MV con:

- usuario: `usuario_mv`
- autenticacion por llave privada recien generada (`rsa_user_<nombre_vm>.pem`)

Flujo de verificacion:

1. Se abre una nueva conexion SSH usando la llave privada (no password).
2. Se abre sesion SSH como `usuario_mv`.
3. Se ejecuta una interaccion real dentro de la VM para validar permisos y operatividad:

- `whoami`
- `mkdir -p /home/usuario_mv/verificacion_ssh`
- `date > /home/usuario_mv/verificacion_ssh/ultima_validacion.txt`
- `test -s /home/usuario_mv/verificacion_ssh/ultima_validacion.txt`
- `echo INTERACCION_OK`

4. Solo se marca exito si:

- la sesion no falla,
- la salida contiene `usuario_mv`,
- la salida contiene `INTERACCION_OK`.

Si la validacion falla, el proceso devuelve error en interfaz y no deja registrado el estado de llave como exitoso para esa MV.

## 7. Timeouts y confiabilidad

Constantes principales:

- `vboxCommandTimeout = 12 * time.Second`
- `vboxCreateDiskTimeout = 5 * time.Minute`
- `sshBootTimeout = 2 * time.Minute`

Uso:

- Operaciones rapidas: `runVBoxManage(...)`
- Operaciones pesadas (crear/clonar disco): `runVBoxManageWithTimeout(vboxCreateDiskTimeout, ...)`

## 8. Errores comunes y manejo aplicado

- `VERR_DISK_FULL`: espacio insuficiente en host.
  - Se muestra mensaje guiado para liberar espacio o mover ruta VirtualBox.
- `dynamic medium storage unit` al pasar a shareable:
  - Se hace fallback a clon Fixed y reintento.
- `VERR_ALREADY_EXISTS`:
  - Se limpia destino previo (closemedium/delete + remove archivo) antes de clonar.
- Falla SSH:
  - Se agrega espera con reintentos y mensajes orientados.

## 9. Comandos de desarrollo usados en el proyecto

- Formatear codigo Go:
  - `gofmt -w main.go`
- Compilar proyecto:
  - `go build ./...`
- Ejecutar servidor:
  - `go run .\main.go`

## 10. Relacion requisito -> implementacion

1. Gestion de plantillas base:
   - Formularios y handlers para registrar plantilla y generar llaves root.
2. Discos multiconexion:
   - Creacion (nuevo/plantilla), shareable, conexion, desconexion, eliminacion.
3. VMs de usuario:
   - Alta, baja, asignacion de disco, estado en dashboard.
4. Usuario Linux + llaves en VM de usuario:
   - Flujo SSH con validaciones de disco con SO.
5. Trazabilidad visual:
   - Dashboard refleja estado de llaves, discos, conexiones y acciones habilitadas.
