# Gestión de Servicios (Fase 2)

## 1. Objetivo del módulo

El módulo de **Gestión de Servicios** automatiza el despliegue de una aplicación Linux en una máquina virtual y su control mediante **systemd**.

El flujo principal permite:

1. Seleccionar una VM de usuario ya configurada con llave.
2. Subir un archivo `.zip` con la aplicación.
3. Extraer la aplicación en una carpeta destino dentro de la VM.
4. Crear/instalar un archivo `.service` en systemd.
5. Controlar el servicio desde el dashboard (`start`, `stop`, `restart`, `enable`, `disable`, `status`).
6. Visualizar estado del servicio y últimas líneas del archivo incremental de ejecución.

---

## 2. Requisitos previos

Antes de usar este módulo debes tener:

1. VM de usuario creada desde el módulo anterior.
2. Usuario `usuario_mv` y llave SSH generados para esa VM.
3. SSH activo en la VM.
4. Acceso root por contraseña disponible en la VM (para instalar/gestionar systemd).
5. Disco multiconexión ya asociado a la VM (si aplica a tu flujo).

---

## 3. Flujo funcional de despliegue

### Paso 1. Preparación de conexión SSH

El backend configura una regla NAT Port Forwarding temporal y enciende la VM en modo headless si está apagada.

### Paso 2. Carga del ZIP

Se recibe el `.zip` desde el formulario web (multipart/form-data), se valida y se sube por SSH a `/tmp`.

### Paso 3. Descompresión en destino

Se crea la carpeta destino y se descomprime el contenido del ZIP con `unzip -o`.

### Paso 4. Generación de script de ejecución

El backend crea un script `run_<servicio>.sh` que:

1. Cambia al `WorkingDirectory`.
2. Incrementa un contador en un archivo de log.
3. Agrega una línea con número incremental y timestamp.
4. Ejecuta el comando real de inicio de la app.

### Paso 5. Instalación del servicio systemd

El backend sube el archivo `.service` a `/tmp`, lo instala en `/etc/systemd/system/`, ejecuta `daemon-reload` y consulta estado.

### Paso 6. Dashboard de control

Desde la GUI puedes:

1. Iniciar (`start`).
2. Detener (`stop`).
3. Reiniciar (`restart`).
4. Habilitar en arranque (`enable`).
5. Deshabilitar en arranque (`disable`).
6. Actualizar estado (`status`) y refrescar tail del archivo incremental.

---

## 4. Comandos utilizados

## 4.1 Comandos VirtualBox (host)

- `VBoxManage modifyvm <vm> --natpf1 delete <regla>`
- `VBoxManage modifyvm <vm> --natpf1 <regla>,tcp,127.0.0.1,<puerto>,,22`
- `VBoxManage startvm <vm> --type headless`

## 4.2 Comandos remotos en VM (SSH)

### Despliegue ZIP

- `cat > /tmp/<archivo>.zip` (subida remota de bytes)
- `mkdir -p <destino> && unzip -o /tmp/<archivo>.zip -d <destino>`

### Preparación de script de ejecución

- `cat > <destino>/run_<servicio>.sh`
- `chmod +x <destino>/run_<servicio>.sh`

### Instalación systemd (root)

- `install -m 644 /tmp/<servicio>.service /etc/systemd/system/<servicio>.service`
- `systemctl daemon-reload`

### Gestión del servicio

- `systemctl start <servicio>.service`
- `systemctl stop <servicio>.service`
- `systemctl restart <servicio>.service`
- `systemctl enable <servicio>.service`
- `systemctl disable <servicio>.service`
- `systemctl is-active <servicio>.service`
- `systemctl is-enabled <servicio>.service`

### Consulta de trazas de ejecución

- `tail -n 20 <destino>/<archivo_contador>`

---

## 5. Estructura recomendada del archivo ZIP

El backend descomprime exactamente lo que reciba en la carpeta destino y ejecuta el comando que indiques en la GUI. Por eso, el ZIP debe ser coherente con ese comando.

## 5.1 Recomendación general

1. Evita rutas absolutas dentro del ZIP.
2. Incluye todos los archivos necesarios para arrancar la app.
3. Define un comando de inicio compatible con lo contenido en el ZIP.
4. Prueba localmente en Linux el mismo comando antes de subir.

## 5.2 Ejemplo para app Python

Contenido del ZIP:

- `main.py`
- `requirements.txt`
- `src/...` (si aplica)

Comando de inicio en GUI:

- `python3 main.py`

## 5.3 Ejemplo para binario Go

Contenido del ZIP:

- `miapp` (binario Linux con permisos de ejecución)
- `config.yaml` (si aplica)

Comando de inicio en GUI:

- `./miapp`

## 5.4 Ejemplo para script Bash

Contenido del ZIP:

- `run_app.sh`
- archivos auxiliares

Comando de inicio en GUI:

- `bash run_app.sh`

---

## 6. Formato del archivo incremental

En cada ejecución del servicio se agrega una línea con formato:

- `N - YYYY-MM-DD HH:MM:SS`

Ejemplo:

- `1 - 2026-04-13 10:00:01`
- `2 - 2026-04-13 10:01:15`
- `3 - 2026-04-13 10:01:20`

El nombre del archivo lo defines en la GUI (`counter_file`), por defecto: `app_runs.log`.

---

## 7. Validaciones y controles de GUI

El módulo valida en backend:

1. VM seleccionada válida.
2. Llave de usuario existente para esa VM.
3. Archivo ZIP presente y no vacío.
4. Parámetros requeridos (`service_name`, `destination_path`, `start_command`).

En la GUI, el dashboard muestra:

1. Estado (`is-active`).
2. Habilitado (`is-enabled`).
3. Última revisión.
4. Últimas líneas del archivo incremental.

---

## 8. Errores comunes

1. **El servicio no inicia**: comando de inicio incorrecto o dependencias faltantes en la VM.
2. **No hay salida en tail**: la app no alcanzó a ejecutar la línea incremental.
3. **Error al instalar servicio**: falta de permisos root o nombre de servicio inválido.
4. **Fallo SSH**: regla NAT no configurada correctamente o SSH no disponible en la VM.

---

## 9. Resumen técnico

Este módulo integra VirtualBox + SSH + systemd para automatizar despliegue y operación de aplicaciones Linux desde una interfaz web en Go, manteniendo trazabilidad por logs, control de estado en dashboard y operación sin interacción manual dentro de la VM.
