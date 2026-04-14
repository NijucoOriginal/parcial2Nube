# Guía práctica: aplicación básica para Gestión de Servicios

Esta guía te deja una aplicación mínima lista para probar el módulo de **Gestión de Servicios** de tu proyecto (subida ZIP + instalación como servicio `systemd`).

## 1. Objetivo

Construir una app web básica en Python (Flask) que:

- responda en un puerto HTTP,
- registre cada inicio en un archivo,
- se pueda empaquetar en `.zip`,
- se despliegue con el formulario de tu dashboard.

## 2. Estructura de archivos recomendada

Crea una carpeta local llamada `demo_servicio_flask` con esta estructura:

```text
/demo_servicio_flask
  app.py
  requirements.txt
  README.md
```

## 3. Código de ejemplo

### Archivo: `app.py`

```python
from flask import Flask
from datetime import datetime
import os

app = Flask(__name__)

@app.route("/")
def home():
    return {
        "ok": True,
        "mensaje": "Servicio Flask activo",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

@app.route("/health")
def health():
    return "healthy", 200

if __name__ == "__main__":
    # Usa PORT si existe (útil para cambiar puerto fácilmente)
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
```

### Archivo: `requirements.txt`

```txt
flask==3.0.3
```

### Archivo: `README.md`

```md
# Demo Servicio Flask

Aplicación mínima para desplegar por ZIP y ejecutar con systemd.

## Ejecución local

python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## 4. Empaquetar en ZIP

Ubícate en la carpeta padre de `demo_servicio_flask` y comprime su contenido.

### PowerShell (Windows)

```powershell
Compress-Archive -Path .\demo_servicio_flask\* -DestinationPath .\demo_servicio_flask.zip -Force
```

## 5. Valores sugeridos en tu formulario de despliegue

En el módulo **Gestión de Servicios** usa estos valores:

- **Máquina virtual destino**: una MV con llave de usuario ya generada.
- **Nombre de servicio**: `demo-flask.service`
- **Carpeta destino en la VM**: `/home/usuario_mv/demo_flask`
- **Comando de inicio**: `python3 app.py`
- **Archivo de trazas incrementales**: `app_runs.log`
- **Archivo ZIP**: `demo_servicio_flask.zip`

## 6. Nota importante sobre dependencias

Tu backend descomprime y ejecuta, pero **no instala dependencias automáticamente** por ahora.

Para Flask, primero instala en la VM (una sola vez):

```bash
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install -r /home/usuario_mv/demo_flask/requirements.txt
```

Si quieres evitar instalación manual, puedes enviar una app que use solo librería estándar de Python.

## 7. Verificación rápida después del despliegue

1. En el dashboard, usa acción **Iniciar** sobre `demo-flask.service`.
2. Pulsa **Actualizar estado** y confirma `active`.
3. Revisa el endpoint publicado automático que ahora muestra el dashboard (ejemplo: `http://127.0.0.1:52xxx`).
4. Abre ese endpoint en navegador y valida respuesta JSON.

## 8. Variante sin dependencias externas (opcional)

Si no quieres Flask, aquí tienes una opción solo con Python estándar.

### Reemplazo de `app.py` (sin `requirements.txt`)

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ["/", "/health"]:
            payload = {
                "ok": True,
                "path": self.path,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("Servidor básico activo en puerto 8080")
    server.serve_forever()
```

Y en el formulario usa:

- **Comando de inicio**: `python3 app.py`
- (La detección automática de puerto en tu backend usará `8080` por defecto en este caso)

---

Con esta guía ya tienes un ejemplo funcional para validar extremo a extremo: ZIP -> despliegue -> systemd -> estado -> endpoint con NAT automático.
