# Explicacion del Simulador de Carga (stress-ng)

## 1. Que significa "workers" en el simulador

En el simulador, el campo **workers** indica cuántos procesos de carga de CPU va a lanzar `stress-ng` al mismo tiempo.

- Si pones `workers = 1`, solo hay 1 proceso presionando CPU.
- Si pones `workers = 2`, hay 2 procesos concurrentes.
- Si pones `workers = 4`, hay 4 procesos concurrentes.

En terminos simples: **mas workers = mas hilos/procesos trabajando a la vez = mas presion total sobre CPU** (en general).

### Recomendacion practica

- Para pruebas suaves: `1` o `2` workers.
- Para pruebas medias: `2` a `4` workers.
- Para pruebas agresivas: `4+` workers (dependiendo de la capacidad de la VM).

> Nota: El impacto real tambien depende de cuántos vCPU tenga la VM.

---

## 2. Por que hay dos tipos de prueba

En el modulo se dejaron **dos pruebas distintas** porque responden a objetivos diferentes:

### A) Simular carga unica

Esta prueba aplica una sola carga constante durante un tiempo definido.

Parametros principales:

- `cpu_load`: porcentaje objetivo (ejemplo: 70)
- `workers`: procesos concurrentes
- `duration_seconds`: duracion total

Ejemplo:

- `cpu_load = 70`, `workers = 2`, `duration = 60s`
- Resultado esperado: CPU estable alrededor de un nivel medio/alto durante 1 minuto.

#### Cuándo usarla

- Cuando quieres validar una condicion puntual.
- Cuando quieres comprobar si el autoscaling reacciona ante una carga sostenida especifica.
- Cuando necesitas pruebas rapidas y controladas.

---

### B) Simular perfil de carga

Esta prueba ejecuta varios niveles de carga en secuencia (escalonados), por ejemplo: `25,60,90`.

Parametros principales:

- `profile_levels`: lista de niveles de carga
- `workers`: procesos concurrentes
- `duration_seconds`: tiempo por cada nivel

Ejemplo:

- `profile_levels = 25,60,90`
- `workers = 2`
- `duration_seconds = 45`

Flujo real:

1. 45s al 25%
2. 45s al 60%
3. 45s al 90%

#### Cuándo usarla

- Cuando quieres simular una carga mas realista (sube por etapas).
- Cuando quieres verificar el comportamiento alrededor de los umbrales bajo/alto.
- Cuando quieres observar estabilidad del algoritmo de autoscaling (evitar escalados falsos por picos cortos).

---

## 3. Diferencia clave entre ambas pruebas

- **Carga unica**: 1 sola intensidad durante toda la prueba.
- **Perfil de carga**: varias intensidades en secuencia.

Si tu objetivo es validar "si escala o no escala" ante un punto fijo, usa **carga unica**.
Si tu objetivo es validar "como se comporta en una curva de demanda", usa **perfil de carga**.

---

## 4. Relacion con umbrales del balanceador

Tus umbrales (alto/bajo) y tiempos de sostenimiento (`SustainSeconds`) se validan mejor asi:

1. Prueba 1 (carga unica media): confirma que no escale de forma prematura.
2. Prueba 2 (carga unica alta): confirma scale out al sostener carga sobre umbral alto.
3. Prueba 3 (perfil de carga): confirma transiciones (bajo -> medio -> alto) y comportamiento de regreso.

---

## 5. Buenas practicas para resultados consistentes

- Iniciar con pocos workers e ir subiendo.
- No usar duraciones demasiado cortas si quieres activar reglas de sostenimiento.
- Revisar CPU promedio y ultima accion automatica en la GUI del modulo de balanceadores.
- Ejecutar pruebas con una sola fuente de carga al inicio (una VM objetivo), luego ampliar.

---

## 6. Resumen rapido

- **Workers**: cuántos procesos de carga se ejecutan en paralelo.
- **Carga unica**: prueba puntual y estable.
- **Perfil de carga**: prueba por etapas para validar respuesta dinamica del autoscaling.
