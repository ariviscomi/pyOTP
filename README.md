# pyOTP

Aplicación de escritorio para generar códigos OTP (TOTP/HOTP) desde una URI estándar `otpauth://…`, con almacenamiento cifrado, interfaz oscura minimalista y opción de permanecer en la bandeja del sistema.

---

## Características

- Soporta **TOTP** y **HOTP** a partir de una URI `otpauth://...`.
- **Almacenamiento cifrado** con Fernet + PBKDF2HMAC-SHA256 y salt aleatoria.
- Tema oscuro sobrio, tipografías modernas y **barra de progreso** para TOTP.
- Botón **Copiar** con aviso efímero **“¡Copiado!”**.
- Etiqueta de **versión** leída de la variable global `Version`.
- **Bandeja del sistema** con menú: Mostrar, Copiar código, Salir.
- **Check** “Permanecer en segundo plano”: al cerrar la ventana, se oculta a bandeja.
- Compatible con **PyInstaller**; usa ícono de ventana desde `assets/` y permite ícono del ejecutable.

---

## Requisitos

- Python **3.9+**
- Dependencias:

  ```bash
  pip install "pyotp>=2,<3" "cryptography>=42,<45" pystray pillow
  ```bash
  
  - `pyotp`: generación TOTP/HOTP
  - `cryptography`: cifrado Fernet y KDF PBKDF2
  - `pystray`: ícono y menú en bandeja
  - `pillow`: soporte de imágenes para la bandeja

---

## Estructura recomendada

``` structure
pyOTP/
├─ pyOTP.py
└─ assets/
   ├─ icon.ico          # recomendado (multi-res, incluir 256×256)
   ├─ icon.png          # alternativa cross-platform
   ├─ favicon.ico       # opcional
   └─ favicon.png       # opcional
```

> La app busca automáticamente `icon.ico`, `favicon.ico`, `icon.png` o `favicon.png` dentro de `assets/`. Si no existen, usa el primer `.ico` o `.png` disponible.  

---

## Configuración y almacenamiento

- **Directorio de configuración**:
  - Windows: `%APPDATA%/pyOTP-config/`
  - Linux/macOS: `~/.config/pyOTP-config/`
- **Archivo**: `config.ini`
- **Secciones**:
  - `[otp]`
    - `salt_b64`: salt aleatoria Base64.
    - `data_b64`: blob Fernet con:

      ```ini
      uri=<otpauth://...>
      hotp_counter=<N>
      ```

  - `[prefs]`
    - `tray_enabled`: `1` para permanecer en segundo plano, `0` para salir al cerrar ventana.

En Linux se intentan permisos `0600` sobre el archivo.

---

## Ejecución

### Opción A: contraseña por CLI

```bash
python pyOTP.py "MiContraseñaSegura"
```

### Opción B: solicitar en GUI

```bash
python pyOTP.py
```

La app pedirá la contraseña para abrir o crear el almacén.

### Primera ejecución

Si no existe `config.ini` o está vacío, la app pedirá **pegar la URI completa** `otpauth://…` y validará el formato.  
Para **HOTP**, se gestiona y persiste `hotp_counter`.

---

## Interfaz

- **Código OTP** grande en tipografía monoespaciada.
- **Progreso TOTP**: tiempo restante del período actual.
- **Información**:
  - TOTP: algoritmo, dígitos, período, segundos restantes.
  - HOTP: dígitos, contador actual.
- **Copiar**: copia el código al portapapeles y muestra “¡Copiado!”.
- **Cambiar URI**: reconfigura el secreto a partir de una nueva `otpauth://…`.
- **Permanecer en segundo plano**: si está activo, al cerrar la ventana la app se oculta en **bandeja**.
- **Versión**: se muestra `v<Version>` en la esquina inferior derecha.

---

## Bandeja del sistema

- Requiere `pystray` y `pillow`.
- Al cerrar la ventana con el **check activo**:
  - La app se oculta y continúa ejecutándose en bandeja.
  - Menú:
    - **Mostrar**: restaura la ventana.
    - **Copiar código**: copia el OTP actual al portapapeles.
    - **Salir**: finaliza el proceso.
- Si `pystray` no está instalado, el check se deshabilita y **cerrar ventana termina la app**.

---

## Compilación a .exe (PyInstaller)

### One-file sin consola, con ícono y assets

PowerShell:

```powershell
py -m PyInstaller pyOTP.py `
  --name OTP `
  --onefile `
  --noconsole `
  --icon assets\icon.ico `
  --add-data "assets;assets"
```

CMD:

```bat
py -m PyInstaller pyOTP.py --name OTP --onefile --noconsole --icon assets\icon.ico --add-data "assets;assets"
```

- Salida: `dist\OTP.exe`
- `--add-data "assets;assets"` incluye la carpeta `assets` en el bundle; la app la resuelve vía `_MEIPASS`.

### .spec con más control (opcional)

1) Generar base:

 ```powershell
 py -m PyInstaller pyOTP.py --name OTP --noconsole --onedir --icon assets\icon.ico --add-data "assets;assets" --specpath .
  ```

2) Ajustar `OTP.spec`:

```python
a = Analysis(
    ['pyOTP.py'],
    datas=[('assets', 'assets')],
    ...
)
exe = EXE(
    ...,
    name='OTP',
    icon='assets/icon.ico',
    console=False
)
```

3) Construir:

```powershell
py -m PyInstaller OTP.spec
```

**Requisitos del ícono**: usar `.ico` con múltiples tamaños e incluir **256×256** para que se vea nítido.

---

## Seguridad

- El secreto se cifra con **Fernet** usando clave derivada por **PBKDF2HMAC-SHA256** y **salt** aleatoria.
- Iteraciones altas para KDF. La contraseña maestra nunca se guarda en claro.
- Si la contraseña es incorrecta: *“Contraseña incorrecta o datos corruptos”*.

No compartas tu `config.ini` ni la `otpauth://…`.

---

## Variables y persistencia

- **`Version`**: variable global mostrada en la UI como `v<Version>`.

  ```python
  Version = "1.0.2"
  ```

- **Preferencia** en `config.ini`:
  - `[prefs] tray_enabled=1|0`

---

## Solución de problemas

- **No aparece el ícono de ventana**  
  Confirmar `assets/icon.ico` o `assets/icon.png`. En one-file, usar `--add-data "assets;assets"`.

- **No queda en bandeja**  
  Instalar `pystray` y `pillow`. Verificar que el check esté activo.

- **Ícono del ejecutable borroso**  
  Usar `.ico` con 256×256 real además de 16/24/32/48/64/128.

- **Fuentes no aplican**  
  Si ninguna de las familias sugeridas está instalada, se usa una genérica del sistema.

- **Clipboard en Linux/Wayland**  
  Puede requerir configuración adicional según la distro.

---

## Estándares y estilo

- Python 3.9+ con enfoque claro.
- UI concisa, textos en **es-AR** y mensajes neutrales.
- Sin logs sensibles; errores en `messagebox`.

---

## Contribución

1. Fork y rama: `feature/<nombre>`.
2. Estilo sugerido: `black` y `ruff`.
3. PR con descripción, pasos de prueba y, si aplica, capturas.

---

## Licencia

Definir antes de publicar. Sugerencia: **MIT** o **Apache-2.0**.

---

## Créditos

- OTP: `pyotp`
- Criptografía: `cryptography`
- Bandeja: `pystray`, `Pillow`
- GUI: `tkinter`

---

## Comandos útiles

```powershell
# Ejecutar pasando contraseña por CLI
python .\pyOTP.py "MiPass"

# Instalar dependencias
pip install "pyotp>=2,<3" "cryptography>=42,<45" pystray pillow

# Compilar .exe one-file con assets e ícono
py -m PyInstaller pyOTP.py --name OTP --onefile --noconsole --icon assets\icon.ico --add-data "assets;assets"
```
