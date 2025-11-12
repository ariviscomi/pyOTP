global cachorro_app
global Version
try:
    Version  # type: ignore
except NameError:
    Version = "1.1.0"

"""
OTP GUI con almacenamiento cifrado, tema oscuro y bandeja.
Dependencias:
  pip install "pyotp>=2,<3" "cryptography>=42,<45" pystray pillow
Compilación:
  py -m PyInstaller pyOTP.py --name OTP --onefile --noconsole --icon assets\icon.ico --add-data "assets;assets"
"""

import os, sys, time, stat, pathlib, base64, configparser, glob, threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import tkinter.font as tkfont
import pyotp

# Bandeja (opcional)
try:
    import pystray
    from PIL import Image as PILImage
    _TRAY_AVAILABLE = True
except Exception:
    _TRAY_AVAILABLE = False

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

APP_NAME = "pyOTP-config"
APP_TITLE = "OTP"

PALETTE = {
    "bg":      "#0E1116",
    "bg2":     "#151922",
    "fg":      "#E6E6E6",
    "muted":   "#A7AAB0",
    "accent":  "#4C8BF5",
    "accent2": "#0F5515",
    "border":  "#252A34",
    "warn":    "#F5A14C",
}

ASSETS_DIRNAME = "assets"
ICON_CANDIDATES = [
    ("ico", ("icon.ico", "favicon.ico")),
    ("png", ("icon.png", "favicon.png")),
]

def _bundle_path() -> pathlib.Path:
    if getattr(sys, "_MEIPASS", None):
        return pathlib.Path(sys._MEIPASS)  # PyInstaller
    return pathlib.Path(__file__).resolve().parent

def asset_path(*parts: str) -> pathlib.Path:
    return _bundle_path().joinpath(ASSETS_DIRNAME, *parts)

def find_icon_file() -> pathlib.Path | None:
    for _ext, names in ICON_CANDIDATES:
        for name in names:
            p = asset_path(name)
            if p.exists():
                return p
    any_ico = glob.glob(str(asset_path("*.ico")))
    if any_ico:
        return pathlib.Path(any_ico[0])
    any_png = glob.glob(str(asset_path("*.png")))
    if any_png:
        return pathlib.Path(any_png[0])
    return None

def choose_font(candidates, size=10, weight="normal"):
    families = set(tkfont.families())
    for name in candidates:
        if name in families:
            return tkfont.Font(family=name, size=size, weight=weight)
    return tkfont.Font(family="Segoe UI" if os.name == "nt" else "Sans", size=size, weight=weight)

def cfg_dir() -> pathlib.Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(pathlib.Path.home() / "AppData" / "Roaming")
        return pathlib.Path(base) / APP_NAME
    return pathlib.Path.home() / ".config" / APP_NAME

CFG_DIR = cfg_dir()
CFG_FILE = CFG_DIR / "config.ini"
SECTION = "otp"
KEY_SALT = "salt_b64"
KEY_DATA = "data_b64"
SECTION_PREFS = "prefs"
KEY_TRAY_ENABLED = "tray_enabled"

def ensure_cfg_dir():
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(CFG_DIR, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except Exception:
            pass

def pbkdf2(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

class SecureStore:
    def __init__(self, cfg: "configparser.RawConfigParser"):
        self.cfg = cfg
        self.uri = ""
        self.hotp_counter = 0

    @staticmethod
    def _serialize(uri: str, hotp_counter: int) -> bytes:
        return f"uri={uri}\nhotp_counter={hotp_counter}\n".encode("utf-8")

    @staticmethod
    def _deserialize(data: bytes):
        text = data.decode("utf-8")
        uri, hotp = "", 0
        for line in text.splitlines():
            if line.startswith("uri="):
                uri = line[4:]
            elif line.startswith("hotp_counter="):
                try:
                    hotp = int(line[len("hotp_counter="):])
                except ValueError:
                    hotp = 0
        return uri, hotp

    def load(self, password: str) -> bool:
        if not self.cfg.has_section(SECTION):
            return False
        salt_b64 = self.cfg.get(SECTION, KEY_SALT, fallback="")
        data_b64 = self.cfg.get(SECTION, KEY_DATA, fallback="")
        if not salt_b64 or not data_b64:
            return False
        try:
            salt = base64.b64decode(salt_b64)
            key = pbkdf2(password, salt)
            blob = Fernet(key).decrypt(base64.b64decode(data_b64))
            self.uri, self.hotp_counter = self._deserialize(blob)
            return True
        except InvalidToken:
            raise InvalidToken("Contraseña incorrecta o datos corruptos")
        except Exception as e:
            raise e

    def save(self, password: str):
        if not self.cfg.has_section(SECTION):
            self.cfg.add_section(SECTION)
        salt = os.urandom(16)
        key = pbkdf2(password, salt)
        enc = Fernet(key).encrypt(self._serialize(self.uri, self.hotp_counter))
        self.cfg.set(SECTION, KEY_SALT, base64.b64encode(salt).decode("ascii"))
        self.cfg.set(SECTION, KEY_DATA, base64.b64encode(enc).decode("ascii"))
        ensure_cfg_dir()
        with open(CFG_FILE, "w", encoding="utf-8") as fh:
            self.cfg.write(fh)
        if os.name != "nt":
            try:
                os.chmod(CFG_FILE, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass

class OTPApp(tk.Tk):
    def __init__(self, cli_password: str | None):
        super().__init__()
        self.title(APP_TITLE)

        # Ícono de ventana
        self._icon_img = None
        self._apply_window_icon()

        self.resizable(False, False)
        self.configure(bg=PALETTE["bg"])
        self._apply_dark_theme()

        # Tipografías
        self.font_ui = choose_font(["Segoe UI Variable", "Segoe UI", "Inter", "Roboto", "SF Pro Text"], size=10)
        self.font_code = choose_font(["JetBrains Mono", "Consolas", "Cascadia Mono", "Fira Code", "Courier New"], size=36, weight="bold")
        self.option_add("*Font", self.font_ui)

        # Variables
        self.code_var = tk.StringVar(value="------")
        self.info_var = tk.StringVar(value="")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.copied_var = tk.StringVar(value="")
        self.tray_enabled_var = tk.BooleanVar(value=True)
        self._copied_job = None

        # Estado de bandeja
        self._tray_icon = None
        self._tray_thread = None
        self._tray_supported = _TRAY_AVAILABLE

        # Config
        self.cfg = configparser.RawConfigParser()
        if CFG_FILE.exists():
            self.cfg.read(CFG_FILE, encoding="utf-8")
        self._load_prefs()

        # Layout
        frm = ttk.Frame(self, padding=12, style="Card.TFrame")
        frm.grid(row=0, column=0, sticky="nsew")

        self.lbl_code = ttk.Label(frm, textvariable=self.code_var, style="Code.TLabel")
        self.lbl_code.configure(font=self.font_code)
        self.lbl_code.grid(row=0, column=0, columnspan=3, pady=(0, 10))

        self.progress = ttk.Progressbar(frm, variable=self.progress_var, maximum=100, length=340, style="Accent.Horizontal.TProgressbar")
        self.progress.grid(row=1, column=0, columnspan=3, sticky="ew")

        self.lbl_info = ttk.Label(frm, textvariable=self.info_var, style="Muted.TLabel")
        self.lbl_info.grid(row=2, column=0, columnspan=3, pady=(6, 6))

        # Controles
        self.btn_copy = ttk.Button(frm, text="Copiar", command=self.copy_code, style="TButton")
        self.btn_copy.grid(row=3, column=0, padx=(0, 8))

        self.lbl_copied = ttk.Label(frm, textvariable=self.copied_var, style="Copied.TLabel")
        self.lbl_copied.grid(row=3, column=1, padx=4)

        self.btn_change = ttk.Button(frm, text="Cambiar URI", command=self.change_uri, style="TButton")
        self.btn_change.grid(row=3, column=2)

        self.chk_tray = ttk.Checkbutton(frm, text="Permanecer en segundo plano", variable=self.tray_enabled_var, command=self._save_prefs)
        self.chk_tray.grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 2))

        # Versión
        self.lbl_version = ttk.Label(frm, text=f"v{Version}", style="Muted.TLabel")
        self.lbl_version.grid(row=5, column=0, columnspan=3, sticky="e")

        # Menú
        menubar = tk.Menu(self, tearoff=0, background=PALETTE["bg2"], foreground=PALETTE["fg"],
                          activeforeground=PALETTE["fg"], activebackground=PALETTE["accent"])
        cfg_menu = tk.Menu(menubar, tearoff=0, background=PALETTE["bg2"], foreground=PALETTE["fg"],
                           activeforeground=PALETTE["fg"], activebackground=PALETTE["accent"])
        cfg_menu.add_command(label="Cambiar URI", command=self.change_uri)
        cfg_menu.add_separator()
        cfg_menu.add_command(label="Salir", command=self._quit_app)
        menubar.add_cascade(label="Config", menu=cfg_menu)
        self.config(menu=menubar)

        # Atajos
        self.bind_all("<Control-c>", lambda e: self.copy_code())

        # Cerrar ventana
        self.protocol("WM_DELETE_WINDOW", self._on_close_window)

        # Password
        self.password = cli_password or ""
        if not self.password:
            self.password = self._prompt_password("Ingresá la contraseña para abrir o crear el almacén:")

        # Store
        self.store = SecureStore(self.cfg)
        if not self._load_or_init_store():
            return

        # OTP listo
        self._build_otp()

        # Centro y loop
        self.after(10, self._center_on_screen)
        self.after(100, self.update_loop)

        # Si no hay bandeja, deshabilito check
        if not self._tray_supported:
            try:
                self.chk_tray.state(["disabled"])
                self.chk_tray.configure(text="Permanecer en segundo plano (no disponible)")
            except Exception:
                pass

    # Estilo
    def _apply_dark_theme(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=PALETTE["bg2"], foreground=PALETTE["fg"])
        self.configure(bg=PALETTE["bg"])
        style.configure("Card.TFrame", background=PALETTE["bg2"], borderwidth=1, relief="solid")
        style.configure("TLabel", background=PALETTE["bg2"], foreground=PALETTE["fg"])
        style.configure("Muted.TLabel", background=PALETTE["bg2"], foreground=PALETTE["muted"])
        style.configure("Code.TLabel", background=PALETTE["bg2"], foreground=PALETTE["fg"])
        style.configure("Copied.TLabel", background=PALETTE["bg2"], foreground=PALETTE["warn"])
        style.configure("TButton", background=PALETTE["bg2"], foreground=PALETTE["fg"],
                        bordercolor=PALETTE["border"], focusthickness=2, focuscolor=PALETTE["accent"])
        style.map("TButton", background=[("active", PALETTE["accent2"]), ("pressed", PALETTE["accent"])],
                  foreground=[("active", PALETTE["fg"])])
        style.configure("Accent.Horizontal.TProgressbar", troughcolor=PALETTE["bg"],
                        background=PALETTE["accent"], bordercolor=PALETTE["border"])

    # Ícono
    def _apply_window_icon(self):
        icon_file = find_icon_file()
        if not icon_file:
            return
        try:
            if os.name == "nt" and icon_file.suffix.lower() == ".ico":
                self.iconbitmap(default=str(icon_file))
            else:
                self._icon_img = tk.PhotoImage(file=str(icon_file))
                self.iconphoto(True, self._icon_img)
        except Exception:
            try:
                self._icon_img = tk.PhotoImage(file=str(icon_file))
                self.iconphoto(True, self._icon_img)
            except Exception:
                pass

    # Centrar
    def _center_on_screen(self):
        try:
            self.update_idletasks()
            w, h = self.winfo_width(), self.winfo_height()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            x = int((sw - w) / 2)
            y = int((sh - h) / 3)
            self.geometry(f"+{x}+{y}")
        except Exception:
            pass

    # Prefs
    def _load_prefs(self):
        if self.cfg.has_section(SECTION_PREFS):
            v = self.cfg.get(SECTION_PREFS, KEY_TRAY_ENABLED, fallback="1")
            self.tray_enabled_var.set(v.strip() != "0")
        else:
            self.tray_enabled_var.set(True)

    def _save_prefs(self):
        if not self.cfg.has_section(SECTION_PREFS):
            self.cfg.add_section(SECTION_PREFS)
        self.cfg.set(SECTION_PREFS, KEY_TRAY_ENABLED, "1" if self.tray_enabled_var.get() else "0")
        ensure_cfg_dir()
        with open(CFG_FILE, "w", encoding="utf-8") as fh:
            self.cfg.write(fh)

    # Cerrar ventana -> ocultar a bandeja si corresponde
    def _on_close_window(self):
        if self._tray_supported and self.tray_enabled_var.get():
            self.withdraw()
            self._ensure_tray_running()
        else:
            self._quit_app()

    # Bandeja
    def _get_tray_image(self):
        icon_file = find_icon_file()
        if icon_file and icon_file.exists():
            try:
                return PILImage.open(str(icon_file))
            except Exception:
                pass
        return PILImage.new("RGBA", (64, 64), (76, 139, 245, 255))

    def _ensure_tray_running(self):
        if self._tray_icon is not None or not self._tray_supported:
            return
        menu = pystray.Menu(
            pystray.MenuItem("Mostrar", self._tray_show_cb),
            pystray.MenuItem("Copiar código", self._tray_copy_cb),
            pystray.MenuItem("Salir", self._tray_quit_cb),
        )
        self._tray_icon = pystray.Icon(APP_TITLE, self._get_tray_image(), APP_TITLE, menu)

        def run_tray():
            try:
                self._tray_icon.run()
            except Exception:
                pass

        self._tray_thread = threading.Thread(target=run_tray, daemon=True)
        self._tray_thread.start()

    def _tray_show_cb(self, icon, item):
        self.after(0, self._show_window)

    def _tray_copy_cb(self, icon, item):
        self.after(0, self.copy_code)

    def _tray_quit_cb(self, icon, item):
        self.after(0, self._quit_app)

    def _show_window(self):
        try:
            self.deiconify()
            self.after(50, self.lift)
            self.after(50, self.focus_force)
        except Exception:
            pass

    def _stop_tray(self):
        if self._tray_icon is not None:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
            self._tray_icon = None
            self._tray_thread = None

    # Acciones
    def change_uri(self):
        new_uri = self._prompt_uri()
        if not new_uri:
            return
        try:
            pyotp.parse_uri(new_uri)
        except Exception as e:
            messagebox.showerror("URI inválida", f"No se pudo parsear la URI:\n{e}")
            return
        self.store.uri = new_uri
        self.store.hotp_counter = 0
        self.store.save(self.password)
        self._build_otp()

    def copy_code(self):
        code = self.code_var.get()
        if code and code != "------":
            self.clipboard_clear()
            self.clipboard_append(code)
            self._show_copied()

    def _show_copied(self):
        if hasattr(self, "_copied_job") and self._copied_job is not None:
            try:
                self.after_cancel(self._copied_job)
            except Exception:
                pass
        self.copied_var.set("¡Copiado!")
        self._copied_job = self.after(1200, lambda: self.copied_var.set(""))

    def advance_hotp(self):
        if not getattr(self, "is_hotp", False):
            return
        try:
            code = self.otp_obj.at(self.store.hotp_counter)
        except Exception as e:
            messagebox.showerror("Error HOTP", str(e))
            return
        self.code_var.set(code)
        self.info_var.set(f"HOTP  dígitos={self.otp_obj.digits}  counter={self.store.hotp_counter}")
        self.store.hotp_counter += 1
        self.store.save(self.password)

    # Loop
    def update_loop(self):
        self.update_display()
        self.after(200, self.update_loop)

    def update_display(self, force: bool = False):
        if not hasattr(self, "otp_obj"):
            return
        if self.is_totp:
            interval = getattr(self.otp_obj, "interval", 30)
            now = int(time.time())
            left = interval - (now % interval)
            prog = int(100 * (interval - left) / interval)
            self.progress_var.set(prog)

            if force or (now % interval == 0) or (left == interval) or (self.code_var.get() == "------"):
                try:
                    code = self.otp_obj.now()
                except Exception as e:
                    messagebox.showerror("Error TOTP", str(e))
                    return
                self.code_var.set(code)

            algo = self.otp_obj.digest().name.upper()
            self.info_var.set(f"TOTP  alg={algo}  dígitos={self.otp_obj.digits}  período={interval}s  expira_en={left}s")
        elif self.is_hotp:
            self.progress_var.set(0)
            if self.code_var.get() == "------":
                self.advance_hotp()
        else:
            self.progress_var.set(0)
            self.info_var.set("Tipo OTP no soportado")

    # OTP
    def _build_otp(self):
        try:
            obj = pyotp.parse_uri(self.store.uri)
        except Exception as e:
            messagebox.showerror("Error", f"URI inválida: {e}")
            self.after(50, self.destroy)
            return
        self.otp_obj = obj
        self.is_totp = isinstance(obj, pyotp.TOTP)
        self.is_hotp = isinstance(obj, pyotp.HOTP)
        self.update_display(force=True)

    # Prompts
    def _prompt_password(self, prompt: str) -> str:
        pw = simpledialog.askstring("Contraseña", prompt, parent=self, show="*")
        return pw or ""

    def _prompt_uri(self) -> str:
        return simpledialog.askstring("Configurar URI OTP", "Pegá la URI completa (otpauth://…):", parent=self)

    # Store init
    def _load_or_init_store(self) -> bool:
        try:
            loaded = False
            if CFG_FILE.exists():
                try:
                    loaded = self.store.load(self.password)
                except InvalidToken:
                    self.password = self._prompt_password("Contraseña incorrecta. Probá de nuevo:")
                    loaded = self.store.load(self.password)
            if not loaded:
                uri = self._prompt_uri()
                if not uri:
                    messagebox.showerror("Error", "No se configuró la URI.")
                    self.after(50, self.destroy); return False
                try:
                    pyotp.parse_uri(uri)
                except Exception as e:
                    messagebox.showerror("URI inválida", f"No se pudo parsear la URI:\n{e}")
                    self.after(50, self.destroy); return False
                self.store.uri = uri
                self.store.hotp_counter = 0
                self.store.save(self.password)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir el almacén: {e}")
            self.after(50, self.destroy)
            return False

    # Terminar proceso
    def _quit_app(self):
        self._stop_tray()
        self.destroy()

def main():
    cli_password = sys.argv[1] if len(sys.argv) > 1 else None
    ensure_cfg_dir()
    app = OTPApp(cli_password)
    app.mainloop()

if __name__ == "__main__":
    main()

cachorro_app = True