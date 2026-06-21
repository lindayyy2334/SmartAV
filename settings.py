

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Répertoire racine du projet
ROOT_DIR = Path(__file__).parent.parent


class Settings:
    """
    Classe de configuration singleton.
    Gère tous les paramètres de l'application SmartAV.
    """

    # ─── Chemins ────────────────────────────────────────────
    ROOT_DIR: Path = ROOT_DIR
    CONFIG_DIR: Path = ROOT_DIR / "config"
    DATABASE_DIR: Path = ROOT_DIR / "database"
    LOGS_DIR: Path = ROOT_DIR / "logs"
    QUARANTINE_DIR: Path = ROOT_DIR / "quarantine"
    REPORTS_DIR: Path = ROOT_DIR / "reports"
    MODELS_DIR: Path = ROOT_DIR / "models"
    DATA_DIR: Path = ROOT_DIR / "data"

    # ─── Base de données ────────────────────────────────────
    DB_PATH: Path = ROOT_DIR / "database" / "smartav.db"

    # ─── Modèle ML ──────────────────────────────────────────
    MODEL_PATH: Path = ROOT_DIR / "models" / "smartav_model.joblib"
    SCALER_PATH: Path = ROOT_DIR / "models" / "scaler.joblib"
    DATASET_PATH: Path = ROOT_DIR / "data" / "dataset.csv"

    # ─── Scanner ────────────────────────────────────────────
    # Extensions considérées comme suspectes
    SUSPICIOUS_EXTENSIONS: List[str] = [
        ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".ps1", ".psm1", ".psd1", ".reg", ".inf",
        ".hta", ".cpl", ".msi", ".dll", ".sys", ".drv",
        ".lnk", ".jar", ".py", ".rb", ".sh", ".bin"
    ]

    # Extensions hautement risquées
    HIGH_RISK_EXTENSIONS: List[str] = [
        ".exe", ".bat", ".cmd", ".com", ".scr",
        ".vbs", ".ps1", ".hta", ".sys", ".dll"
    ]

    # Taille maximale de fichier à scanner (50 MB)
    MAX_FILE_SIZE_MB: int = 50
    MAX_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * 1024 * 1024

    # ─── Signatures malveillantes (hashes SHA-256) ──────────
    # En production, ces hashes proviendraient d'une base VirusTotal
    MALICIOUS_HASHES: List[str] = [
        # Exemples de hashes fictifs pour démonstration
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "d4f56e0a7c6b8d9e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
        "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe1",
    ]

    # Chaînes suspectes dans les fichiers (analyse heuristique)
    SUSPICIOUS_STRINGS: List[bytes] = [
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",  # Fichier test EICAR
        b"cmd.exe /c",
        b"powershell -enc",
        b"WScript.Shell",
        b"CreateObject",
        b"Shell.Application",
        b"HKEY_LOCAL_MACHINE\\SOFTWARE",
        b"net user /add",
        b"reg add",
    ]

    # ─── Monitoring ─────────────────────────────────────────
    MONITOR_INTERVAL_SECONDS: int = 5
    CPU_ALERT_THRESHOLD: float = 90.0      # % CPU
    MEMORY_ALERT_THRESHOLD: float = 85.0   # % RAM
    DISK_ALERT_THRESHOLD: float = 90.0     # % Disque

    # Processus légitimes à ignorer
    TRUSTED_PROCESSES: List[str] = [
        "System", "Registry", "smss.exe", "csrss.exe",
        "wininit.exe", "services.exe", "lsass.exe",
        "svchost.exe", "explorer.exe", "python.exe",
        "python3.exe", "code.exe"
    ]

    # ─── Quarantaine ────────────────────────────────────────
    QUARANTINE_ENCRYPTION_KEY: str = "SmartAV-Quarantine-Key-2024"

    # ─── Interface ──────────────────────────────────────────
    WINDOW_WIDTH: int = 1280
    WINDOW_HEIGHT: int = 800
    APP_THEME: str = "dark"

    # ─── Fichier de configuration utilisateur ───────────────
    USER_CONFIG_FILE: Path = CONFIG_DIR / "user_config.json"

    # Paramètres par défaut sauvegardables
    DEFAULT_USER_CONFIG: Dict[str, Any] = {
        "theme": "dark",
        "auto_quarantine": True,
        "real_time_monitoring": True,
        "scan_on_startup": False,
        "notification_enabled": True,
        "max_file_size_mb": 50,
        "excluded_paths": [],
        "ml_threshold": 0.7,
    }

    @classmethod
    def initialize_directories(cls) -> None:
        """Crée tous les répertoires nécessaires s'ils n'existent pas."""
        dirs = [
            cls.DATABASE_DIR,
            cls.LOGS_DIR,
            cls.QUARANTINE_DIR,
            cls.REPORTS_DIR,
            cls.MODELS_DIR,
            cls.DATA_DIR,
            cls.CONFIG_DIR,
        ]
        for directory in dirs:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Répertoire vérifié: {directory}")

    @classmethod
    def load_user_config(cls) -> Dict[str, Any]:
        """
        Charge la configuration utilisateur depuis le fichier JSON.

        Returns:
            Dictionnaire de configuration.
        """
        if cls.USER_CONFIG_FILE.exists():
            try:
                with open(cls.USER_CONFIG_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                # Fusionner avec les valeurs par défaut
                return {**cls.DEFAULT_USER_CONFIG, **config}
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Erreur lecture config: {e}. Utilisation des défauts.")
        return cls.DEFAULT_USER_CONFIG.copy()

    @classmethod
    def save_user_config(cls, config: Dict[str, Any]) -> bool:
        """
        Sauvegarde la configuration utilisateur.

        Args:
            config: Dictionnaire de configuration à sauvegarder.

        Returns:
            True si succès, False sinon.
        """
        try:
            cls.USER_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(cls.USER_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            logger.info("Configuration utilisateur sauvegardée.")
            return True
        except IOError as e:
            logger.error(f"Erreur sauvegarde config: {e}")
            return False

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """
        Récupère une valeur de configuration.

        Args:
            key: Clé de configuration.
            default: Valeur par défaut.

        Returns:
            Valeur de configuration.
        """
        config = cls.load_user_config()
        return config.get(key, default)
