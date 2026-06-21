

import logging
import logging.handlers
from pathlib import Path
from typing import Optional


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[Path] = None
) -> None:
    """
    Configure le système de logging global de SmartAV.

    Args:
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Chemin vers le fichier de log (optionnel).
    """
    if log_file is None:
        from config.settings import Settings
        log_file = Settings.LOGS_DIR / "smartav.log"

    # S'assurer que le dossier logs existe
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Format détaillé pour fichier
    file_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Format simple pour console
    console_formatter = _ColorFormatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S"
    )

    # Handler fichier rotatif (10 MB max, 5 fichiers de backup)
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)

    # Handler console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(level)

    # Configuration du root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Réduire le bruit des librairies tierces
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)

    logging.getLogger(__name__).info(
        f"Logging initialisé. Fichier: {log_file} | Niveau console: {logging.getLevelName(level)}"
    )


class _ColorFormatter(logging.Formatter):
    """
    Formatter qui ajoute des couleurs ANSI pour la sortie console.
    """

    # Codes couleur ANSI
    COLORS = {
        "DEBUG":    "\033[36m",   # Cyan
        "INFO":     "\033[32m",   # Vert
        "WARNING":  "\033[33m",   # Jaune
        "ERROR":    "\033[31m",   # Rouge
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def format(self, record: logging.LogRecord) -> str:
        """Formate le message avec couleur selon le niveau."""
        color = self.COLORS.get(record.levelname, "")
        record.levelname = f"{color}{self.BOLD}{record.levelname}{self.RESET}"
        return super().format(record)
