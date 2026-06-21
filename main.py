
import sys
import logging
import argparse
from pathlib import Path
 
# Ajouter le répertoire racine au path Python
ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))
 
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
 
from config.settings import Settings
from config.logger import setup_logging
from database.db_manager import DatabaseManager
from gui.main_window import MainWindow
 
 
def parse_arguments() -> argparse.Namespace:
    """Parse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        prog="SmartAV",
        description="Antivirus Intelligent Avancé - Projet Académique",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python main.py                    # Lance l'interface graphique
  python main.py --scan /path/file  # Scan CLI d'un fichier
  python main.py --scan-dir /path   # Scan CLI d'un dossier
  python main.py --train-model      # Entraîne le modèle ML
        """
    )
    parser.add_argument(
        "--scan",
        metavar="FILE",
        help="Scanner un fichier en mode CLI"
    )
    parser.add_argument(
        "--scan-dir",
        metavar="DIR",
        help="Scanner un dossier récursivement en mode CLI"
    )
    parser.add_argument(
        "--train-model",
        action="store_true",
        help="Entraîner le modèle ML"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="SmartAV 1.0.0"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Activer le mode debug"
    )
    return parser.parse_args()
 
 
def run_cli_mode(args: argparse.Namespace) -> int:
    """
    Exécute SmartAV en mode ligne de commande.
 
    Args:
        args: Arguments parsés.
 
    Returns:
        Code de retour (0 = succès, 1 = erreur).
    """
    from scanner.file_scanner import FileScanner
    from scanner.dir_scanner import DirectoryScanner
    from ml.model_trainer import ModelTrainer
 
    logger = logging.getLogger(__name__)
 
    if args.train_model:
        logger.info("Entraînement du modèle ML...")
        trainer = ModelTrainer()
        trainer.train()
        print("✅ Modèle entraîné et sauvegardé avec succès.")
        return 0
 
    if args.scan:
        path = Path(args.scan)
        if not path.exists():
            print(f"❌ Fichier introuvable: {path}")
            return 1
        scanner = FileScanner()
        result = scanner.scan_file(path)
        print(f"\n{'='*50}")
        print(f"Résultat du scan: {path.name}")
        print(f"Statut: {'🔴 MALVEILLANT' if result.is_malicious else '🟢 SAIN'}")
        print(f"Score ML: {result.ml_score:.2f}")
        print(f"Signatures: {result.signature_matches}")
        print(f"{'='*50}\n")
        return 0
 
    if args.scan_dir:
        path = Path(args.scan_dir)
        if not path.exists():
            print(f"❌ Dossier introuvable: {path}")
            return 1
        scanner = DirectoryScanner()
        results = scanner.scan_directory(path)
        malicious = [r for r in results if r.is_malicious]
        print(f"\n{'='*50}")
        print(f"Scan terminé: {path}")
        print(f"Fichiers scannés: {len(results)}")
        print(f"Menaces détectées: {len(malicious)}")
        print(f"{'='*50}\n")
        return 0
 
    return 0
 
 
def run_gui_mode() -> int:
    """
    Lance l'interface graphique PyQt6.
 
    Returns:
        Code de retour de l'application.
    """
    # Activer le DPI haute résolution
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
 
    app = QApplication(sys.argv)
    app.setApplicationName("SmartAV")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("SmartAV Security")
 
    # Charger le style global
    _load_stylesheet(app)
 
    # Initialiser la base de données
    db = DatabaseManager()
    db.initialize()
 
    # Créer et afficher la fenêtre principale
    window = MainWindow()
    window.show()
 
    return app.exec()
 
 
def _load_stylesheet(app: QApplication) -> None:
    """Charge le fichier de style QSS."""
    style_path = ROOT_DIR / "gui" / "resources" / "style.qss"
    if style_path.exists():
        with open(style_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
 
 
def main() -> int:
    """Fonction principale."""
    args = parse_arguments()
 
    # Configurer le logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level)
 
    logger = logging.getLogger(__name__)
    logger.info("Démarrage de SmartAV v1.0.0")
 
    # Initialiser les répertoires nécessaires
    Settings.initialize_directories()
 
    # Mode CLI ou GUI
    if any([args.scan, args.scan_dir, args.train_model]):
        return run_cli_mode(args)
    else:
        return run_gui_mode()
 
 
if __name__ == "__main__":
    sys.exit(main())
 
