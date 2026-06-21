

import sqlite3
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple

from config.settings import Settings

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Gestionnaire SQLite singleton pour SmartAV.

    Utilise un verrou threading pour la sécurité des accès concurrents.
    Fournit toutes les opérations CRUD sur les tables SmartAV.
    """

    _instance: Optional["DatabaseManager"] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "DatabaseManager":
        """Implémentation du pattern Singleton thread-safe."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._db_path: Path = Settings.DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._thread_local = threading.local()
        self._initialized = True
        logger.info(f"DatabaseManager initialisé: {self._db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """
        Retourne une connexion SQLite thread-locale.
        Crée une nouvelle connexion si nécessaire.
        """
        if not hasattr(self._thread_local, "conn") or self._thread_local.conn is None:
            self._thread_local.conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
                timeout=30.0
            )
            self._thread_local.conn.row_factory = sqlite3.Row
            # Activer les clés étrangères et WAL mode pour performance
            self._thread_local.conn.execute("PRAGMA foreign_keys = ON")
            self._thread_local.conn.execute("PRAGMA journal_mode = WAL")
            self._thread_local.conn.execute("PRAGMA synchronous = NORMAL")
        return self._thread_local.conn

    def initialize(self) -> None:
        """
        Initialise la base de données en créant toutes les tables nécessaires.
        Appelé au démarrage de l'application.
        """
        logger.info("Initialisation de la base de données...")
        conn = self._get_connection()
        try:
            self._create_tables(conn)
            conn.commit()
            logger.info("Base de données initialisée avec succès.")
        except sqlite3.Error as e:
            logger.error(f"Erreur initialisation DB: {e}")
            conn.rollback()
            raise

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        """Crée toutes les tables du schéma SmartAV."""

        # Table des scans effectués
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,           -- 'quick', 'full', 'file', 'realtime'
                target_path TEXT NOT NULL,
                started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                finished_at TIMESTAMP,
                total_files INTEGER DEFAULT 0,
                infected_files INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running',     -- 'running', 'completed', 'aborted'
                duration_seconds REAL DEFAULT 0.0
            )
        """)

        # Table des résultats de scan par fichier
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                file_extension TEXT,
                sha256_hash TEXT,
                is_malicious INTEGER DEFAULT 0,    -- 0 = sain, 1 = malveillant
                threat_level TEXT DEFAULT 'none',  -- 'none', 'low', 'medium', 'high', 'critical'
                detection_method TEXT,             -- 'signature', 'ml', 'heuristic', 'extension'
                ml_score REAL DEFAULT 0.0,
                threat_name TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        # Table de quarantaine
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                sha256_hash TEXT,
                threat_name TEXT,
                threat_level TEXT DEFAULT 'high',
                quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_restored INTEGER DEFAULT 0,
                restored_at TIMESTAMP,
                is_deleted INTEGER DEFAULT 0
            )
        """)

        # Table des alertes de monitoring
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,          -- 'process', 'file', 'network', 'system'
                severity TEXT NOT NULL,            -- 'info', 'warning', 'danger', 'critical'
                title TEXT NOT NULL,
                description TEXT,
                process_name TEXT,
                process_pid INTEGER,
                file_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_acknowledged INTEGER DEFAULT 0
            )
        """)

        # Table des rapports générés
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,
                report_path TEXT NOT NULL,
                scan_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)

        # Table de configuration persistante
        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Index pour les performances
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_malicious ON scan_results(is_malicious)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_hash ON scan_results(sha256_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON quarantine(sha256_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_monitoring_created ON monitoring_alerts(created_at)")

        logger.debug("Toutes les tables créées/vérifiées.")

    # ─── Méthodes Scans ─────────────────────────────────────────────────────

    def create_scan(self, scan_type: str, target_path: str) -> int:
        """
        Crée un nouvel enregistrement de scan.

        Args:
            scan_type: Type de scan ('quick', 'full', 'file', 'realtime').
            target_path: Chemin cible du scan.

        Returns:
            ID du scan créé.
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "INSERT INTO scans (scan_type, target_path, started_at) VALUES (?, ?, ?)",
                (scan_type, target_path, datetime.now().isoformat())
            )
            conn.commit()
            scan_id = cursor.lastrowid
            logger.debug(f"Scan créé: ID={scan_id}, type={scan_type}")
            return scan_id
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erreur création scan: {e}")
            raise

    def update_scan(
        self,
        scan_id: int,
        total_files: int,
        infected_files: int,
        status: str,
        duration: float
    ) -> None:
        """Met à jour les statistiques d'un scan terminé."""
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE scans
                   SET finished_at=?, total_files=?, infected_files=?,
                       status=?, duration_seconds=?
                   WHERE id=?""",
                (datetime.now().isoformat(), total_files, infected_files,
                 status, duration, scan_id)
            )
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erreur mise à jour scan {scan_id}: {e}")

    def insert_scan_result(self, result: Dict[str, Any]) -> int:
        """
        Insère un résultat de scan en base.

        Args:
            result: Dictionnaire contenant les données du résultat.

        Returns:
            ID de l'enregistrement inséré.
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """INSERT INTO scan_results
                   (scan_id, file_path, file_name, file_size, file_extension,
                    sha256_hash, is_malicious, threat_level, detection_method,
                    ml_score, threat_name, scanned_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.get("scan_id"),
                    result.get("file_path"),
                    result.get("file_name"),
                    result.get("file_size", 0),
                    result.get("file_extension"),
                    result.get("sha256_hash"),
                    1 if result.get("is_malicious") else 0,
                    result.get("threat_level", "none"),
                    result.get("detection_method"),
                    result.get("ml_score", 0.0),
                    result.get("threat_name"),
                    datetime.now().isoformat()
                )
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erreur insertion résultat: {e}")
            return -1

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Récupère l'historique des scans.

        Args:
            limit: Nombre maximum de scans à retourner.

        Returns:
            Liste de dictionnaires représentant les scans.
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """SELECT * FROM scans
                   ORDER BY started_at DESC
                   LIMIT ?""",
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Erreur lecture historique: {e}")
            return []

    def get_scan_results(self, scan_id: int) -> List[Dict[str, Any]]:
        """Récupère tous les résultats d'un scan spécifique."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT * FROM scan_results WHERE scan_id=? ORDER BY is_malicious DESC",
                (scan_id,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Erreur lecture résultats scan {scan_id}: {e}")
            return []

    # ─── Méthodes Quarantaine ────────────────────────────────────────────────

    def add_to_quarantine(self, data: Dict[str, Any]) -> int:
        """Ajoute un fichier à la quarantaine."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """INSERT INTO quarantine
                   (original_path, quarantine_path, file_name, file_size,
                    sha256_hash, threat_name, threat_level)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    data.get("original_path"),
                    data.get("quarantine_path"),
                    data.get("file_name"),
                    data.get("file_size", 0),
                    data.get("sha256_hash"),
                    data.get("threat_name"),
                    data.get("threat_level", "high")
                )
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erreur ajout quarantaine: {e}")
            return -1

    def get_quarantine_items(self) -> List[Dict[str, Any]]:
        """Récupère tous les éléments en quarantaine actifs."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """SELECT * FROM quarantine
                   WHERE is_deleted=0 AND is_restored=0
                   ORDER BY quarantined_at DESC"""
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Erreur lecture quarantaine: {e}")
            return []

    def restore_from_quarantine(self, item_id: int) -> bool:
        """Marque un élément de quarantaine comme restauré."""
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE quarantine SET is_restored=1, restored_at=? WHERE id=?",
                (datetime.now().isoformat(), item_id)
            )
            conn.commit()
            return True
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erreur restauration quarantaine: {e}")
            return False

    def delete_from_quarantine(self, item_id: int) -> bool:
        """Marque un élément de quarantaine comme supprimé définitivement."""
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE quarantine SET is_deleted=1 WHERE id=?",
                (item_id,)
            )
            conn.commit()
            return True
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erreur suppression quarantaine: {e}")
            return False

    # ─── Méthodes Alertes ───────────────────────────────────────────────────

    def add_alert(self, alert: Dict[str, Any]) -> int:
        """Ajoute une alerte de monitoring."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """INSERT INTO monitoring_alerts
                   (alert_type, severity, title, description,
                    process_name, process_pid, file_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert.get("alert_type"),
                    alert.get("severity"),
                    alert.get("title"),
                    alert.get("description"),
                    alert.get("process_name"),
                    alert.get("process_pid"),
                    alert.get("file_path")
                )
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erreur ajout alerte: {e}")
            return -1

    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Récupère les alertes récentes."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT * FROM monitoring_alerts ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Erreur lecture alertes: {e}")
            return []

    # ─── Statistiques Dashboard ─────────────────────────────────────────────

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """
        Récupère les statistiques pour le dashboard.

        Returns:
            Dictionnaire avec toutes les métriques du dashboard.
        """
        conn = self._get_connection()
        try:
            stats: Dict[str, Any] = {}

            # Total des scans
            cursor = conn.execute("SELECT COUNT(*) FROM scans WHERE status='completed'")
            stats["total_scans"] = cursor.fetchone()[0]

            # Total des fichiers scannés
            cursor = conn.execute("SELECT SUM(total_files) FROM scans WHERE status='completed'")
            result = cursor.fetchone()[0]
            stats["total_files_scanned"] = result or 0

            # Total des menaces détectées
            cursor = conn.execute("SELECT COUNT(*) FROM scan_results WHERE is_malicious=1")
            stats["total_threats"] = cursor.fetchone()[0]

            # Fichiers en quarantaine
            cursor = conn.execute(
                "SELECT COUNT(*) FROM quarantine WHERE is_deleted=0 AND is_restored=0"
            )
            stats["quarantine_count"] = cursor.fetchone()[0]

            # Alertes non acquittées
            cursor = conn.execute(
                "SELECT COUNT(*) FROM monitoring_alerts WHERE is_acknowledged=0"
            )
            stats["unacknowledged_alerts"] = cursor.fetchone()[0]

            # Dernier scan
            cursor = conn.execute(
                "SELECT started_at, scan_type FROM scans ORDER BY started_at DESC LIMIT 1"
            )
            row = cursor.fetchone()
            stats["last_scan"] = dict(row) if row else None

            # Menaces par niveau
            cursor = conn.execute(
                """SELECT threat_level, COUNT(*) as count
                   FROM scan_results WHERE is_malicious=1
                   GROUP BY threat_level"""
            )
            stats["threats_by_level"] = {row[0]: row[1] for row in cursor.fetchall()}

            return stats
        except sqlite3.Error as e:
            logger.error(f"Erreur lecture stats dashboard: {e}")
            return {}

    def close(self) -> None:
        """Ferme la connexion à la base de données."""
        if hasattr(self._thread_local, "conn") and self._thread_local.conn:
            self._thread_local.conn.close()
            self._thread_local.conn = None
            logger.debug("Connexion DB fermée.")
