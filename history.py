"""
Scan History Manager
====================
Thread-safe in-memory history storage with optional JSON file persistence.
Stores the most recent scan results for display in the history panel.
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import List, Dict, Optional


class HistoryManager:
    """
    Manages URL scan history with thread-safe operations.
    
    Stores entries in-memory with optional file persistence.
    Automatically limits history to the most recent MAX_ENTRIES.
    """

    MAX_ENTRIES = 50
    DEFAULT_FILE = "history_data.json"

    def __init__(self, persist: bool = False, filepath: Optional[str] = None):
        """
        Initialize the history manager.
        
        Args:
            persist: If True, also save history to a JSON file.
            filepath: Path to the JSON file for persistence (default: history_data.json).
        """
        self._entries: List[Dict] = []
        self._lock = threading.Lock()
        self._persist = persist
        self._filepath = filepath or self.DEFAULT_FILE

        if self._persist and os.path.exists(self._filepath):
            self._load_from_file()

    def add_entry(self, url: str, status: str, risk_score: int) -> Dict:
        """
        Add a new scan result to history.
        
        Args:
            url: The scanned URL.
            status: Result status ("safe", "suspicious", "dangerous").
            risk_score: Numeric risk score (0-100).
            
        Returns:
            The created history entry dict.
        """
        entry = {
            "id": self._generate_id(),
            "url": url,
            "status": status,
            "risk_score": risk_score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            self._entries.insert(0, entry)  # Most recent first

            # Trim to max entries
            if len(self._entries) > self.MAX_ENTRIES:
                self._entries = self._entries[:self.MAX_ENTRIES]

            if self._persist:
                self._save_to_file()

        return entry

    def get_history(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Retrieve scan history.
        
        Args:
            limit: Maximum number of entries to return (default: all).
            
        Returns:
            List of history entry dicts, most recent first.
        """
        with self._lock:
            if limit:
                return list(self._entries[:limit])
            return list(self._entries)

    def clear_history(self) -> int:
        """
        Clear all history entries.
        
        Returns:
            Number of entries that were cleared.
        """
        with self._lock:
            count = len(self._entries)
            self._entries = []

            if self._persist:
                self._save_to_file()

        return count

    def get_entry_count(self) -> int:
        """Return the current number of history entries."""
        with self._lock:
            return len(self._entries)

    def _generate_id(self) -> str:
        """Generate a unique ID for a history entry."""
        now = datetime.now(timezone.utc)
        return f"scan_{now.strftime('%Y%m%d%H%M%S')}_{id(now) % 10000:04d}"

    def _save_to_file(self) -> None:
        """Save current history to JSON file. Must be called within a lock."""
        try:
            with open(self._filepath, 'w', encoding='utf-8') as f:
                json.dump(self._entries, f, indent=2, ensure_ascii=False)
        except (IOError, OSError):
            pass  # Silently fail file operations — in-memory is primary

    def _load_from_file(self) -> None:
        """Load history from JSON file."""
        try:
            with open(self._filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    self._entries = data[:self.MAX_ENTRIES]
        except (IOError, OSError, json.JSONDecodeError):
            self._entries = []
