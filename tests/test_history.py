"""
Unit tests for the HistoryManager.
Tests CRUD operations, limits, and thread safety.
"""

import os
import json
import tempfile
import threading
import pytest
from history import HistoryManager


@pytest.fixture
def manager():
    """Create a fresh non-persistent HistoryManager."""
    return HistoryManager(persist=False)


@pytest.fixture
def persistent_manager(tmp_path):
    """Create a HistoryManager with file persistence."""
    filepath = str(tmp_path / "test_history.json")
    return HistoryManager(persist=True, filepath=filepath)


# ─── Test Adding Entries ────────────────────────────────────────────────────

class TestAddEntry:
    """Test adding scan entries to history."""

    def test_add_single_entry(self, manager):
        entry = manager.add_entry("https://example.com", "safe", 10)
        assert entry["url"] == "https://example.com"
        assert entry["status"] == "safe"
        assert entry["risk_score"] == 10
        assert "id" in entry
        assert "timestamp" in entry

    def test_add_multiple_entries(self, manager):
        manager.add_entry("https://a.com", "safe", 5)
        manager.add_entry("https://b.com", "suspicious", 45)
        manager.add_entry("https://c.com", "dangerous", 85)
        assert manager.get_entry_count() == 3

    def test_newest_entry_first(self, manager):
        manager.add_entry("https://first.com", "safe", 10)
        manager.add_entry("https://second.com", "safe", 15)

        history = manager.get_history()
        assert history[0]["url"] == "https://second.com"
        assert history[1]["url"] == "https://first.com"


# ─── Test History Retrieval ─────────────────────────────────────────────────

class TestGetHistory:
    """Test retrieving history entries."""

    def test_empty_history(self, manager):
        history = manager.get_history()
        assert history == []

    def test_get_all_entries(self, manager):
        for i in range(5):
            manager.add_entry(f"https://site{i}.com", "safe", i * 5)

        history = manager.get_history()
        assert len(history) == 5

    def test_get_with_limit(self, manager):
        for i in range(10):
            manager.add_entry(f"https://site{i}.com", "safe", i)

        history = manager.get_history(limit=3)
        assert len(history) == 3

    def test_limit_larger_than_entries(self, manager):
        manager.add_entry("https://example.com", "safe", 5)
        history = manager.get_history(limit=100)
        assert len(history) == 1

    def test_returns_copy(self, manager):
        """Modifying returned list shouldn't affect internal state."""
        manager.add_entry("https://example.com", "safe", 5)
        history = manager.get_history()
        history.clear()
        assert manager.get_entry_count() == 1


# ─── Test Max Entries Limit ─────────────────────────────────────────────────

class TestMaxEntries:
    """Test that history is trimmed to MAX_ENTRIES."""

    def test_trim_at_max(self, manager):
        # Override max for testing
        manager.MAX_ENTRIES = 5

        for i in range(10):
            manager.add_entry(f"https://site{i}.com", "safe", i)

        assert manager.get_entry_count() == 5

    def test_oldest_entries_removed(self, manager):
        manager.MAX_ENTRIES = 3

        manager.add_entry("https://old.com", "safe", 0)
        manager.add_entry("https://mid.com", "safe", 5)
        manager.add_entry("https://new.com", "safe", 10)
        manager.add_entry("https://newest.com", "safe", 15)

        history = manager.get_history()
        urls = [e["url"] for e in history]
        assert "https://old.com" not in urls
        assert "https://newest.com" in urls


# ─── Test Clear History ─────────────────────────────────────────────────────

class TestClearHistory:
    """Test clearing history."""

    def test_clear_returns_count(self, manager):
        for i in range(5):
            manager.add_entry(f"https://site{i}.com", "safe", i)

        count = manager.clear_history()
        assert count == 5

    def test_clear_empties_history(self, manager):
        manager.add_entry("https://example.com", "safe", 5)
        manager.clear_history()
        assert manager.get_entry_count() == 0
        assert manager.get_history() == []

    def test_clear_empty_history(self, manager):
        count = manager.clear_history()
        assert count == 0


# ─── Test Persistence ───────────────────────────────────────────────────────

class TestPersistence:
    """Test file-based persistence."""

    def test_save_and_load(self, tmp_path):
        filepath = str(tmp_path / "hist.json")

        # Create manager and add entries
        m1 = HistoryManager(persist=True, filepath=filepath)
        m1.add_entry("https://example.com", "safe", 10)
        m1.add_entry("https://evil.tk", "dangerous", 90)

        # Create new manager — should load from file
        m2 = HistoryManager(persist=True, filepath=filepath)
        history = m2.get_history()

        assert len(history) == 2
        assert history[0]["url"] == "https://evil.tk"

    def test_persistence_file_created(self, tmp_path):
        filepath = str(tmp_path / "new_hist.json")
        m = HistoryManager(persist=True, filepath=filepath)
        m.add_entry("https://test.com", "safe", 5)

        assert os.path.exists(filepath)

    def test_corrupted_file_handled(self, tmp_path):
        filepath = str(tmp_path / "corrupt.json")

        # Write corrupted JSON
        with open(filepath, 'w') as f:
            f.write("not valid json{{{")

        # Should not crash — just start with empty history
        m = HistoryManager(persist=True, filepath=filepath)
        assert m.get_entry_count() == 0


# ─── Test Thread Safety ────────────────────────────────────────────────────

class TestThreadSafety:
    """Test concurrent access to history."""

    def test_concurrent_adds(self, manager):
        """Multiple threads adding entries shouldn't cause data corruption."""
        errors = []

        def add_entries(thread_id):
            try:
                for i in range(20):
                    manager.add_entry(
                        f"https://thread{thread_id}-{i}.com",
                        "safe",
                        thread_id * 10 + i,
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_entries, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # All 100 entries should be added (or trimmed to MAX_ENTRIES)
        assert manager.get_entry_count() <= manager.MAX_ENTRIES

    def test_concurrent_read_write(self, manager):
        """Reading and writing concurrently shouldn't crash."""
        errors = []

        def writer():
            try:
                for i in range(30):
                    manager.add_entry(f"https://write-{i}.com", "safe", i)
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(30):
                    manager.get_history()
                    manager.get_entry_count()
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# ─── Test Entry Count ───────────────────────────────────────────────────────

class TestEntryCount:
    """Test get_entry_count method."""

    def test_initial_count_zero(self, manager):
        assert manager.get_entry_count() == 0

    def test_count_after_adds(self, manager):
        manager.add_entry("https://a.com", "safe", 5)
        manager.add_entry("https://b.com", "safe", 10)
        assert manager.get_entry_count() == 2

    def test_count_after_clear(self, manager):
        manager.add_entry("https://a.com", "safe", 5)
        manager.clear_history()
        assert manager.get_entry_count() == 0
