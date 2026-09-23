"""Typed inventory errors (docs/threat-model.md → Vulnerability DB sync, Inventory rendering)."""

from __future__ import annotations

from app.core.errors import AppError


class InventoryError(AppError):
    status_code = 422
    code = "inventory_failed"
    message_key = "errors.inventory.failed"


class DumpTooLarge(InventoryError):
    status_code = 413
    code = "dump_too_large"
    message_key = "errors.inventory.dumpTooLarge"


class DumpInvalid(InventoryError):
    code = "dump_invalid"
    message_key = "errors.inventory.dumpInvalid"


class DumpKindUnknown(InventoryError):
    code = "dump_kind_unknown"
    message_key = "errors.inventory.dumpKindUnknown"


class SyncDisabled(InventoryError):
    status_code = 409
    code = "vulndb_sync_disabled"
    message_key = "errors.inventory.syncDisabled"


class EnqueueFailed(InventoryError):
    status_code = 503
    code = "vulndb_enqueue_failed"
    message_key = "errors.inventory.enqueueFailed"


class SbomMissing(InventoryError):
    status_code = 404
    code = "sbom_missing"
    message_key = "errors.inventory.sbomMissing"
