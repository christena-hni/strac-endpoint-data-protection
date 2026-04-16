import json
import logging
from datetime import datetime

from peewee import (
    AutoField,
    BigIntegerField,
    BooleanField,
    CharField,
    DateTimeField,
    ForeignKeyField,
    IntegerField,
    Model,
    OperationalError,
    SqliteDatabase,
    TextField,
)

from config import DB_NAME

logger = logging.getLogger("storage-database")

try:
    db = SqliteDatabase(DB_NAME)
    logger.debug(f"local database connection created: {DB_NAME}")
except Exception as e:
    logger.error(f"failed to create database connection: {str(e)}")
    raise


# custom peewee field to store lists in the database
class ListField(TextField):
    def db_value(self, value):
        if value is None:
            return None
        return json.dumps(value)

    def python_value(self, value):
        if value is None:
            return []
        return json.loads(value)


class BaseModel(Model):
    class Meta:
        database = db


class ManagerStatus(BaseModel):
    name = CharField(unique=True)
    should_run = BooleanField(default=False)
    is_running = BooleanField(default=False)
    last_updated = DateTimeField(default=datetime.now)

    class Meta:
        indexes = ((("name",), True),)  # unique index on name


class ManagerHistory(BaseModel):
    name = CharField()
    action = CharField()  # start, stop, restart
    timestamp = DateTimeField(default=datetime.now)
    success = BooleanField(default=True)
    message = TextField(null=True)


class AccessFSUsageLog(BaseModel):
    timestamp = CharField()
    filepath = CharField()
    app_name = CharField()


class BrowserDownloadRecord(BaseModel):
    filename = CharField()
    local_path = CharField()
    source_url = CharField()
    download_time = DateTimeField()
    file_size = BigIntegerField(null=True)
    browser = CharField()
    file_exists = BooleanField()
    mime_type = CharField(null=True)
    created_at = DateTimeField(default=datetime.now)


class BrowserScanHistory(BaseModel):
    browser = CharField(unique=True)
    last_scan = DateTimeField()


class VirtEnvScanHistory(BaseModel):
    vm_name = CharField(unique=True)
    vm_type = CharField()
    last_scan = DateTimeField()


class ScannerHistory(BaseModel):
    id = AutoField()
    path = CharField()
    start_time = DateTimeField()
    end_time = DateTimeField(null=True)
    directories_scanned = IntegerField(default=0)
    files_scanned = IntegerField(default=0)
    directories_skipped = IntegerField(default=0)
    files_skipped = IntegerField(default=0)


class ScannerFile(BaseModel):
    id = AutoField()
    scanner_history = ForeignKeyField(ScannerHistory, backref="files")
    file_path = CharField()  # absolute path
    file_name = CharField()  # file name only
    file_extension = CharField()
    file_signature = CharField(index=True, null=True)


class ScannerFinding(BaseModel):
    id = AutoField()
    scanner_file = ForeignKeyField(ScannerFile, backref="findings")
    finding_type = CharField()
    content = TextField()
    context = TextField()


class NetworkFilterOriginalDefaultRules(BaseModel):
    content = TextField()
    timestamp = DateTimeField(default=datetime.now)


class NetworkInitialConfig(BaseModel):
    content = TextField()
    timestamp = DateTimeField(default=datetime.now)


class NetworkFilterCurrentRules(BaseModel):
    content = TextField()
    timestamp = DateTimeField(default=datetime.now)


class NetworkFilterBlockedSite(BaseModel):
    domain = CharField(unique=True)
    ip_addresses = ListField(default=[])
    added_at = DateTimeField(default=datetime.now)


class NetworkFilterDomainIPTranslation(BaseModel):
    domain = CharField()
    ip_address = CharField()
    dns_server = CharField()
    resolved_at = DateTimeField(default=datetime.now)


class NetworkFilterRuleUpdateHistory(BaseModel):
    changes = TextField()
    updated_at = DateTimeField(default=datetime.now)


class NetworkFilterWebsiteBlockHistory(BaseModel):
    domain = CharField()
    blocked_at = DateTimeField(default=datetime.now)


class NotificationHistory(BaseModel):
    message = TextField()
    notified_at = DateTimeField(default=datetime.now)


class HttpApiLog(BaseModel):
    request_url = CharField()
    request_body = TextField(null=True)
    response_body = TextField(null=True)
    status_code = IntegerField()
    timestamp = DateTimeField(default=datetime.now)


class StracApiDocument(BaseModel):
    document_id = CharField(unique=True)
    content_type = CharField()
    app_name = CharField()
    document_type = CharField()
    file_name = CharField()
    creation_time = DateTimeField()
    size = IntegerField()
    is_sensitive = BooleanField(default=False)
    detection_time = DateTimeField(null=True)
    detected_entities = TextField(null=True)


# -- GenAI observability tables --------------------------------------------
# One GenAIInteraction per prompt submission or file upload intercepted by
# the GenAI manager's TLS-terminating proxy. See src/managers/genai/.


class GenAIInteraction(BaseModel):
    id = AutoField()
    occurred_at = DateTimeField(default=datetime.now, index=True)
    user = CharField(index=True)            # logged-in OS user
    device_id = CharField(index=True)       # SYSTEM.uuid
    provider = CharField(index=True)        # openai | anthropic | copilot | ...
    model = CharField(null=True)            # parsed from request body
    conversation_id = CharField(null=True, index=True)
    direction = CharField(default="request")  # request | response
    url = CharField()
    method = CharField(default="POST")
    host = CharField(index=True)
    # SHA-256 of the extracted prompt text; the raw text is redacted before
    # it hits the Strac backend unless a finding was raised (see runbook).
    prompt_sha256 = CharField(null=True, index=True)
    prompt_chars = IntegerField(default=0)
    prompt_truncated = BooleanField(default=False)
    prompt_preview = TextField(null=True)   # first ~512 redacted chars
    # TLS-pinning or decrypt-failure cases pass through untouched and are
    # surfaced here so operators can see coverage gaps.
    bypass_reason = CharField(null=True)
    status_code = IntegerField(null=True)
    strac_event_id = CharField(null=True)
    synced_to_strac = BooleanField(default=False, index=True)
    created_at = DateTimeField(default=datetime.now)


class GenAIUpload(BaseModel):
    id = AutoField()
    interaction = ForeignKeyField(GenAIInteraction, backref="uploads")
    filename = CharField()
    mime_type = CharField(null=True)
    size_bytes = BigIntegerField(default=0)
    sha256 = CharField(index=True)
    strac_document_id = CharField(null=True)
    created_at = DateTimeField(default=datetime.now)


class GenAIFinding(BaseModel):
    id = AutoField()
    interaction = ForeignKeyField(GenAIInteraction, backref="findings")
    upload = ForeignKeyField(GenAIUpload, backref="findings", null=True)
    detector_name = CharField(index=True)
    finding_type = CharField()
    # We intentionally store a REDACTED copy of the matched content (hash +
    # a masked preview) rather than the raw value, so the audit log itself
    # doesn't become a secondary leak of sensitive data.
    content_redacted = TextField()
    content_sha256 = CharField(null=True)
    context_redacted = TextField(null=True)
    severity = CharField(default="medium")   # low | medium | high | critical
    created_at = DateTimeField(default=datetime.now)


class UsbDrive(BaseModel):
    name = CharField(unique=True)
    mount_point = CharField(unique=True)
    first_connected = DateTimeField(default=datetime.now)
    last_connected = DateTimeField(default=datetime.now)


# this was previously called "FileTransfer" so check your code for that
class UsbFileTransfer(BaseModel):
    filename = CharField()
    destination_path = CharField()
    file_size = IntegerField()
    file_type = CharField()
    usb_drive = CharField()
    transfer_time = DateTimeField(default=datetime.now)
    file_hash = CharField(null=True)

    class Meta:
        database = db
        indexes = (
            (
                ("file_hash", "filename", "usb_drive"),
                True,
            ),  # unique index on file_hash, filename, and usb_drive
        )


def initialize_db():
    """
    Initialize the database and create the necessary tables.
    """
    try:
        db.connect()
        db.create_tables(
            [
                AccessFSUsageLog,
                BrowserDownloadRecord,
                BrowserScanHistory,
                GenAIFinding,
                GenAIInteraction,
                GenAIUpload,
                HttpApiLog,
                ManagerHistory,
                ManagerStatus,
                NetworkFilterBlockedSite,
                NetworkFilterCurrentRules,
                NetworkFilterDomainIPTranslation,
                NetworkInitialConfig,
                NetworkFilterOriginalDefaultRules,
                NetworkFilterRuleUpdateHistory,
                NetworkFilterWebsiteBlockHistory,
                NotificationHistory,
                ScannerFile,
                ScannerFinding,
                ScannerHistory,
                StracApiDocument,
                UsbDrive,
                UsbFileTransfer,
                VirtEnvScanHistory,
            ]
        )
        logger.debug("local database tables created")
    except OperationalError as e:
        if "already opened" in str(e):
            logger.warning("database connection already opened")
        else:
            logger.error(f"failed to create tables: {str(e)}")
    except Exception as e:
        logger.error(f"failed to initialize database: {str(e)}")
        raise
