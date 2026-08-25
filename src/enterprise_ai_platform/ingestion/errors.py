"""Stable privacy-safe failures for the governed ingestion boundary."""


class IngestionError(Exception):
    """Base error whose public form never includes source content or paths."""

    code = "ingestion_error"
    public_message = "The ingestion operation failed."
    exit_code = 4

    def __init__(self) -> None:
        super().__init__(self.public_message)


class IngestionConfigurationError(IngestionError):
    code = "ingestion_configuration_invalid"
    public_message = "The ingestion configuration is invalid."
    exit_code = 2


class IngestionSourceError(IngestionError):
    code = "ingestion_source_quarantined"
    public_message = "The source did not pass ingestion validation."
    exit_code = 3


class IngestionAuthorizationError(IngestionError):
    code = "ingestion_authorization_denied"
    public_message = "The ingestion operation is not authorized."
    exit_code = 3


class IngestionContractError(IngestionError):
    code = "ingestion_contract_mismatch"
    public_message = "An ingestion provider does not match the approved contract."
    exit_code = 4


class IngestionProviderError(IngestionError):
    code = "ingestion_provider_failed"
    public_message = "An ingestion provider could not complete the operation."
    exit_code = 4


class IngestionRollbackIndeterminateError(IngestionError):
    code = "ingestion_rollback_indeterminate"
    public_message = "The affected document version could not be proven absent."
    exit_code = 5


class IngestionCancelledError(IngestionError):
    code = "ingestion_cancelled"
    public_message = "The ingestion operation was cancelled."
    exit_code = 130
