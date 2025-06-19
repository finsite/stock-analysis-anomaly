"""Processor module for detecting anomalies from input messages.

This module validates incoming messages and computes anomaly detection
based on the input data. All operations are logged for observability.
"""

from typing import Any

from app.utils.setup_logger import setup_logger
from app.utils.types import ValidatedMessage
from app.utils.validate_data import validate_message_schema

logger = setup_logger(__name__)


def validate_input_message(message: dict[str, Any]) -> ValidatedMessage:
    """
    Validate the incoming raw message against the expected schema.

    Parameters
    ----------
    message : dict[str, Any]
        The raw message payload.

    Returns
    -------
    ValidatedMessage
        A validated message object.

    Raises
    ------
    ValueError
        If the message is not properly structured.
    """
    logger.debug("🔍 Validating message schema...")
    if not validate_message_schema(message):
        logger.error("❌ Message schema invalid: %s", message)
        raise ValueError("Invalid message format")
    return message  # type: ignore[return-value]


def detect_anomaly(message: ValidatedMessage) -> dict[str, Any]:
    """
    Detect anomaly from the validated input message.

    This function is a placeholder for statistical models or
    rule-based logic to determine if an anomaly occurred.

    Parameters
    ----------
    message : ValidatedMessage
        The validated input message.

    Returns
    -------
    dict[str, Any]
        Dictionary with anomaly detection result.
    """
    logger.debug("📉 Detecting anomaly for %s", message["symbol"])

    # Placeholder anomaly condition: static rule
    is_anomaly = False
    confidence = 0.0

    return {
        "symbol": message["symbol"],
        "timestamp": message["timestamp"],
        "is_anomaly": is_anomaly,
        "confidence": confidence,
    }


def process_message(raw_message: dict[str, Any]) -> ValidatedMessage:
    """
    Main entry point for processing a single message.

    Parameters
    ----------
    raw_message : dict[str, Any]
        Raw input from the message queue.

    Returns
    -------
    ValidatedMessage
        Enriched and validated message ready for output.
    """
    logger.info("🚦 Processing new message...")
    validated = validate_input_message(raw_message)
    anomaly_data = detect_anomaly(validated)

    enriched: ValidatedMessage = {
        "symbol": validated["symbol"],
        "timestamp": validated["timestamp"],
        "data": {**validated["data"], **anomaly_data},
    }
    logger.debug("✅ Final enriched message: %s", enriched)
    return enriched
