import logging
import re
import smtplib
from os import getenv
from typing import List, Literal, Optional, Self, Tuple

from dns.resolver import NXDOMAIN, Timeout, resolve  # type: ignore
from dotenv import load_dotenv

# Configure logger
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Default email domains
DEFAULT_ALLOWED_EMAIL_DOMAINS = [
    "aol.com",
    "gmail.com",
    "hotmail.com",
    "icloud.com",
    "outlook.com",
    "yahoo.com",
    "zoho.com",
    "duck.com",
]

# Configurable allowed domains
ALLOWED_EMAIL_DOMAINS = getenv(
    "ALLOWED_EMAIL_DOMAINS", default=",".join(DEFAULT_ALLOWED_EMAIL_DOMAINS)
).split(",")


# Default sender email
DEFAULT_SENDER_EMAIL = getenv("DEFAULT_FROM_EMAIL", default=None)

if DEFAULT_SENDER_EMAIL is None:
    raise ValueError("DEFAULT_FROM_EMAIL is not set in environment variables")


class DNSSMTPEmailValidator:
    """
    Validates email addresses using format checks, DNS MX records, and SMTP verification.
    """

    def __init__(
        self: Self,
        email: str,
        sender_email: str = DEFAULT_SENDER_EMAIL,
        raise_exception: Literal[True, False] = False,
    ) -> None:
        """
        Args:
            email: Email address to validate.
            sender_email: Used as the MAIL FROM address in SMTP check.
            raise_exception: Whether to raise exceptions instead of storing errors.
        """
        self.sender_email = sender_email
        self.recipient_email = email
        self.raise_exception = raise_exception
        self.errors: dict[str, list[str]] = {}

    def __is_valid_email_format(self: Self) -> bool:
        """Check if email matches the standard format."""
        pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        return re.match(pattern, self.recipient_email) is not None

    def __get_username_and_domain(self: Self) -> List[str]:
        """Split email into [username, domain]."""
        return self.recipient_email.split("@")

    @staticmethod
    def __validate_email_domain(domain: str) -> bool:
        """Return True if domain is in the allowed list."""
        return domain in ALLOWED_EMAIL_DOMAINS

    def __handle_error(self: Self, error_message: list[str]) -> None:
        """
        Store or raise error depending on configuration.

        Args:
            error_message: Description of the error.
            code: Short error identifier.
        """
        logger.error(f"Validation error : {' '.join(error_message)}")
        error = {"email": error_message}
        if self.raise_exception:
            raise ValueError(" ".join(error_message))
        self.errors = error

    def __get_mx_record(self: Self) -> Optional[str]:
        """Retrieve the MX record for the domain."""
        if not self.__is_valid_email_format():
            self.__handle_error(["Invalid email format."])
            return None

        username, domain = self.__get_username_and_domain()
        if not self.__validate_email_domain(domain):
            self.__handle_error([f"Unsupported email domain '{domain}'."])
            return None

        try:
            mx_records = resolve(domain, "MX", lifetime=5)
            if not mx_records:
                self.__handle_error([f"No MX records found for domain '{domain}'."])
                return None
            return str(mx_records[0].exchange).strip()  # type: ignore
        except NXDOMAIN:
            self.__handle_error([f"Domain '{domain}' does not exist."])
        except Timeout:
            self.__handle_error(
                [f"Timeout occurred while querying MX records for '{domain}'."],
            )
        except Exception as e:
            logger.exception("Unexpected exception during MX lookup.")
            self.__handle_error([f"Unexpected error during MX lookup: {str(e)}"])
        return None

    def __connect_to_mail_server(self: Self, mx_host: str) -> Optional[Tuple[int, str]]:
        """Attempt SMTP connection and validate recipient."""
        try:
            with smtplib.SMTP(mx_host, 25, timeout=10) as server:
                server.helo()
                server.mail(self.sender_email)
                code, message = server.rcpt(self.recipient_email)

                if code != 250:
                    self.__handle_error(
                        [
                            f"The recipient '{self.recipient_email}' was not accepted by the server."
                        ],
                    )
                return code, message.decode()
        except smtplib.SMTPException as e:
            logger.exception("SMTP error during connection.")
            self.__handle_error([f"SMTP error occurred: {str(e)}"])
        except Exception as e:
            logger.exception("Unexpected exception during SMTP connection.")
            self.__handle_error(
                [f"Unexpected error during SMTP connection: {str(e)}"],
            )
        return None

    def is_valid(self: Self) -> bool:
        """Run the full validation process."""
        mx_host = self.__get_mx_record()
        if not mx_host:
            return False

        response = self.__connect_to_mail_server(mx_host)
        if not response:
            return False

        return response[0] == 250
