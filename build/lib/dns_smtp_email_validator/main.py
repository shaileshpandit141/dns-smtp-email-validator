from typing import Self, List, Tuple, Literal, Optional
import re
import smtplib
from dns.resolver import resolve, NXDOMAIN, Timeout  # type: ignore
from decouple import config, Csv  # type: ignore
from .main_types import ErrorsFieldType, ErrorsType

# List of commonly used and allowed email domain names
DEFAULT_ALLOWED_EMAIL_DOMAINS = [
    "aol.com",
    "gmail.com",
    "hotmail.com",
    "icloud.com",
    "outlook.com",
    "yahoo.com",
    "zoho.com"
]

# Get allowed email domains from config, falling back to defaults
ALLOWED_EMAIL_DOMAINS = config(
    "ALLOWED_EMAIL_DOMAINS",
    cast=Csv(),
    default=','.join(DEFAULT_ALLOWED_EMAIL_DOMAINS)
)


class DNSSMTPEmailValidator:
    """
    A class to validate email addresses using DNS and SMTP checks.

    Validates email format, domain existence via MX records,
    and recipient acceptance via SMTP.
    """

    def __init__(
        self: Self,
        email: str,
        sender_email: str = "example@domain.com",
        raise_exception: Literal[True, False] = False
    ) -> None:
        """
        Initialize the email validator.

        Args:
            email: The email address to validate
            sender_email: Email address to use as sender in SMTP checks
            raise_exception: Whether to raise exceptions on validation errors
        """
        self.sender_email = sender_email
        self.recipient_email = email
        self.raise_exception = raise_exception
        self.errors: ErrorsType = []
        self.long_errors: ErrorsType = []

    def __is_valid_email_format(self: Self) -> bool:
        """Check if email matches standard email format pattern."""
        pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        return re.match(pattern, self.recipient_email) is not None

    def __get_username_and_domain(self: Self) -> List[str]:
        """Split email into username and domain parts."""
        return self.recipient_email.split("@")

    @staticmethod
    def __validate_email_domain(domain: str) -> bool:
        """Check if domain is in allowed list."""
        return domain in ALLOWED_EMAIL_DOMAINS

    def __handle_error(
        self: Self,
        error_message: str,
        code: str = "invalid_email",
        details: Optional[str] = None
    ) -> None:
        """
        Handle validation errors by either raising exception or storing error message.

        Args:
            error_message: The error message to handle
            code: Error code identifier
            details: Additional error details
        """
        error: ErrorsFieldType = {
            "field": "email",
            "code": code,
            "message": error_message,
            "details": {
                "error_type": code,
                "error_description": error_message,
                "additional_info": details
            }
        }
        if self.raise_exception:
            raise ValueError(error_message)
        self.errors.append(error)

    def __get_mx_record(self: Self) -> Optional[str]:
        """
        Get MX record for email domain.

        Returns:
            Mail server hostname or None if lookup fails
        """
        if not self.__is_valid_email_format():
            self.__handle_error(
                "Invalid email format. Please check and try again.",
                "invalid_format"
            )
            return None

        username, domain = self.__get_username_and_domain()
        if not DNSSMTPEmailValidator.__validate_email_domain(domain):
            self.__handle_error(
                f"The domain '{domain}' is not supported. Please use a valid email domain.",
                "invalid_domain"
            )
            return None

        try:
            mx_records = resolve(domain, "MX", lifetime=5)
            if not mx_records:
                self.__handle_error(
                    f"No mail server found for domain: {domain}",
                    "no_mx_record"
                )
                return None
            return str(mx_records[0].exchange).strip()
        except NXDOMAIN:
            self.__handle_error(
                f"The domain {domain} does not exist. Please check the spelling.",
                "domain_not_found"
            )
            return None
        except Timeout:
            self.__handle_error(
                f"Connection timed out while checking domain: {domain}. Please try again later.",
                "timeout"
            )
            return None
        except Exception as error:
            self.__handle_error(
                "An error occurred while verifying the mail server",
                "mx_lookup_error",
                str(error)
            )
            self.long_errors.append({
                "field": "email",
                "code": "mx_lookup_error",
                "message": "An error occurred while verifying the mail server",
                "details": {
                    "error_message": str(error),
                    "resolution": "Please try again or contact support"
                }
            })
            return None

    def __connect_to_mail_server(self: Self, mx_host: str) -> Optional[Tuple[int, str]]:
        """
        Connect to mail server and verify recipient acceptance.

        Args:
            mx_host: Hostname of the mail server

        Returns:
            Tuple of (response code, message) or None on error
        """
        try:
            with smtplib.SMTP(mx_host, 25, timeout=10) as server:
                server.helo()
                server.mail(self.sender_email)
                code, message = server.rcpt(self.recipient_email)
                if code != 250:
                    self.__handle_error(
                        "The email address could not be verified",
                        "verification_failed",
                        message.decode()
                    )
                    self.long_errors.append({
                        "field": "email",
                        "code": "verification_failed",
                        "message": "The email address could not be verified",
                        "details": {
                            "server_response": message.decode(),
                            "resolution": "Please verify the email address is correct"
                        }
                    })
                return code, message.decode()
        except smtplib.SMTPException as error:
            self.__handle_error(
                "Could not connect to email server. Please try again later.",
                "smtp_error",
                str(error)
            )
            self.long_errors.append({
                "field": "email",
                "code": "smtp_error",
                "message": "Could not connect to email server",
                "details": {
                    "error_message": str(error),
                    "resolution": "Please try again later"
                }
            })
        except Exception as error:
            self.__handle_error(
                "An unexpected error occurred during verification",
                "verification_error",
                str(error)
            )
            self.long_errors.append({
                "field": "email",
                "code": "verification_error",
                "message": "An unexpected error occurred during verification",
                "details": {
                    "error_message": str(error),
                    "resolution": "Please try again or contact support"
                }
            })
        return None

    def is_valid(self: Self) -> bool:
        """
        Perform complete email validation.

        Returns:
            True if email is valid, False otherwise
        """
        try:
            mx_host = self.__get_mx_record()
            if not mx_host:
                self.__handle_error(
                    "Email validation failed - could not verify mail server",
                    "mx_verification_failed"
                )
                return False

            response = self.__connect_to_mail_server(mx_host)
            if not response:
                self.__handle_error(
                    "Email validation failed - could not complete server verification",
                    "smtp_verification_failed"
                )
                return False

            return response[0] == 250
        except Exception as error:
            self.__handle_error(
                "Email validation process failed",
                "validation_error", str(error)
            )
            self.long_errors.append({
                "field": "email",
                "code": "validation_error",
                "message": "Email validation process failed",
                "details": {
                    "error_message": str(error),
                    "resolution": "Please try again or contact support"
                }
            })
            return False
