from typing import Self, List, Tuple, Literal, Optional
import re
import smtplib
from dns.resolver import resolve, NXDOMAIN, Timeout
from decouple import config, Csv

ALLOWED_EMAIL_DOMAINS = config("ALLOWED_EMAIL_DOMAINS", cast=Csv(), default = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "aol.com", "zoho.com", "protonmail.com",
    "yandex.com", "gmx.com", "mail.ru", "rediffmail.com",
    "qq.com", "163.com", "126.com", "tutanota.com",
    "yahoo.co.jp", "nifty.com"
])


class DNSSMTPEmailValidator:
    def __init__(
        self: Self,
        email: str,
        sender_email: str = "example@domain.com",
        raise_exception: Literal[True, False] = False
    ) -> None:
        self.sender_email = sender_email
        self.recipient_email = email
        self.raise_exception = raise_exception
        self.errors = []

    def __is_valid_email_format(self: Self) -> bool:
        pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        return re.match(pattern, self.recipient_email) is not None

    def __get_username_and_domain(self: Self) -> List[str]:
        return self.recipient_email.split("@")

    @staticmethod
    def __validate_email_domain(domain: str) -> bool:
        return domain in ALLOWED_EMAIL_DOMAINS

    def __handle_error(self: Self, error_message: str) -> None:
        if self.raise_exception:
            raise ValueError(error_message)
        self.errors.append(error_message)

    def __get_mx_record(self: Self) -> Optional[str]:
        if not self.__is_valid_email_format():
            self.__handle_error("Provided email address is not valid.")
            return None

        username, domain = self.__get_username_and_domain()
        if not DNSSMTPEmailValidator.__validate_email_domain(domain):
            self.__handle_error("The email domain is not allowed.")
            return None

        try:
            mx_records = resolve(domain, "MX", lifetime=5)
            if not mx_records:
                self.__handle_error(f"No MX records found for domain: {domain}")
                return None
            return str(mx_records[0].exchange).strip()
        except NXDOMAIN:
            self.__handle_error(f"No MX record found for domain: {domain}")
            return None
        except Timeout:
            self.__handle_error(f"DNS query timed out for domain: {domain}")
            return None
        except Exception as error:
            self.__handle_error(f"Failed to fetch MX record: {error}")
            return None

    def __connect_to_mail_server(self: Self, mx_host: str) -> Optional[Tuple[int, bytes]]:
        try:
            # Use a more secure port if available
            with smtplib.SMTP(mx_host, 25, timeout=10) as server:
                server.helo()
                server.mail(self.sender_email)
                code, message = server.rcpt(self.recipient_email)
                return code, message
        except smtplib.SMTPException as e:
            self.__handle_error(f"SMTP connection failed: {e}")
        except Exception as e:
            self.__handle_error(f"Unexpected error during SMTP communication: {e}")
        return None

    def is_valid(self: Self) -> bool:
        try:
            mx_host = self.__get_mx_record()
            if mx_host:
                payload = self.__connect_to_mail_server(mx_host)
                if payload:
                    return payload[0] == 250
            return False
        except Exception as error:
            self.__handle_error(str(error))
            return False
