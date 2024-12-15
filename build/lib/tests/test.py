import unittest
from dns_smtp_email_validator import DNSSMTPEmailValidator

class TestDNSSMTPEmailValidator(unittest.TestCase):
    def test_valid_email(self):
        validator = DNSSMTPEmailValidator("johnsmithtesting@gmail.com")
        self.assertTrue(validator.is_valid())

    def test_invalid_email(self):
        validator = DNSSMTPEmailValidator("invalid-email")
        self.assertFalse(validator.is_valid())

    def test_valid_email_with_numbers(self):
        validator = DNSSMTPEmailValidator("test123@example.com")
        self.assertTrue(validator.is_valid())

    def test_valid_email_with_dots(self):
        validator = DNSSMTPEmailValidator("john.smith@example.com")
        self.assertTrue(validator.is_valid())

    def test_valid_email_with_plus(self):
        validator = DNSSMTPEmailValidator("john+test@example.com")
        self.assertTrue(validator.is_valid())

    def test_invalid_email_no_at_symbol(self):
        validator = DNSSMTPEmailValidator("johndoe.example.com")
        self.assertFalse(validator.is_valid())

    def test_invalid_email_multiple_at_symbols(self):
        validator = DNSSMTPEmailValidator("john@doe@example.com")
        self.assertFalse(validator.is_valid())

    def test_invalid_email_special_chars(self):
        validator = DNSSMTPEmailValidator("john#doe@example.com")
        self.assertFalse(validator.is_valid())

    def test_invalid_email_empty_string(self):
        validator = DNSSMTPEmailValidator("")
        self.assertFalse(validator.is_valid())

    def test_invalid_email_spaces(self):
        validator = DNSSMTPEmailValidator("john doe@example.com")
        self.assertFalse(validator.is_valid())

if __name__ == "__main__":
    unittest.main()
