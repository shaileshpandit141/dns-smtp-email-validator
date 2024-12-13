import unittest
from dns_smtp_email_validator import DNSSMTPEmailValidator 

class TestDNSAndSMTPEmailValidator(unittest.TestCase):
    def test_valid_email(self):
        validator = DNSSMTPEmailValidator("test@gmail.com")
        self.assertTrue(validator.is_valid())

    def test_invalid_email(self):
        validator = DNSSMTPEmailValidator("invalid-email")
        self.assertFalse(validator.is_valid())

if __name__ == "__main__":
    unittest.main()
