from setuptools import setup, find_packages  # type: ignore

setup(
    name="dns-smtp-email-validator",
    version="0.1.6",
    author="Shailesh",
    author_email="shaileshpandit141@gmail.com",
    description="""DNS and SMTP Email Validator is a robust Python library designed
    to validate email addresses at multiple levels. It checks the format, domain,
    and MX records, and even communicates with the mail server to confirm the
    existence of the recipient's email address.
    """,
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/shaileshpandit141/dns-smtp-email-validator.git",
    packages=find_packages(),
    install_requires=[
        "dnspython>=2.3.0",
        "python-decouple>=3.0.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
)
