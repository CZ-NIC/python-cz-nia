"""Setup script for cz_nia."""

from setuptools import find_packages, setup

import cz_nia

setup(
    name="cz_nia",
    version=cz_nia.__version__,
    author="Tomas Pazderka",
    author_email="tomas.pazderka@nic.cz",
    url="https://github.com/CZ-NIC/python-cz-nia",
    description="Python application for communication with Czech NIA.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    python_requires="~=3.9",
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        "zeep @ git+https://github.com/blaggacao/python-zeep.git@signed_parts",
        "xmlsec",
        "lxml ~= 5.0",
    ],
    extras_require={
        "quality": ["ruff", "mypy"],
        "tests": ["responses"],
        "types": ["types-requests"],
    },
)
