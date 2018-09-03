"""Setup script for cz_nia."""
from setuptools import find_packages, setup

import cz_nia


setup(name='cz_nia',
      version=cz_nia.__version__,
      description='Python application for communication with Czech NIA.',
      packages=find_packages(),
      install_requires=['zeep', 'xmlsec'],
      extras_require={'quality': ['isort', 'flake8', 'pydocstyle']})
