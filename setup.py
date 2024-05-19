from setuptools import setup, find_packages
import os
import sys
import subprocess


def install_requirements():
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])


def prepare_tool():
    # Unzip Models.zip
    import zipfile
    with zipfile.ZipFile('Models.zip', 'r') as zip_ref:
        zip_ref.extractall('Models')



install_requirements()
prepare_tool()

setup(
    name='ForceField',
    version='1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'bcrypt',
        'requests',
        'urllib3',
        'tqdm',
        'mysql-connector-python',
        'scapy',
        'beautifulsoup4',
        'colorama',
        'scikit-learn',
    ],
)
