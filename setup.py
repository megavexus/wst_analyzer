#!/usr/bin/python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
try:  # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError:  # for pip <= 9.0.3
    from pip.req import parse_requirements
from glob import glob

REQUIREMENTS = [str(ir.req) for ir in parse_requirements(
    'requirements.txt',  session=False)]

setup(
    name='wst_analyzer',
    version='0.2',
    description='Monitoring Asset API (shodan, whois, otx)',

    author='Javier Gutiérrez y Omar Rodriguez',
    author_email='omarrs@gmail.com',

    url='https://127.0.0.1:5000/analyzer/',

    install_requires=REQUIREMENTS,

    packages=find_packages(where='src'),
    include_package_data=True,
    package_dir={'': 'src'},
    zip_safe=False,
    data_files=[('requs', glob('*.txt'))],

    # Testing
    #setup_requires=["pytest-runner"],
    #tests_require=REQUIREMENTS_TEST,
)