#!/usr/bin/env python

import setuptools

setuptools.setup(
    name='f5-lbaas-agent',
    version='0.1.0',
    description='F5 lbaas agent',
    author='C3',
    author_email='DL-eBay-C3-Dev@corp.ebay.com',
    url='https://github.scm.corp.ebay.com/vbhamidipati/f5_lbaas_agent.git',
    packages=setuptools.find_packages(),
    include_package_data=True,
    zip_safe=False,
    scripts=['f5/bin/f5_lbaas_agent'],
    install_requires = [
    'eventlet>=0.9.17',
    'greenlet>=0.3.3'
    ]
)
