#!/usr/bin/python

from setuptools import setup


setup(
    name='wpactrl-cffi',
    setup_requires=['cffi>=1.0.0'],
    cffi_modules=['build_ffi.py:ffi'],
    install_requires=['cffi>=1.0.0'],
    description='Python bindings for wpa_supplicant/hostapd ctrl socket, built with cffi.',
)
