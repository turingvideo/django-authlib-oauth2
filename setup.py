#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import django_authlib_oauth2


with open('requirements.txt') as f:
    requirements = f.read().strip().split('\n')

version = django_authlib_oauth2.__version__

setup(
    name='Django Authlib OAuth2',
    version=version,
    description='OAuth2 authorization server for Django using Authlib.',
    keywords='django, authlib, oauth2',
    url='https://github.com/longshine/django-authlib-oauth2',
    packages=find_packages(include=('django_authlib_oauth2', 'django_authlib_oauth2.*')),
    install_requires=requirements,
    python_requires=">=3.6",
)
