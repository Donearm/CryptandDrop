#!/usr/bin/env python2
# -*- coding: utf-8 -*-
###############################################################################
# Copyright (c) 2011-2013, Gianluca Fiore
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
###############################################################################

from distutils.core import setup

setup(name='Cryptanddrop',
        version='0.1',
        author='Gianluca Fiore',
        author_email='forod.g@gmail.com',
        url='https://github.com/Donearm/CryptandDrop',
        download_url='https://github.com/Donearm/CryptandDrop',
        description='An encrypter/decrypter for files hosted on Dropbox',
        long_description=open('README.mdown').read(),
        packages=['cryptanddrop'],
        provides=['cryptanddrop'],
        requires=['pycrypto', 'python-oauth', 'simplejson'],
        keywords='encrypter decrypter dropbox',
        license='COPYING',
        classfiers=['Development Status :: 4 - Beta',
            'Environment :: Console',
            'Intended Audience :: End Users/Desktop',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: GNU General Public License (GPL)',
            'Operating System :: OS Independent',
            'Programming Language :: Python :: 2',
            'Topic :: Internet']
        )
