import sys
try:
    import multiprocessing, logging
except:
    print "A more recent version of Python is needed."
    sys.exit(1)

from setuptools import setup, find_packages

setup(
    name = 'django-runtime-tags',
    version = '0.1.0',
    description = 'Set template tags via Django admin interface',
    long_description = open('README.rst').read(),
    keywords = 'Django runtime template tags',
    url = 'http://pypi.python.org/pypi/django-runtime-tags/',
    author = 'Liam Kirsher',
    author_email = 'liamk@numenet.com',
    zip_safe = True,

    packages = find_packages(exclude=['tests', 'examples']),
    include_package_data = True,
    exclude_package_data = {'': ['.gitignore']},
    install_requires = [ 'Django >= 1.3', ],
    setup_requires = [ 'setuptools_git >= 0.3', ],

    tests_require = ['nose'],
    test_suite = 'nose.collector',

    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
