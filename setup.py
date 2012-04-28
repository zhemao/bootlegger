from setuptools import setup

setup(
    name='bootlegger',
    version='0.1.0',
    description='Command Line Interface to Speakeasy',
    author='Zhehao Mao',
    author_email='zhehao.mao@gmail.com',
    packages=['bootlegger'],
    install_requires=['pycrypto', 'requests'],
    entry_points = {
        'console_scripts': [
            'bootlegger = bootlegger.cli:main',
            'bl = bootlegger.cli:main'
        ]
    }
)

