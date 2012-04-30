from setuptools import setup

setup(
    name='bootlegger',
    version='0.4.0',
    description='Command Line Interface to Speakeasy',
    author='Zhehao Mao',
    author_email='zhehao.mao@gmail.com',
    packages=['bootlegger'],
    entry_points = {
        "console_scripts" : [
            "bootlegger = bootlegger.cli:main",
            "bl = bootlegger.cli:main"
        ]
    },
    install_requires=['pycrypto', 'requests']
)

