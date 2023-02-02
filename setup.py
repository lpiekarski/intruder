from setuptools import setup

setup(
    name="intruder",
    version="0.1.0",

    url='https://github.com/lpiekarski/intruder',
    author='Łukasz Piekarski',
    author_email='lukasz.piekarski.001@gmail.com',

    py_modules=['intruder'],
    entry_points={
        'console_scripts': [
            'intruder=intruder:main',
        ],
    },
)