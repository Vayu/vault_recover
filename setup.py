from setuptools import setup


setup(
    name='vault_recover',
    version='0.0.1',
    author='Valery Yundin',
    author_email='yuvalery@gmail.com',
    description=('Extract vault master key from memory of running process'),
    keywords='',
    url='https://github.com/Vayu/vault_recover',
    scripts=['vault_recover.py'],
    install_requires=[
        'cryptography>=1.3.1,<2.0.0',
    ]
)
