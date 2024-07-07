import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='PiHole6-api',
    version='0.1',
    description='A python3 wrapper for the pihole6 api',
    url='https://github.com/ingoratsdorf/pihole6-api',
    author='Ingo Ratsdorf',
    author_email='ingo@ratsdorf.net',
    license='MIT',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=['requests', 'python-dateutil'],
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 1 - Planning",
    ),
)
