import re
from skbuild import setup
from setuptools import find_packages


with open("cyminhook/__init__.py", "r", encoding="utf-8") as f:
    version = re.search(r'(?m)^__version__ = "([a-zA-Z0-9.-]+)"', f.read()).group(1)

with open("README.rst", "r", encoding="utf-8") as f:
    long_description = f.read()


setup(
    name="cyminhook",
    version=version,
    author="Segev Finer",
    author_email="segev208@gmail.com",
    description="Hook functions on Windows using MinHook",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/segevfiner/cyminhook",
    project_urls={
        "Documentation": "https://segevfiner.github.io/cyminhook/",
        "Issue Tracker": "https://github.com/segevfiner/cyminhook/issues",
    },
    license="MIT",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    keywords="MinHook",
    zip_safe=False,
    packages=find_packages(),
    python_requires='>=3.6',
    extras_require={
        "dev": [
            "sphinx==4.*",
        ],
    },
)
