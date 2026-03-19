from setuptools import setup, find_packages

setup(
    name="samd-validation-toolkit",
    version="0.1.0",
    description="SaMD Validation Checklist & IQ/OQ/PQ Template Generator",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="SaMD Toolkit Contributors",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[
        "reportlab>=4.0.0",
        "jinja2>=3.1.0",
        "click>=8.1.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "black", "mypy", "flake8"],
    },
    entry_points={
        "console_scripts": [
            "samd-toolkit=samd_toolkit.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Healthcare Industry",
        "Topic :: Scientific/Engineering :: Medical Science Apps.",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
    ],
    keywords="samd medical device validation iq oq pq fda iec62304 iso14971 cybersecurity",
)
