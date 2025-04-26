from setuptools import setup, find_packages

setup(
    name="imaged",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "PySide6",
        "Pillow",
        "numpy",
        "qoi",
        "ntplib",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "imaged=imaged.ui.main:main",
        ],
    },
    package_data={
        "imaged": ["../resources/qml/*.qml"],
    },
    include_package_data=True,
    data_files=[
        ("share/imaged/qml", ["resources/qml/MainView.qml"]),
        ("share/imaged/icons", []),  # Empty for now, will be populated when icons are added
    ],
) 