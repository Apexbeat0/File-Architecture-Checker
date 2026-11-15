# File Architecture Checker

A lightweight Python tool for inspecting Windows PE files.

File Architecture Checker identifies the architecture and basic properties of Windows executable files without executing them.

## Features

- Detects CPU architecture:
  - x86 (32-bit)
  - x64 (64-bit)
  - ARM / ARM64
  - ARM64EC
  - Itanium (IA64)
- Identifies file types (EXE, DLL, SYS).
- Detects .NET assemblies.
- Displays file size.
- Reads the PE timestamp.
- Supports drag and drop.
- Copy results to clipboard.

## Requirements

- Python 3
- Tkinter (usually included with Python)
- `tkinterdnd2` (optional, for drag and drop support)

Install the optional dependency:

```bash
pip install tkinterdnd2
```

## Usage

Run the application:

```bash
python file_architecture_checker_min.py
```

Select a Windows executable file or drag and drop it into the application.

## About

This project was created as a small personal project for learning and experimentation.

The application was developed with the assistance of **Claude AI** using a Vibe Coding workflow.

## Developer

**Apex_beat**

## Building for Windows

The application can be compiled into a standalone Windows executable using Nuitka.

Install Nuitka:

```bash
pip install nuitka
```

Build command:

```bash
python -m nuitka --mode=onefile --enable-plugins=tk-inter --windows-console-mode=disable --include-package-data=tkinterdnd2 --product-name="File Architecture Checker" --file-version=1.0.0.0 --output-filename=FileArchitectureChecker.exe file_architecture_checker_min.py
```

**Build requirements:**
- Python
- Nuitka
- A compatible C compiler
- Windows environment

The generated executable will be named `FileArchitectureChecker.exe`.
