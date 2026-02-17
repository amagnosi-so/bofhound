import os
import platform
import subprocess


def find_7z_executable():
    """Find 7z executable on the system"""
    system = platform.system()

    if system == "Windows":
        # Common 7-Zip installation paths on Windows
        possible_paths = [
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
            os.path.expandvars(r"%ProgramFiles%\7-Zip\7z.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\7-Zip\7z.exe"),
        ]

        for path in possible_paths:
            if os.path.isfile(path):
                return path

        # Try PATH as fallback
        try:
            subprocess.run(['7z', '--help'], capture_output=True, check=True)
            return '7z'
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        return None
    else:
        # Linux/Unix - should be in PATH
        try:
            # Try 7z first
            subprocess.run(['7z', '--help'], capture_output=True, check=True)
            return '7z'
        except (subprocess.CalledProcessError, FileNotFoundError):
            try:
                # Try 7za (alternative package name)
                subprocess.run(['7za', '--help'], capture_output=True, check=True)
                return '7za'
            except (subprocess.CalledProcessError, FileNotFoundError):
                return None
