import os
import platform
import sys
import time
import urllib.request
import tarfile
import zipfile
import tempfile
import shutil
import stat
import json

GITHUB_REPO = "The-17/agentsecrets"

def _get_version():
    try:
        from importlib.metadata import version
        return version("agentsecrets-cli")
    except Exception:
        pass
    try:
        import re
        pyproject = os.path.join(os.path.dirname(__file__), "..", "..", "pyproject.toml")
        if os.path.exists(pyproject):
            with open(pyproject, "r", encoding="utf-8") as f:
                m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', f.read())
                if m:
                    return m.group(1)
    except Exception:
        pass
    return "dev"

VERSION = _get_version()

def compare_versions(v1, v2):
    p1 = [int(x) for x in (v1 or "").lstrip("v").split(".") if x.isdigit()]
    p2 = [int(x) for x in (v2 or "").lstrip("v").split(".") if x.isdigit()]
    while len(p1) < 3: p1.append(0)
    while len(p2) < 3: p2.append(0)
    for i in range(3):
        if p1[i] < p2[i]: return -1
        if p1[i] > p2[i]: return 1
    return 0

def check_update_notice():
    try:
        cache_file = os.path.expanduser("~/.agentsecrets/pypi_update_cache.json")
        cache = None
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r") as f:
                    cache = json.load(f)
            except Exception:
                pass

        now = int(time.time())
        if cache and cache.get("latest_version") and compare_versions(cache["latest_version"], VERSION) > 0:
            sys.stderr.write(
                f"\n\033[33mUpdate available:\033[0m {VERSION} -> \033[32m{cache['latest_version']}\033[0m\n"
                f"Run: \033[36mpip install --upgrade agentsecrets-cli\033[0m to update\n\n"
            )

        if not cache or not cache.get("last_checked") or now - cache["last_checked"] > 86400:
            try:
                req = urllib.request.Request(
                    f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                    headers={"User-Agent": "agentsecrets-pypi"}
                )
                with urllib.request.urlopen(req, timeout=2.0) as response:
                    data = json.loads(response.read().decode())
                    latest = data.get("tag_name", "").lstrip("v")
                    if latest:
                        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
                        with open(cache_file, "w") as f:
                            json.dump({"last_checked": now, "latest_version": latest}, f)
            except Exception:
                pass
    except Exception:
        pass

def cleanup_old_binaries(base_dir, current_binary_path):
    try:
        if not os.path.exists(base_dir):
            return
        prefix = "agentsecrets.exe_" if platform.system().lower() == "windows" else "agentsecrets_"
        for fname in os.listdir(base_dir):
            full_path = os.path.join(base_dir, fname)
            if fname.startswith(prefix) and full_path != current_binary_path:
                try:
                    os.remove(full_path)
                except Exception:
                    pass
    except Exception:
        pass

def get_platform_info():
    """Returns a tuple of (os_name, arch_name) compatible with GoReleaser naming."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_name = system
    if system == "darwin":
        os_name = "darwin"
    elif system == "windows":
        os_name = "windows"
    elif system == "linux":
        os_name = "linux"
    
    arch_name = "amd64"
    if machine in ["x86_64", "amd64"]:
        arch_name = "amd64"
    elif machine in ["arm64", "aarch64"]:
        arch_name = "arm64"
    elif machine in ["i386", "i686", "x86"]:
        arch_name = "386"
    
    return os_name, arch_name

def ensure_binary():
    """
    Check if the agentsecrets binary exists for the current platform.
    If not, download it from GitHub Releases.
    Returns the absolute path to the binary.
    """
    check_update_notice()
    os_name, arch_name = get_platform_info()
    
    base_dir = os.path.expanduser("~/.agentsecrets/bin")
    os.makedirs(base_dir, exist_ok=True)
    
    binary_name = "agentsecrets"
    if os_name == "windows":
        binary_name += ".exe"
    
    binary_path = os.path.join(base_dir, f"{binary_name}_{VERSION}")
    
    if os.path.exists(binary_path):
        return binary_path
    
    sys.stderr.write(f"AgentSecrets binary not found. Downloading version {VERSION} for {os_name}/{arch_name}...\n")
    
    ext = "tar.gz" if os_name != "windows" else "zip"
    asset_name = f"agentsecrets_{VERSION}_{os_name}_{arch_name}.{ext}"
    url = f"https://github.com/{GITHUB_REPO}/releases/download/v{VERSION}/{asset_name}"
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, asset_name)
            
            with urllib.request.urlopen(url) as response, open(archive_path, 'wb') as out_file:
                shutil.copyfileobj(response, out_file)
            
            if ext == "tar.gz":
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=tmpdir)
            else:
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(tmpdir)
            
            extracted_binary = os.path.join(tmpdir, binary_name)
            if not os.path.exists(extracted_binary):
                for root, dirs, files in os.walk(tmpdir):
                    if binary_name in files:
                        extracted_binary = os.path.join(root, binary_name)
                        break
            
            shutil.move(extracted_binary, binary_path)
            
            st = os.stat(binary_path)
            os.chmod(binary_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

            # Pre-register with keychain-auth if available
            import subprocess
            kc = shutil.which("keychain-auth")
            if kc:
                try:
                    subprocess.run(
                        [kc, "register", binary_path],
                        timeout=5, capture_output=True,
                    )
                except Exception:
                    pass
            
        cleanup_old_binaries(base_dir, binary_path)
        return binary_path
        
    except Exception as e:
        system_binary = shutil.which("agentsecrets")
        if system_binary and not system_binary.endswith(".py") and "site-packages" not in system_binary:
            return system_binary
            
        raise Exception(
            f"Failed to download AgentSecrets binary from {url}.\n"
            f"Error: {e}\n\n"
            "TIP: Please verify your internet connection or install directly via Homebrew:\n"
            "  brew install The-17/tap/agentsecrets"
        )
