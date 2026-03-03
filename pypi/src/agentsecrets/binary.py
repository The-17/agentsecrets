import os
import platform
import sys
import urllib.request
import tarfile
import zipfile
import tempfile
import shutil
import stat

# Try to get the version from package metadata, fallback to a hardcoded version
def _get_version():
    try:
        from importlib.metadata import version, PackageNotFoundError
    except ImportError:  # Python < 3.8
        try:
            from pkg_resources import get_distribution, DistributionNotFound
        except ImportError:
            # Fallback if pkg_resources is also not available
            return "1.1.0"

        try:
            return get_distribution("agentsecrets").version
        except DistributionNotFound:
            # Fallback if package not found
            return "1.1.0"

    try:
        return version("agentsecrets")
    except PackageNotFoundError:
        # Fallback if package not found
        return "1.1.0"

VERSION = _get_version()
GITHUB_REPO = "The-17/agentsecrets"

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
    os_name, arch_name = get_platform_info()
    
    # Store binaries in a hidden directory in the user's home or package dir
    # For PyPI, it's easier to store in the package directory itself if we have permissions,
    # or ~/.agentsecrets/bin
    base_dir = os.path.expanduser("~/.agentsecrets/bin")
    os.makedirs(base_dir, exist_ok=True)
    
    binary_name = "agentsecrets"
    if os_name == "windows":
        binary_name += ".exe"
    
    # Versioned binary path
    binary_path = os.path.join(base_dir, f"{binary_name}_{VERSION}")
    
    if os.path.exists(binary_path):
        return binary_path
    
    # Need to download
    print(f"AgentSecrets binary not found. Downloading version {VERSION} for {os_name}/{arch_name}...", file=sys.stderr)
    
    ext = "tar.gz" if os_name != "windows" else "zip"
    # Match the naming template in .goreleaser.yaml: {{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}
    # Note: GoReleaser naming is case-sensitive and uses specific strings.
    # Looking at .goreleaser.yaml: name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    # GoReleaser Os: linux, darwin, windows
    # GoReleaser Arch: amd64, arm64
    
    asset_name = f"agentsecrets_{VERSION}_{os_name}_{arch_name}.{ext}"
    url = f"https://github.com/{GITHUB_REPO}/releases/download/v{VERSION}/{asset_name}"
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, asset_name)
            
            # Download the archive
            with urllib.request.urlopen(url) as response, open(archive_path, 'wb') as out_file:
                shutil.copyfileobj(response, out_file)
            
            # Extract
            if ext == "tar.gz":
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=tmpdir)
            else:
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(tmpdir)
            
            # Move the binary to the final location
            # The archive contains the binary in the root
            extracted_binary = os.path.join(tmpdir, binary_name)
            if not os.path.exists(extracted_binary):
                # Maybe it's inside a folder? goreleaser usually puts it in root by default unless configured otherwise
                # Let's check all files in tmpdir
                for root, dirs, files in os.walk(tmpdir):
                    if binary_name in files:
                        extracted_binary = os.path.join(root, binary_name)
                        break
            
            shutil.move(extracted_binary, binary_path)
            
            # Ensure executable
            st = os.stat(binary_path)
            os.chmod(binary_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            
        return binary_path
        
    except Exception as e:
        # Fallback to checking if a real binary is already in the PATH
        system_binary = shutil.which("agentsecrets")
        # Ensure we don't pick up this Python wrapper itself (infinite loop)
        if system_binary and not system_binary.endswith(".py") and "site-packages" not in system_binary:
            return system_binary
            
        raise Exception(
            f"Failed to download AgentSecrets binary from {url}.\n"
            f"Error: {e}\n\n"
            "TIP: This usually happens if the version hasn't been released on GitHub yet.\n"
            "Please run: git tag v1.0.0 && git push origin v1.0.0\n"
            "This will trigger the build that makes this binary available."
        )
