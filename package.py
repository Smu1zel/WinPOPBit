#!/usr/bin/env python3
"""
================================================================================
WinPOPBit Packaging Script
================================================================================
Compiles winpopbit.py into a standalone onefile Windows executable using Python 3.8
(to make Windows 8 work) and Nuitka, then bundles it into a release zip archive
containing:
  - winpopbit.exe
  - badblobs.xml
  - badblobs_via_u3xxx.xml
  - badblobs_win10_nx.xml
  - LICENSE
  - LICENSE.PEFILE
  - blobs/README.txt
  - README.html (compiled from README.md at runtime)
================================================================================
"""

import os
import sys
import shutil
import subprocess
import argparse
import zipfile
import base64
import mimetypes
import re
from pathlib import Path


def find_python_38() -> str:
    """
    Locates the Python 3.8 executable.
    Checks:
      1. Currently running interpreter (if 3.8)
      2. Windows 'py' launcher (-3.8)
      3. PATH (python3.8, python)
      4. Common Windows installation directories
    """
    if sys.version_info[:2] == (3, 8):
        return sys.executable

    # Try py launcher
    py_launcher = shutil.which("py")
    if py_launcher:
        try:
            res = subprocess.run(
                [py_launcher, "-3.8", "-c", "import sys; print(sys.executable)"],
                capture_output=True,
                text=True,
                check=True,
            )
            exe = res.stdout.strip()
            if exe and os.path.isfile(exe):
                return exe
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    # Try PATH python3.8
    py38_path = shutil.which("python3.8")
    if py38_path:
        return py38_path

    # Try standard Windows install locations
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(local_app_data, r"Programs\Python\Python38\python.exe"),
        r"C:\Python38\python.exe",
        r"C:\Program Files\Python38\python.exe",
    ]
    for cand in candidates:
        if os.path.isfile(cand):
            return cand

    return ""


def check_dependencies(python_exe: str):
    """
    Ensures nuitka and pefile are installed in the target Python 3.8 environment.
    """
    missing = []
    for pkg in ["nuitka", "pefile", "zstandard"]:
        try:
            subprocess.run(
                [python_exe, "-c", f"import {pkg}"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            missing.append(pkg)

    if missing:
        print("[-] Missing required packages in Python 3.8 environment:")
        for m in missing:
            print(f"    - {m}")
        print("\nPlease install them using:")
        print(f"    \"{python_exe}\" -m pip install {' '.join(missing)}")
        sys.exit(1)


def build_executable(python_exe: str, root_dir: Path, build_dir: Path) -> Path:
    """
    Compiles winpopbit.py using Nuitka.
    """
    script_path = root_dir / "winpopbit.py"
    if not script_path.is_file():
        print(f"[-] Error: Script not found: {script_path}")
        sys.exit(1)

    print(f"[*] Compiling {script_path.name} with Nuitka ({python_exe})...")
    
    cmd = [
        python_exe,
        "-m",
        "nuitka",
        "--onefile",
        "--assume-yes-for-downloads",
        "--include-package=pefile",
        "--include-package=src",
        f"--output-dir={build_dir}",
        "--remove-output",
        "--python-flag=-O",
        "--python-flag=no_site",
        "--mingw64",
        "--lto=yes",
        "--windows-uac-admin",
        "--noinclude-setuptools-mode=nofollow",
        "--noinclude-pytest-mode=nofollow",
        str(script_path),
    ]

    print("[*] Running command:")
    print("    " + " ".join(cmd))
    
    res = subprocess.run(cmd, cwd=root_dir)
    if res.returncode != 0:
        print(f"[-] Nuitka build failed with return code {res.returncode}")
        sys.exit(res.returncode)

    exe_path = build_dir / "winpopbit.exe"
    if not exe_path.is_file():
        # Fallback check directly in root_dir or build_dir
        cand = root_dir / "winpopbit.exe"
        if cand.is_file():
            exe_path = cand
        else:
            print(f"[-] Error: Expected executable not found at {exe_path}")
            sys.exit(1)

    print(f"[+] Successfully built: {exe_path} ({exe_path.stat().st_size:,} bytes)")
    return exe_path


def compile_readme_to_html(root_dir: Path) -> Path:
    """
    Compiles README.md into a standalone, styled README.html with:
      - GitHub-style alert callouts (> [!NOTE], > [!IMPORTANT], etc.)
      - Fenced code blocks and tables
      - Inlined base64 images (so the HTML is completely self-contained)
      - Responsive GitHub-like CSS with dark/light mode support
    """
    try:
        import markdown2
    except ImportError:
        print("[-] Warning: 'markdown2' is not installed. Run: pip install markdown2")
        print("    Skipping README.html generation.")
        return None

    readme_md = root_dir / "README.md"
    if not readme_md.is_file():
        print(f"[-] Warning: {readme_md} not found.")
        return None

    print(f"[*] Compiling {readme_md.name} to standalone README.html...")
    content = readme_md.read_text(encoding="utf-8")

    extras = [
        "fenced-code-blocks",
        "alerts",
        "tables",
        "header-ids",
        "cuddled-lists",
        "strike",
        "task_list",
        "code-friendly",
    ]

    body_html = markdown2.markdown(content, extras=extras)

    # Inline local images into base64 data URIs
    def inline_image_match(match):
        img_src = match.group(1)
        if img_src.startswith(("http://", "https://", "data:")):
            return match.group(0)
        img_path = (root_dir / img_src).resolve()
        if img_path.is_file():
            mime_type, _ = mimetypes.guess_type(str(img_path))
            mime_type = mime_type or "image/png"
            b64_data = base64.b64encode(img_path.read_bytes()).decode("ascii")
            print(f"    + Inlined image {img_src} as base64 ({img_path.stat().st_size:,} bytes)")
            return f'src="data:{mime_type};base64,{b64_data}"'
        return match.group(0)

    body_html = re.sub(r'src=["\']([^"\']+)["\']', inline_image_match, body_html)

    # GitHub-like CSS stylesheet
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WinPOPBit - README</title>
<style>
  :root {{
    --bg-color: #0d1117;
    --text-color: #c9d1d9;
    --border-color: #30363d;
    --code-bg: #161b22;
    --link-color: #58a6ff;
    --blockquote-border: #3b434b;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --bg-color: #ffffff;
      --text-color: #24292f;
      --border-color: #d0d7de;
      --code-bg: #f6f8fa;
      --link-color: #0969da;
      --blockquote-border: #d0d7de;
    }}
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background-color: var(--bg-color);
    max-width: 900px;
    margin: 0 auto;
    padding: 2.5rem 1.5rem;
    box-sizing: border-box;
  }}
  a {{ color: var(--link-color); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  h1, h2, h3, h4 {{
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 0.3em;
    margin-top: 1.8em;
    font-weight: 600;
  }}
  h1 {{ font-size: 2rem; margin-top: 0; }}
  h2 {{ font-size: 1.5rem; }}
  h3 {{ font-size: 1.25rem; }}
  p, ul, ol {{ margin-top: 0; margin-bottom: 16px; }}
  ul, ol {{ padding-left: 2em; }}
  li + li {{ margin-top: 0.25em; }}
  hr {{ height: 0.25em; padding: 0; margin: 24px 0; background-color: var(--border-color); border: 0; }}
  pre, code {{ font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }}
  code {{ background-color: var(--code-bg); padding: 0.2em 0.4em; border-radius: 6px; font-size: 85%; }}
  pre {{
    background-color: var(--code-bg);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 1rem;
    overflow-x: auto;
    line-height: 1.45;
  }}
  pre code {{ background-color: transparent; padding: 0; font-size: 85%; }}
  blockquote {{
    margin: 1em 0;
    padding: 0 1em;
    color: #8b949e;
    border-left: 0.25em solid var(--blockquote-border);
  }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  table th, table td {{ border: 1px solid var(--border-color); padding: 6px 13px; }}
  table tr:nth-child(2n) {{ background-color: var(--code-bg); }}
  img {{ max-width: 100%; height: auto; border-radius: 6px; margin: 0.5rem 0; }}
  .alert {{
    padding: 0.75rem 1rem;
    margin: 1rem 0;
    border-left: 4px solid;
    border-radius: 6px;
    background-color: var(--code-bg);
  }}
  .alert em {{
    font-weight: 600;
    font-style: normal;
    display: block;
    margin-bottom: 0.3rem;
    text-transform: uppercase;
    font-size: 0.8rem;
    letter-spacing: 0.5px;
  }}
  .alert p:last-child {{ margin-bottom: 0; }}
  .alert.note {{ border-color: #1f6feb; }}
  .alert.note em {{ color: #58a6ff; }}
  .alert.important {{ border-color: #8957e5; }}
  .alert.important em {{ color: #bc8cff; }}
  .alert.warning {{ border-color: #d29922; }}
  .alert.warning em {{ color: #e3b341; }}
  .alert.tip {{ border-color: #238636; }}
  .alert.tip em {{ color: #3fb950; }}
  .alert.caution {{ border-color: #da3633; }}
  .alert.caution em {{ color: #f85149; }}
</style>
</head>
<body>
{body_html}
</body>
</html>
"""

    out_path = root_dir / "README.html"
    out_path.write_text(full_html, encoding="utf-8")
    print(f"[+] Successfully generated standalone {out_path.name} ({out_path.stat().st_size:,} bytes)")
    return out_path


def create_release_zip(root_dir: Path, exe_path: Path, output_zip: Path):
    """
    Packages the executable and required assets into a zip file.
    """
    readme_html = compile_readme_to_html(root_dir)

    required_files = [
        (exe_path, "winpopbit.exe"),
        (root_dir / "badblobs.xml", "badblobs.xml"),
        (root_dir / "badblobs_via_u3xxx.xml", "badblobs_via_u3xxx.xml"),
        (root_dir / "badblobs_win10_nx.xml", "badblobs_win10_nx.xml"),
        (root_dir / "LICENSE", "LICENSE"),
        (root_dir / "LICENSE.PEFILE", "LICENSE.PEFILE"),
        (root_dir / "README.md", "README.md"),
        (root_dir / "blobs" / "README.txt", "blobs/README.txt"),
    ]

    if readme_html and readme_html.is_file():
        required_files.append((readme_html, "README.html"))

    for file_path, arcname in required_files:
        if not file_path.is_file():
            print(f"[-] Error: Required file missing for package: {file_path}")
            sys.exit(1)

    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()

    print(f"[*] Creating release archive: {output_zip}...")
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path, arcname in required_files:
            print(f"    + Adding {arcname} ({file_path.stat().st_size:,} bytes)")
            zf.write(file_path, arcname=arcname)

    print(f"[+] Release package created successfully: {output_zip} ({output_zip.stat().st_size:,} bytes)")


def main():
    parser = argparse.ArgumentParser(description="Build and package WinPOPBit into a release zip archive.")
    parser.add_argument(
        "-o",
        "--output",
        default="dist/winpopbit-release.zip",
        help="Path for output zip file (default: dist/winpopbit-release.zip)",
    )
    parser.add_argument(
        "--build-dir",
        default="build",
        help="Temporary build directory for Nuitka output (default: build)",
    )
    parser.add_argument(
        "--python",
        default=None,
        help="Explicit path to Python 3.8 executable",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip Nuitka compilation and package existing winpopbit.exe from build-dir",
    )
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parent
    build_dir = (root_dir / args.build_dir).resolve()
    output_zip = (root_dir / args.output).resolve()

    if args.skip_build:
        exe_path = build_dir / "winpopbit.exe"
        if not exe_path.is_file():
            exe_path = root_dir / "winpopbit.exe"
        if not exe_path.is_file():
            print(f"[-] Error: --skip-build specified but executable not found at {build_dir / 'winpopbit.exe'}")
            sys.exit(1)
    else:
        python_exe = args.python or find_python_38()
        if not python_exe:
            print("[-] Error: Python 3.8 executable could not be found.")
            print("    Please install Python 3.8 or specify path using --python <path_to_python.exe>")
            sys.exit(1)

        print(f"[+] Using Python 3.8: {python_exe}")
        check_dependencies(python_exe)
        exe_path = build_executable(python_exe, root_dir, build_dir)

    create_release_zip(root_dir, exe_path, output_zip)


if __name__ == "__main__":
    main()
