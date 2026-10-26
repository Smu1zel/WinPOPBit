import os
import xml.etree.ElementTree as ET
from .patchers import PATCHER_REGISTRY


class BlobItem:
    """Represents a single binary item tracked in badblobs.xml."""
    def __init__(self, blob_id: str, action: str, target: str, description: str = "", filename: str = None, patcher: str = None, enabled: bool = True, options: dict = None):
        self.id = blob_id
        self.action = action # 'patch', 'replace', 'ignore'
        self.target = target # Relative target path inside mounted WIM (e.g. Windows/System32/ntoskrnl.exe)
        self.description = description
        self.filename = filename # Filename inside blobs/ directory (for action="replace")
        self.patcher = patcher # Registered patch handler name (for action="patch")
        self.enabled = enabled
        self.options = options or {}


DEFAULT_BCD_COMMANDS = [
    "/set {default} nointegritychecks Yes",
    "/set {default} bootmenupolicy legacy"
]


class BlobDatabase:
    """Loads and validates badblobs.xml configuration."""
    def __init__(self, xml_path: str, blobs_dir: str):
        self.xml_path = xml_path
        self.blobs_dir = blobs_dir
        self.blobs: dict[str, BlobItem] = {}
        self.bcd_commands: list = []
        self.load()

    def load(self):
        """Parses the badblobs.xml database file."""
        if not os.path.exists(self.xml_path):
            raise FileNotFoundError(f"badblobs configuration not found at: {self.xml_path}")

        tree = ET.parse(self.xml_path)
        root = tree.getroot()

        for blob_elem in root.findall("Blob"):
            b_id = blob_elem.get("id")
            action = blob_elem.get("action", "").lower()
            enabled = blob_elem.get("enabled", "true").lower() == "true"
            patcher = blob_elem.get("patcher")
            filename = blob_elem.get("file")

            target_elem = blob_elem.find("Target")
            target = target_elem.text.strip().replace("\\", "/") if target_elem is not None and target_elem.text else ""

            desc_elem = blob_elem.find("Description")
            desc = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

            # Parse optional key-value parameters for the patcher
            options = {}
            opts_elem = blob_elem.find("Options")
            if opts_elem is not None:
                for opt in opts_elem.findall("Option"):
                    opt_name = opt.get("name")
                    opt_val = opt.get("value")
                    if opt_name:
                        options[opt_name] = opt_val.lower() == "true" if opt_val in ("true", "false") else opt_val

            blob = BlobItem(
                blob_id=b_id,
                action=action,
                target=target,
                description=desc,
                filename=filename,
                patcher=patcher,
                enabled=enabled,
                options=options
            )
            self.blobs[b_id] = blob

        # Parse BCD configuration commands
        bcd_elem = root.find("Bcd")
        if bcd_elem is None:
            bcd_elem = root.find("BcdCommands")

        if bcd_elem is not None:
            self.bcd_commands = []
            for cmd_elem in bcd_elem.findall("Command"):
                if cmd_elem.text and cmd_elem.text.strip():
                    self.bcd_commands.append(cmd_elem.text.strip())
        else:
            self.bcd_commands = list(DEFAULT_BCD_COMMANDS)

    def validate(self, allow_missing: bool = False) -> bool:
        """
        Enforces fail-fast integrity checking:
        - action="replace": Verifies the replacement file exists inside the blobs/ directory.
        - action="patch": Verifies the routine is registered in PATCHER_REGISTRY.
        - action="ignore": Explicitly skipped.
        
        If validation fails, halts execution immediately unless allow_missing=True.
        """
        errors = []
        for b_id, blob in self.blobs.items():
            if not blob.enabled:
                continue

            if blob.action == "replace":
                if not blob.filename:
                    errors.append(f"Blob '{b_id}' action is 'replace' but no 'file' attribute is specified.")
                else:
                    blob_file_path = os.path.join(self.blobs_dir, blob.filename)
                    if not os.path.exists(blob_file_path):
                        errors.append(f"Missing replacement file '{blob.filename}' for blob '{b_id}' in '{self.blobs_dir}'.")
            elif blob.action == "patch":
                if blob.patcher not in PATCHER_REGISTRY:
                    errors.append(f"Blob '{b_id}' specifies unknown patch routine '{blob.patcher}'. Registered patchers: {list(PATCHER_REGISTRY.keys())}")
            elif blob.action == "ignore":
                pass
            else:
                errors.append(f"Blob '{b_id}' has invalid action '{blob.action}'. Must be 'patch', 'replace', or 'ignore'.")

        for cmd in self.bcd_commands:
            if not isinstance(cmd, str) or not cmd.strip():
                errors.append("Invalid or empty BCD command found in badblobs configuration.")

        if errors:
            print("\n[!] BADBLOBS VALIDATION FAILED:")
            for err in errors:
                print(f"  [-] {err}")
            if allow_missing:
                print("[!] Warning: --allow-missing-blobs specified. Proceeding with warnings.\n")
                return True
            return False
        return True
