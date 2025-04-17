"""
Security Utilities - Functions related to secure file operations.
"""
import os
import platform
import random
from pathlib import Path
from typing import Optional

def is_rotational(path: Path) -> bool:
    """
    Check if the given path is on a rotational drive (HDD).

    Args:
        path (Path): Path to check

    Returns:
        bool: True if the path is on a rotational drive, False otherwise
    """
    if platform.system() == "Linux":
        try:
            # Get the device where the file is located
            dev = os.stat(path).st_dev
            dev_name = get_block_device_from_dev(dev)
            
            if dev_name:
                # Check if the device is rotational
                rot_path = f"/sys/block/{dev_name}/queue/rotational"
                if os.path.exists(rot_path):
                    with open(rot_path, 'r') as f:
                        return f.read().strip() == '1'
        except Exception:
            pass
            
    # Default to assuming rotational (more secure erase)
    return True

def get_block_device_from_dev(dev: int) -> Optional[str]:
    """
    Get the block device name from a device number on Linux.

    Args:
        dev (int): Device number

    Returns:
        Optional[str]: Block device name or None if not found
    """
    try:
        # This is Linux-specific
        dev_major = os.major(dev)
        dev_minor = os.minor(dev)
        
        for device in os.listdir('/sys/block'):
            with open(f'/sys/block/{device}/dev', 'r') as f:
                major_minor = f.read().strip()
                major, minor = map(int, major_minor.split(':'))
                
                if major == dev_major:
                    # For the root device itself
                    if minor == dev_minor:
                        return device
                    
                    # For partitions of the device
                    for partition in os.listdir(f'/sys/block/{device}'):
                        if partition.startswith(device) and os.path.isdir(f'/sys/block/{device}/{partition}'):
                            partition_path = f'/sys/block/{device}/{partition}/dev'
                            if os.path.exists(partition_path):
                                with open(partition_path, 'r') as f:
                                    part_major_minor = f.read().strip()
                                    part_major, part_minor = map(int, part_major_minor.split(':'))
                                    if part_major == dev_major and part_minor == dev_minor:
                                        return device
    except Exception:
        pass
    
    return None

def secure_delete(path: Path, passes: int = 3) -> bool:
    """
    Securely delete a file by overwriting it multiple times before unlinking.
    
    Args:
        path (Path): Path to the file to delete
        passes (int): Number of overwrite passes (default: 3)
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not path.exists() or not path.is_file():
        return False
        
    try:
        # Get file size
        file_size = path.stat().st_size
        
        # Open file for binary writing
        with open(path, 'r+b') as f:
            # Multiple overwrite passes
            for i in range(passes):
                # Seek to beginning of file
                f.seek(0)
                
                # Different patterns for each pass
                if i == 0:
                    # First pass: all zeros
                    pattern = b'\x00'
                elif i == 1:
                    # Second pass: all ones
                    pattern = b'\xFF'
                else:
                    # Subsequent passes: random data
                    pattern = bytes([random.randint(0, 255) for _ in range(min(4096, file_size))])
                
                # Write pattern in chunks
                bytes_remaining = file_size
                while bytes_remaining > 0:
                    if len(pattern) > bytes_remaining:
                        f.write(pattern[:bytes_remaining])
                        bytes_remaining = 0
                    else:
                        f.write(pattern)
                        bytes_remaining -= len(pattern)
                
                # Flush to disk
                f.flush()
                os.fsync(f.fileno())
        
        # Finally unlink (delete) the file
        path.unlink()
        return True
        
    except Exception:
        # If any error occurs, try regular delete
        try:
            path.unlink()
            return True
        except Exception:
            return False

def generate_secure_passphrase(length: int = 16, include_special: bool = True) -> str:
    """
    Generate a cryptographically secure random passphrase.
    
    Args:
        length (int): Length of the passphrase (default: 16)
        include_special (bool): Include special characters (default: True)
        
    Returns:
        str: The generated passphrase
    """
    import secrets
    import string
    
    # Character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = string.punctuation if include_special else ""
    
    # Ensure at least one character from each set
    passphrase = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits)
    ]
    
    if include_special:
        passphrase.append(secrets.choice(special))
    
    # Fill remaining length with random characters from all sets
    all_chars = lowercase + uppercase + digits + special
    passphrase.extend(secrets.choice(all_chars) for _ in range(length - len(passphrase)))
    
    # Shuffle the passphrase
    secrets.SystemRandom().shuffle(passphrase)
    
    return ''.join(passphrase)