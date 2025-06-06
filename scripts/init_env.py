import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv, find_dotenv, set_key


def get_key_path() -> Path:
    """
    Returns the resolved path to the RSA private key file.

    The path is taken from the environment variable VAULTIC_ENCRYPTION_KEY_PATH,
    or defaults to ~/.vaultic_key.pem.

    Returns:
        Path: Absolute path to the key file.
    """
    default_path = Path(".vaultic/keys/vaultic_key.pem")
    return Path(os.getenv("VAULTIC_ENCRYPTION_KEY_PATH", default_path)).resolve()


def generate_rsa_private_key() -> rsa.RSAPrivateKey:
    """
    Generates a new RSA private key (2048-bit).

    Returns:
        rsa.RSAPrivateKey: The generated private key object.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def save_key_to_file(key: rsa.RSAPrivateKey, path: Path) -> None:
    """
    Saves the given RSA private key to the specified file path in PEM format.

    Args:
        key (rsa.RSAPrivateKey): The RSA private key to save.
        path (Path): The file path where the key should be saved.

    Notes:
        - The file is created with strict 600 permissions on UNIX systems.
        - The directory will be created if it doesn't exist.
    """
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem)

    try:
        os.chmod(path, 0o600)  # Secure file permissions
    except Exception:
        pass  # Ignore permission errors on non-UNIX systems


def setup_pepper_in_env():
    """
    Sets up the VAULTIC_PEPPER environment variable if it doesn't exist.
    """
    dotenv_path = find_dotenv()

    # If .env doesn't exist, try to create it from .env.example
    if not dotenv_path:
        example_path = ".env.example"
        if os.path.exists(example_path):
            with open(example_path, "r") as example, open(".env", "w") as env:
                env.write(example.read())
            dotenv_path = ".env"
        else:
            with open(".env", "w") as env:
                env.write("# Generated by Vaultic init script\n")
            dotenv_path = ".env"

    load_dotenv(dotenv_path)

    # Check if VAULTIC_PEPPER is already set
    if not os.getenv("VAULTIC_PEPPER"):
        # Generate a secure random pepper
        pepper = os.urandom(32).hex()
        set_key(dotenv_path, "VAULTIC_PEPPER", pepper)
        print(f"✅ Generated secure pepper and saved to {dotenv_path}")
    else:
        print("✅ VAULTIC_PEPPER already exists in environment")


def print_key_warning(path: Path) -> None:
    """
    Prints a critical warning about the RSA private key importance.

    Args:
        path (Path): Path to the RSA key file.
    """
    print("\n--- VAULTIC KEY INITIALIZED ---")
    print(f"Key successfully generated and stored at:\n  {path}")
    print("\nIMPORTANT:")
    print("- This private key is essential to decrypt your Vaultic backups.")
    print("- If you lose this key, your encrypted data CANNOT be recovered.")
    print("- No recovery service exists. This is by design.")
    print(
        "- Store this file in a secure location (offline storage, encrypted vault, etc.).\n"
    )
    print(
        "- The VAULTIC_PEPPER environment variable in your .env file is also critical"
    )
    print("  for decryption. Never change it once you've started encrypting files.\n")


def main() -> None:
    """
    Script entry point.

    Checks if a key already exists. If not, generates and stores a new RSA private key.
    Also ensures the VAULTIC_PEPPER environment variable is set.
    """
    # Setup the pepper in the environment
    setup_pepper_in_env()

    # Setup the RSA key
    key_path = get_key_path()

    if key_path.exists():
        print(f"🔐 Key already exists at {key_path}.")
        return

    private_key = generate_rsa_private_key()
    save_key_to_file(private_key, key_path)
    print_key_warning(key_path)


if __name__ == "__main__":
    main()
