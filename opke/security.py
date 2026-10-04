"""Security utilities for OPKE: memory wiping and secure input handling."""

import getpass
import sys
from typing import Union


def zero_memory(buf: Union[bytearray, memoryview, list]) -> None:
    """Overwrites mutable memory buffers with zeros to prevent key leakage.

    Args:
        buf: A mutable buffer (bytearray, memoryview, or list of ints) to be zeroed.
    """
    if isinstance(buf, (bytearray, memoryview)):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, list):
        for i in range(len(buf)):
            buf[i] = 0


def prompt_passphrase(
    confirm: bool = False,
    prompt: str = "Enter passphrase: ",
    confirm_prompt: str = "Confirm passphrase: ",
) -> bytearray:
    """Safely prompts for a passphrase without echoing characters to terminal.

    Args:
        confirm: If True, asks user to type the passphrase a second time to verify.
        prompt: Initial prompt string.
        confirm_prompt: Confirmation prompt string.

    Returns:
        bytearray: UTF-8 encoded passphrase as a mutable bytearray that can be zeroed.

    Raises:
        ValueError: If passphrases do not match or if an empty passphrase is provided.
    """
    p1 = getpass.getpass(prompt)
    if not p1:
        raise ValueError("Passphrase cannot be empty.")

    if confirm:
        p2 = getpass.getpass(confirm_prompt)
        if p1 != p2:
            # Overwrite local variables before raising
            del p1, p2
            raise ValueError("Passphrases do not match.")
        del p2

    result = bytearray(p1.encode("utf-8"))
    del p1
    return result


def prompt_secret(prompt: str = "Enter secret plaintext: ") -> bytearray:
    """Prompts the user for secret plaintext if not provided via pipe/file.

    If running interactively in a TTY, attempts to prompt securely or read input.
    """
    if sys.stdin.isatty():
        s = getpass.getpass(f"{prompt} (hidden): ")
        if not s:
            raise ValueError("Secret cannot be empty.")
        res = bytearray(s.encode("utf-8"))
        del s
        return res
    else:
        raw = sys.stdin.buffer.read()
        # Strip trailing newline if any
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n") or raw.endswith(b"\r"):
            raw = raw[:-1]
        if not raw:
            raise ValueError("Secret cannot be empty.")
        return bytearray(raw)
