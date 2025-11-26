import hashlib
import json
import os

# --- Configuration ---
HASHES_FILE = "hashes.json"


def compute_hashes(filepath):
    """Computes SHA-256, SHA-1, and MD5 hashes for a given file."""

    # Initialize hash objects
    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    md5_hash = hashlib.md5()

    try:
        # Open file in binary read mode ('rb')
        with open(filepath, 'rb') as f:
            # Read file in chunks (improves performance for large files)
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                sha1_hash.update(byte_block)
                md5_hash.update(byte_block)

        # Return the hexadecimal digests
        return {
            "SHA-256": sha256_hash.hexdigest(),
            "SHA-1": sha1_hash.hexdigest(),
            "MD5": md5_hash.hexdigest()
        }
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None


def store_hashes(filepath, hashes):
    """Stores the computed hashes in a JSON file."""
    try:
        with open(HASHES_FILE, 'w') as f:
            # Store the hashes in the JSON file
            json.dump({filepath: hashes}, f, indent=4)
        print(f"✅ Hashes for **{filepath}** stored successfully in **{HASHES_FILE}**.")
    except Exception as e:
        print(f"Error storing hashes: {e}")


def check_integrity(filepath):
    """Compares the current file's hash against the stored hash."""
    print(f"\n--- Integrity Check for {filepath} ---")

    # 1. Load stored hashes
    if not os.path.exists(HASHES_FILE):
        print(f"❌ Check Failed: Hash file **{HASHES_FILE}** not found.")
        return False

    try:
        with open(HASHES_FILE, 'r') as f:
            stored_data = json.load(f)

        # Get the stored hashes for the specific file
        if filepath not in stored_data:
            print(f"❌ Check Failed: No stored hash data found for **{filepath}** in **{HASHES_FILE}**.")
            return False

        stored_hashes = stored_data[filepath]
        print(f"ℹ️ Loaded stored hashes from {HASHES_FILE}.")

    except json.JSONDecodeError:
        print(f"❌ Check Failed: Invalid JSON format in **{HASHES_FILE}**.")
        return False

    # 2. Compute current hashes
    current_hashes = compute_hashes(filepath)
    if current_hashes is None:
        return False  # Error was already printed in compute_hashes

    # 3. Compare hashes
    integrity_pass = True
    print("\n| Algorithm | Stored Hash | Current Hash | Status |")
    print("| :--- | :--- | :--- | :--- |")

    for algo, stored_hash in stored_hashes.items():
        current_hash = current_hashes.get(algo, "N/A")

        if stored_hash == current_hash:
            status = "PASS"
            symbol = "✅"
        else:
            status = "**FAIL (WARNING)**"
            symbol = "🚨"
            integrity_pass = False  # Set flag to False if ANY hash fails

        print(f"| {algo} | {stored_hash} | {current_hash} | {symbol} {status} |")

    # 4. Final Result
    if integrity_pass:
        print(f"\n✨ **INTEGRITY CHECK RESULT: PASS** - The file {filepath} has not been tampered with.")
    else:
        print(
            f"\n⚠️ **INTEGRITY CHECK RESULT: FAIL - WARNING!** - The file {filepath} has been modified since the hashes were recorded.")

    return integrity_pass


# --- Main Execution Flow ---
if __name__ == "__main__":
    ORIGINAL_FILE = "original.txt"
    TAMPERED_FILE = "tampered.txt"

    # --- Task 1: Compute and Store Hashes ---
    print("--- Task 1: Computing and Storing Initial Hashes ---")

    # Check if the original file exists before proceeding
    if not os.path.exists(ORIGINAL_FILE):
        print(f"🛑 Error: Please create the file **{ORIGINAL_FILE}** before running the script.")
    else:
        initial_hashes = compute_hashes(ORIGINAL_FILE)
        if initial_hashes:
            store_hashes(ORIGINAL_FILE, initial_hashes)

            # --- Task 2 (Initial Check): Check integrity of the *original* file ---
            # This confirms the baseline works (should pass)
            print("\n--- Initial Baseline Check (Should Pass) ---")
            check_integrity(ORIGINAL_FILE)

            # --- Task 3: Simulate Tampering and Re-check Integrity ---
            print("\n" + "=" * 50)
            print("--- Task 3: Tampering Simulation ---")
            print(f"Please modify the content of **{ORIGINAL_FILE}** and rename it to **{TAMPERED_FILE}**")
            print("Or, simply copy and modify the file now to see the check fail.")
            input("Press Enter after you have created/modified **tampered.txt**...")

            # Use the TAMPERED_FILE for the final integrity check
            check_integrity(TAMPERED_FILE)