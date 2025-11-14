"""MDK Python bindings - Marmot Development Kit"""
try:
    from .mdk_uniffi import *
except ImportError as e:
    from pathlib import Path
    bindings_dir = Path(__file__).parent
    print("Error: Could not import mdk_uniffi. Make sure the bindings are built.")
    print(f"Expected bindings at: {bindings_dir}")
    print(f"Import error: {e}")
    raise

