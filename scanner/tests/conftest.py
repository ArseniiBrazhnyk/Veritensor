import pytest
import shutil
from pathlib import Path
from tests.utils.malware_gen import MalwareGenerator

# Temporary folder for tests
TEST_DIR = Path("tests/temp_artifacts")

@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    """
    Before running all the tests:
    1. Creates the artifacts folder.
    2. Generates viruses (Pickle, PyTorch).
    3. Creates clean files.
    """
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)
    TEST_DIR.mkdir(parents=True)

    #1. Generating viruses
    gen = MalwareGenerator(TEST_DIR)
    gen.generate_all()

    # 2. Create a "clean" file
    clean_file = TEST_DIR / "clean_model.pkl"
    import pickle
    with open(clean_file, "wb") as f:
        pickle.dump({"weights": [1, 2, 3], "name": "safe"}, f)

    yield TEST_DIR

    # Cleaning after the tests (you can comment for debugging)
    # shutil.rmtree(TEST_DIR)

@pytest.fixture
def clean_model_path():
    return TEST_DIR / "clean_model.pkl"

@pytest.fixture
def infected_pickle_path():
    return TEST_DIR / "rce_simple.pkl"

@pytest.fixture
def infected_pytorch_path():
    return TEST_DIR / "model_infected.pt"
