import io
import zipfile
import pickle
from veritensor.engines.static.pickle_engine import scan_pickle_stream

def test_scan_pytorch_zip_recursive():
    """
    Checks that the engine can look inside Zip archives. (PyTorch .bin/.pt).
    """

    class Evil:
        def __reduce__(self):
            return (eval, ("print('pwned')",))
    
    evil_bytes = pickle.dumps(Evil())


    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("archive/data.pkl", evil_bytes)
        z.writestr("archive/version", "3")
    
    zip_bytes = buffer.getvalue()


    threats = scan_pickle_stream(zip_bytes)
    

    assert len(threats) > 0
    assert any("eval" in t for t in threats)
