import math
from collections import Counter

def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon entropy of a string.
    Returns a value between 0.0 and 8.0 (for ASCII).
    High entropy (> 4.5) usually indicates a random secret/key.
    """
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def is_high_entropy(data: str, min_length: int = 16, threshold: float = 4.5) -> bool:
    """
    Heuristic to determine if a string looks like a secret key.
    """
    # 1. Filter out common false positives (paths, urls, sentences)
    if " " in data or "/" in data or "\\" in data:
        return False
    
    # 2. Check length
    if len(data) < min_length:
        return False
        
    # 3. Check Entropy
    return calculate_shannon_entropy(data) > threshold
