# Copyright 2026 Veritensor Security
# PII Scanner wrapper around Microsoft Presidio (NLP-based)

import logging
from typing import List

logger = logging.getLogger(__name__)

try:
    from presidio_analyzer import AnalyzerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

class PIIScanner:
    _engine = None
    _init_error = None

    @classmethod
    def get_engine(cls):
        """
        Lazy initialization of the heavy ML model.
        Only runs if the user installed 'veritensor[pii]'.
        """
        if not PRESIDIO_AVAILABLE:
            return None

        if cls._engine is None and cls._init_error is None:
            try:
                # Load NLP engine. Requires: python -m spacy download en_core_web_lg
                # Score threshold 0.4 filters out weak matches
                cls._engine = AnalyzerEngine(default_score_threshold=0.4)
            except OSError as e:
                if "Can't find model" in str(e):
                    cls._init_error = (
                        "Spacy model missing. Run: python -m spacy download en_core_web_lg"
                    )
                else:
                    cls._init_error = str(e)
                logger.warning(f"PII Engine Init Failed: {cls._init_error}")
            except Exception as e:
                cls._init_error = str(e)
                logger.warning(f"PII Engine Init Failed: {e}")
        
        return cls._engine

    @staticmethod
    def scan(text: str) -> List[str]:
        """
        Scans text for PII using ML. Returns list of threats.
        """
        if not PRESIDIO_AVAILABLE:
            return []

        engine = PIIScanner.get_engine()
        if not engine:
            return []

        threats = []
        try:
            # Limit text length to avoid hanging on massive logs (100KB limit)
            text_sample = text[:100000] 
            results = engine.analyze(text=text_sample, language='en')
            
            for res in results:
                # Filter only confident matches
                if res.score >= 0.5:
                    entity = text_sample[res.start:res.end]
                    # Masking: Jo** instead of John (Privacy in logs)
                    masked = entity[:2] + "*" * (len(entity)-2) if len(entity) > 2 else "***"
                    threats.append(f"HIGH: PII Leak ({res.entity_type}): {masked}")
                    
        except Exception as e:
            logger.debug(f"PII Scan error: {e}")
            
        return threats
