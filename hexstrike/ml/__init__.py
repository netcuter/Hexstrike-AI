"""
Hexstrike ML - Machine Learning Enhancement Module

Provides ML-powered features to increase vulnerability detection accuracy:
- False Positive Filter (Gradient Boosting)
- Intelligent Payload Generation (Markov Chain)
- Adaptive Learning (SQLite + auto-retrain)

Usage:
    from hexstrike.ml import MLEngine

    ml = MLEngine()
    filtered_results = ml.filter_false_positives(scan_results)
    new_payloads = ml.generate_payloads(successful_payloads)
    ml.learn_from_scan(scan_results)
"""

__version__ = "1.0.0"
__author__ = "Hexstrike AI Team"

from .ml_engine import MLEngine
from .fp_filter import FalsePositiveFilter
from .payload_generator import PayloadGenerator
from .adaptive_learner import AdaptiveLearner

__all__ = [
    'MLEngine',
    'FalsePositiveFilter',
    'PayloadGenerator',
    'AdaptiveLearner',
]
