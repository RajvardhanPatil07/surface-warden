"""Measurement harness for surface-warden.

Kept separate from `engine/` on purpose: the engine must never be able to
see the answer key, and the harness must never be able to change a score.
"""
