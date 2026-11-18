"""Importing this package registers every built-in check."""

from . import ec2, iam, logging_rds, s3  # noqa: F401  (imported for registration side effects)
from .base import Check, all_checks, register

__all__ = ["Check", "all_checks", "register"]
