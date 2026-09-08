"""HashGuard v2 -- mining-farm curtailment and health monitoring with a ledger
that neither the operator nor the client can quietly rewrite.

The public surface is small on purpose:

    from hashguard.ledger import GuardedLedger, verify_chain, verify_seal
    from hashguard.attest import SavingsAuditor
    from hashguard.qtmp import QTMPEngine

Everything else is an implementation detail of the agent. The one artefact that
matters to a sceptical reader is ``tools/hashguard_verify.py``, which checks a
statement without importing any of this.
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
