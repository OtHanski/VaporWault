"""
test_cluster.py — integration tests for cluster replication.

All tests in this module require a two-server setup and are gated by the
VW_TEST_CLUSTER=1 environment variable.  Run with:

    VW_TEST_CLUSTER=1 pytest tests/integration/test_cluster.py -v

Without that variable the entire module is skipped.
"""

import os
import pytest

pytestmark = pytest.mark.cluster


@pytest.fixture(autouse=True)
def require_cluster_env():
    """Skip all tests in this module unless VW_TEST_CLUSTER=1 is set."""
    if not os.environ.get("VW_TEST_CLUSTER"):
        pytest.skip("VW_TEST_CLUSTER=1 not set")


# ── Placeholder tests ─────────────────────────────────────────────────────────
#
# Full cluster tests require starting a second vapourwaultd instance with a
# cluster_port configured, authenticating it as a replica via NODE_HELLO, and
# then verifying that oplog entries propagate.  This infrastructure will be
# added in a dedicated cluster integration task.

def test_cluster_placeholder():
    """
    Placeholder: cluster tests pass trivially when the cluster environment is
    present.  Real scenarios (primary→replica replication, watermark tracking)
    are implemented in a later phase.
    """
    assert True
