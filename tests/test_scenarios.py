import pytest

from tests.scenarios import SCENARIOS


@pytest.mark.parametrize("tid,scenario,inp,expected,check", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_scenario(tid, scenario, inp, expected, check, tmp_path):
    actual, passed = check(tmp_path)
    assert passed, f"{tid} {scenario}: expected {expected}; actual {actual}"
