import pytest

from autodiag.diagnose.performance import counter_deltas


def row(value, startup="2026-01-01", instance=1):
    return {
        "INST_ID": instance,
        "STARTUP_TIME": startup,
        "CATEGORY": "time_us",
        "METRIC": "DB time",
        "VALUE": value,
    }


def test_deltas_not_lifetime_totals():
    rows, omitted = counter_deltas([row(100000000)], [row(105000000)], 5)
    assert rows[0]["PER_SECOND"] == 1
    assert sum(omitted.values()) == 0


def test_restarts_resets_and_missing_counters_are_not_rates():
    rows, omitted = counter_deltas([row(100)], [row(10), row(200, "new"), row(200, instance=2)], 5)
    assert rows == [] and omitted == {"new": 1, "reset": 1, "restart": 1}


@pytest.mark.parametrize(
    "category,expected",
    [("time_us", 1), ("wait_us", 1), ("stat_count", 1000000), ("wait_count", 1000000)],
)
def test_counter_units_and_new_metrics(category, expected):
    before = {**row(100), "CATEGORY": category}
    after = {**row(5000100), "CATEGORY": category}
    new = {**after, "METRIC": "first observed event"}
    rows, omitted = counter_deltas([before], [after, new], 5)
    assert len(rows) == 1 and rows[0]["PER_SECOND"] == expected
    assert omitted == {"new": 1, "reset": 0, "restart": 0}


def test_invalid_interval():
    with pytest.raises(ValueError):
        counter_deltas([], [], 0)
