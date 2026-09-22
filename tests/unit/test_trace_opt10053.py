from pathlib import Path

from autodiag.trace.models import TraceKind
from autodiag.trace.opt10053 import parse_opt10053


def test_parse_10053(fixtures_dir: Path) -> None:
    opt = parse_opt10053((fixtures_dir / "23ai/traces/AUTODIAG_10053.trc").read_text())
    assert opt.kind is TraceKind.OPTIMIZER
    assert "optimizer_mode" in opt.parameters
    assert len(opt.parameters) > 50
    names = {t.name for t in opt.table_stats}
    assert {"ORDERS", "ORDER_ITEMS"} <= names
    orders = next(t for t in opt.table_stats if t.name == "ORDERS")
    assert orders.rows == 100000 and orders.blocks and orders.blocks > 0
    assert any(i.table == "ORDERS" for i in opt.index_stats)
    assert opt.access_paths and all(a.table for a in opt.access_paths)
    assert opt.final_cost is not None and opt.final_cost > 0
    assert opt.join_orders >= 1
    assert opt.sql_text and "autodiag_10053" in opt.sql_text
    assert "value=" not in opt.model_dump_json()
