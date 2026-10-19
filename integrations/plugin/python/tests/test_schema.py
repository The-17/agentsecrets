from __future__ import annotations

import json
import unittest
from pathlib import Path

from agentsecrets_plugin import TOOL_SCHEMA, tool_schema


class SchemaTests(unittest.TestCase):
    def test_python_schema_matches_shared_fixture(self) -> None:
        fixture = Path(__file__).resolve().parents[2] / "schema" / "tool.json"
        self.assertTrue(fixture.is_file(), fixture)
        self.assertEqual(json.loads(fixture.read_text(encoding="utf-8")), TOOL_SCHEMA)

    def test_tool_schema_is_a_defensive_copy(self) -> None:
        schema = tool_schema()
        schema["name"] = "changed"
        self.assertEqual(TOOL_SCHEMA["name"], "agentsecrets_call")


if __name__ == "__main__":
    unittest.main()
