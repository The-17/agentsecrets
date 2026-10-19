from __future__ import annotations

import importlib
import importlib.util
import sys
import unittest

ADAPTERS = (
    ("langchain", "langchain_core"),
    ("crewai", "crewai"),
    ("autogen", "autogen_core"),
    ("llamaindex", "llama_index.core"),
)


class AdapterImportTests(unittest.TestCase):
    def test_core_package_does_not_import_frameworks(self) -> None:
        imported = [name for _, name in ADAPTERS if name in sys.modules]
        self.assertEqual(imported, [])

    def test_missing_extras_fail_with_install_guidance(self) -> None:
        for module_name, package_name in ADAPTERS:
            try:
                spec = importlib.util.find_spec(package_name)
            except ModuleNotFoundError:
                spec = None
            if spec is not None:
                continue
            module = importlib.import_module(f"agentsecrets_plugin.{module_name}")
            with self.subTest(module=module_name):
                with self.assertRaises(ImportError) as ctx:
                    module.make_tool(object())
                self.assertIn("pip install", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
