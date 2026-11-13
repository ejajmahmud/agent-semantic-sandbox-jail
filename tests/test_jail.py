"""Unit tests for agent-semantic-sandbox-jail."""
import unittest
from agent_semantic_sandbox_jail.jail import SemanticSandboxJail

class TestSemanticSandboxJail(unittest.TestCase):
    def setUp(self):
        self.jail = SemanticSandboxJail()

    def test_safe_execution(self):
        res = self.jail.execute("result = len([1, 2, 3])")
        self.assertTrue(res.success)
        self.assertEqual(res.output, 3)

    def test_block_os_import(self):
        res = self.jail.execute("import os; x = 1")
        self.assertFalse(res.success)
        self.assertIn("Forbidden module import", res.error)

    def test_block_dunder(self):
        res = self.jail.execute("x = ().__class__.__bases__")
        self.assertFalse(res.success)
        self.assertIn("Forbidden dunder attribute", res.error)

if __name__ == "__main__":
    unittest.main()
