from __future__ import annotations

import unittest

from agentsecrets_plugin import CallRequest, CallResult, InvalidRequest, parse_injections


class ParseInjectionsTests(unittest.TestCase):
    def test_all_styles(self) -> None:
        parsed = parse_injections(
            {
                "bearer": "A_KEY",
                "basic": "B_KEY",
                "header:X-Api-Key": "C_KEY",
                "query:api_key": "D_KEY",
                "body:auth.token": "E_KEY",
                "form:api_key": "F_KEY",
            }
        )
        by_style = {item.style: item for item in parsed}
        self.assertEqual(by_style["bearer"].target, "")
        self.assertEqual(by_style["header"].target, "X-Api-Key")
        self.assertEqual(by_style["body"].target, "auth.token")
        self.assertEqual(by_style["bearer"].key, "A_KEY")

    def test_rejects_empty(self) -> None:
        with self.assertRaises(InvalidRequest):
            parse_injections({})

    def test_rejects_target_on_untargeted_style(self) -> None:
        with self.assertRaises(InvalidRequest):
            parse_injections({"bearer:foo": "A_KEY"})

    def test_rejects_missing_target(self) -> None:
        with self.assertRaises(InvalidRequest):
            parse_injections({"header:": "A_KEY"})

    def test_rejects_unknown_style(self) -> None:
        with self.assertRaises(InvalidRequest):
            parse_injections({"magic": "A_KEY"})

    def test_rejects_empty_key_name(self) -> None:
        with self.assertRaises(InvalidRequest):
            parse_injections({"bearer": "  "})

    def test_rejects_non_string_values(self) -> None:
        with self.assertRaises(InvalidRequest):
            parse_injections({"bearer": None})  # type: ignore[dict-item]


class CallRequestTests(unittest.TestCase):
    def test_normalizes_method_and_injection_spec(self) -> None:
        request = CallRequest(
            url="https://api.example.com",
            method="post",
            injections={"Header:X-Api-Key": "KEY"},
        )
        self.assertEqual(request.method, "POST")
        self.assertEqual(dict(request.injections), {"header:X-Api-Key": "KEY"})

    def test_prepared_sets_json_content_type(self) -> None:
        request = CallRequest(
            url="https://api.example.com",
            injections={"bearer": "KEY"},
            body='{"hello":"world"}',
        ).prepared()
        self.assertEqual(request.headers["Content-Type"], "application/json")

    def test_prepared_keeps_existing_content_type(self) -> None:
        request = CallRequest(
            url="https://api.example.com",
            injections={"bearer": "KEY"},
            headers={"content-type": "application/vnd.api+json"},
            body="{}",
        ).prepared()
        self.assertEqual(request.headers["content-type"], "application/vnd.api+json")
        self.assertNotIn("Content-Type", request.headers)

    def test_prepared_leaves_non_json_body_alone(self) -> None:
        request = CallRequest(
            url="https://api.example.com",
            injections={"bearer": "KEY"},
            body="a=1",
        ).prepared()
        self.assertNotIn("Content-Type", request.headers)

    def test_accepts_custom_environment_names(self) -> None:
        for name in ("qa", "preview-pr-12", "uat"):
            request = CallRequest(
                url="https://api.example.com",
                injections={"bearer": "KEY"},
                environment=name,
            )
            self.assertEqual(request.environment, name)

    def test_normalizes_environment_case_and_whitespace(self) -> None:
        request = CallRequest(
            url="https://api.example.com",
            injections={"bearer": "KEY"},
            environment="  QA  ",
        )
        self.assertEqual(request.environment, "qa")

    def test_rejects_invalid_environment(self) -> None:
        for name in ("", "has space", "-lead", "9qa", "root", "admin", "api", "internal", "default"):
            with self.subTest(name=name):
                with self.assertRaises(InvalidRequest):
                    CallRequest(
                        url="https://api.example.com",
                        injections={"bearer": "KEY"},
                        environment=name,
                    )

    def test_from_mapping_accepts_camel_agent_id(self) -> None:
        request = CallRequest.from_mapping(
            {
                "url": "https://api.example.com",
                "injections": {"bearer": "KEY"},
                "agentId": "researcher",
            }
        )
        self.assertEqual(request.agent_id, "researcher")

    def test_from_mapping_rejects_non_string_injection_value(self) -> None:
        with self.assertRaises(InvalidRequest):
            CallRequest.from_mapping(
                {
                    "url": "https://api.example.com",
                    "injections": {"bearer": 1},
                }
            )

    def test_local_payload_omits_empty_fields(self) -> None:
        payload = CallRequest(
            url="https://api.example.com",
            injections={"bearer": "KEY"},
        ).local_payload()
        self.assertEqual(
            payload,
            {
                "url": "https://api.example.com",
                "method": "GET",
                "injections": {"bearer": "KEY"},
                "agent_id": "plugin",
            },
        )


class CallResultTests(unittest.TestCase):
    def test_to_dict_includes_optional_metadata(self) -> None:
        result = CallResult(
            status_code=200,
            headers={"content-type": "application/json"},
            body="{}",
            environment="staging",
            redacted=True,
        )
        self.assertEqual(
            result.to_dict(),
            {
                "status_code": 200,
                "headers": {"content-type": "application/json"},
                "body": "{}",
                "environment": "staging",
                "redacted": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
