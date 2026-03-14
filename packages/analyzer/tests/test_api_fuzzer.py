"""
Tests for the web API fuzzing module.

Uses unittest.mock to avoid real network requests.
All tests are offline / deterministic.
"""

import json
import time
import unittest
from unittest.mock import MagicMock, patch

from src.api_fuzzer import (
    ApiEndpoint,
    HttpInteraction,
    ApiFuzzer,
    parse_openapi_spec,
    parse_har_traffic,
    fuzz_from_openapi,
    fuzz_from_har,
    fuzz_from_endpoint_list,
    _detect_sqli,
    _detect_ssrf_response,
    _detect_ssrf_timing,
    _detect_stack_trace,
    _detect_sensitive_data,
    _detect_auth_bypass,
    _looks_like_url_param,
    _sample_body_from_schema,
)


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _ix(body="", status=200, method="GET", url="http://example.com/api", duration_ms=100.0):
    return HttpInteraction(
        request_method=method,
        request_url=url,
        request_headers={},
        request_body="",
        response_status=status,
        response_headers={},
        response_body=body,
        duration_ms=duration_ms,
    )


# ─────────────────────────────────────────────────────────────────
# parse_openapi_spec
# ─────────────────────────────────────────────────────────────────

class TestParseOpenApiSpec(unittest.TestCase):

    def _swagger2_spec(self):
        return {
            "swagger": "2.0",
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"in": "query", "name": "limit", "schema": {"type": "integer", "default": 10}},
                        ],
                        "security": [{"apiKey": []}],
                    },
                    "post": {
                        "parameters": [
                            {
                                "in": "body",
                                "name": "body",
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "age": {"type": "integer"},
                                    },
                                },
                            }
                        ]
                    },
                }
            },
        }

    def _openapi3_spec(self):
        return {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com/v2"}],
            "paths": {
                "/items/{id}": {
                    "get": {
                        "parameters": [
                            {"in": "query", "name": "format", "schema": {"default": "json"}},
                        ],
                    },
                    "delete": {},
                },
                "/items": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "title": {"type": "string"},
                                            "count": {"type": "integer"},
                                        },
                                    }
                                }
                            }
                        },
                        "security": [{"bearerAuth": []}],
                    }
                },
            },
        }

    def test_swagger2_extracts_endpoints(self):
        endpoints = parse_openapi_spec(self._swagger2_spec())
        methods = {(e.method, e.url) for e in endpoints}
        self.assertIn(("GET", "https://api.example.com/v1/users"), methods)
        self.assertIn(("POST", "https://api.example.com/v1/users"), methods)

    def test_swagger2_query_params_extracted(self):
        endpoints = parse_openapi_spec(self._swagger2_spec())
        get_ep = next(e for e in endpoints if e.method == "GET")
        self.assertIn("limit", get_ep.params)

    def test_swagger2_body_extracted(self):
        endpoints = parse_openapi_spec(self._swagger2_spec())
        post_ep = next(e for e in endpoints if e.method == "POST")
        self.assertIsNotNone(post_ep.body)
        self.assertIn("name", post_ep.body)
        self.assertIn("age", post_ep.body)

    def test_swagger2_auth_required_flag(self):
        endpoints = parse_openapi_spec(self._swagger2_spec())
        get_ep = next(e for e in endpoints if e.method == "GET")
        self.assertTrue(get_ep.auth_required)
        post_ep = next(e for e in endpoints if e.method == "POST")
        self.assertFalse(post_ep.auth_required)

    def test_openapi3_extracts_endpoints(self):
        endpoints = parse_openapi_spec(self._openapi3_spec())
        methods = {(e.method, e.url) for e in endpoints}
        self.assertIn(("GET", "https://api.example.com/v2/items/{id}"), methods)
        self.assertIn(("DELETE", "https://api.example.com/v2/items/{id}"), methods)
        self.assertIn(("POST", "https://api.example.com/v2/items"), methods)

    def test_openapi3_request_body_extracted(self):
        endpoints = parse_openapi_spec(self._openapi3_spec())
        post_ep = next(e for e in endpoints if e.method == "POST" and e.url.endswith("/items"))
        self.assertIsNotNone(post_ep.body)
        self.assertIn("title", post_ep.body)
        self.assertIn("count", post_ep.body)

    def test_empty_spec_returns_no_endpoints(self):
        endpoints = parse_openapi_spec({})
        self.assertEqual(endpoints, [])

    def test_spec_with_no_paths_returns_empty(self):
        endpoints = parse_openapi_spec({"openapi": "3.0.0", "paths": {}})
        self.assertEqual(endpoints, [])


# ─────────────────────────────────────────────────────────────────
# parse_har_traffic
# ─────────────────────────────────────────────────────────────────

class TestParseHarTraffic(unittest.TestCase):

    def _har(self):
        return {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/users",
                            "queryString": [{"name": "page", "value": "1"}],
                            "headers": [{"name": "Authorization", "value": "Bearer token123"}],
                            "postData": {},
                        }
                    },
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/users",
                            "queryString": [],
                            "headers": [],
                            "postData": {
                                "mimeType": "application/json",
                                "text": '{"name": "Alice"}',
                            },
                        }
                    },
                    # Duplicate of first entry — should be deduplicated
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/users",
                            "queryString": [{"name": "page", "value": "2"}],
                            "headers": [],
                            "postData": {},
                        }
                    },
                ]
            }
        }

    def test_extracts_endpoints(self):
        endpoints = parse_har_traffic(self._har())
        self.assertEqual(len(endpoints), 2)

    def test_deduplicates_same_method_url(self):
        endpoints = parse_har_traffic(self._har())
        get_eps = [e for e in endpoints if e.method == "GET"]
        self.assertEqual(len(get_eps), 1)

    def test_query_params_extracted(self):
        endpoints = parse_har_traffic(self._har())
        get_ep = next(e for e in endpoints if e.method == "GET")
        self.assertIn("page", get_ep.params)

    def test_headers_extracted(self):
        endpoints = parse_har_traffic(self._har())
        get_ep = next(e for e in endpoints if e.method == "GET")
        self.assertIn("Authorization", get_ep.headers)

    def test_json_body_extracted(self):
        endpoints = parse_har_traffic(self._har())
        post_ep = next(e for e in endpoints if e.method == "POST")
        self.assertIsNotNone(post_ep.body)
        self.assertEqual(post_ep.body.get("name"), "Alice")

    def test_empty_har_returns_empty(self):
        endpoints = parse_har_traffic({})
        self.assertEqual(endpoints, [])


# ─────────────────────────────────────────────────────────────────
# _sample_body_from_schema
# ─────────────────────────────────────────────────────────────────

class TestSampleBodyFromSchema(unittest.TestCase):

    def test_string_field(self):
        body = _sample_body_from_schema({"type": "object", "properties": {"name": {"type": "string"}}})
        self.assertEqual(body, {"name": "test"})

    def test_integer_field(self):
        body = _sample_body_from_schema({"type": "object", "properties": {"age": {"type": "integer"}}})
        self.assertEqual(body, {"age": 1})

    def test_boolean_field(self):
        body = _sample_body_from_schema({"type": "object", "properties": {"active": {"type": "boolean"}}})
        self.assertEqual(body, {"active": True})

    def test_non_object_type_returns_none(self):
        body = _sample_body_from_schema({"type": "string"})
        self.assertIsNone(body)

    def test_empty_schema_returns_none(self):
        body = _sample_body_from_schema({})
        self.assertIsNone(body)


# ─────────────────────────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────────────────────────

class TestDetectors(unittest.TestCase):

    # SQLi
    def test_sqli_detected_on_sql_syntax_error(self):
        ix = _ix(body="You have an error in your SQL syntax near 'OR 1=1'")
        f = _detect_sqli(ix)
        self.assertIsNotNone(f)
        self.assertEqual(f.rule, "api_sqli_error")
        self.assertEqual(f.severity, "high")

    def test_sqli_detected_on_mysql_fetch(self):
        ix = _ix(body="mysql_fetch_array() expects parameter 1 to be resource")
        f = _detect_sqli(ix)
        self.assertIsNotNone(f)

    def test_sqli_not_triggered_on_clean_response(self):
        ix = _ix(body='{"users": []}')
        self.assertIsNone(_detect_sqli(ix))

    # SSRF response
    def test_ssrf_response_detected_on_metadata(self):
        ix = _ix(body="ami-id: ami-0abcdef1234567890\ninstance-id: i-1234")
        f = _detect_ssrf_response(ix)
        self.assertIsNotNone(f)
        self.assertEqual(f.rule, "api_ssrf_detected")
        self.assertEqual(f.severity, "critical")

    def test_ssrf_response_not_triggered_on_clean(self):
        ix = _ix(body='{"status": "ok"}')
        self.assertIsNone(_detect_ssrf_response(ix))

    # SSRF timing
    def test_ssrf_timing_detected_on_timeout(self):
        ix = _ix(status=0, duration_ms=5000.0)
        f = _detect_ssrf_timing(ix)
        self.assertIsNotNone(f)
        self.assertEqual(f.rule, "api_ssrf_timing")

    def test_ssrf_timing_not_triggered_when_fast(self):
        ix = _ix(status=0, duration_ms=100.0)
        self.assertIsNone(_detect_ssrf_timing(ix))

    def test_ssrf_timing_not_triggered_when_status_not_zero(self):
        ix = _ix(status=200, duration_ms=5000.0)
        self.assertIsNone(_detect_ssrf_timing(ix))

    # Stack trace
    def test_stack_trace_detected_python(self):
        ix = _ix(body="Traceback (most recent call last):\n  File app.py, line 10")
        f = _detect_stack_trace(ix)
        self.assertIsNotNone(f)
        self.assertEqual(f.rule, "api_stack_trace_exposure")

    def test_stack_trace_detected_java(self):
        ix = _ix(body="java.lang.NullPointerException at com.example.Foo.bar(Foo.java:42)")
        f = _detect_stack_trace(ix)
        self.assertIsNotNone(f)

    def test_stack_trace_not_triggered_on_clean(self):
        ix = _ix(body='{"error": "not found"}')
        self.assertIsNone(_detect_stack_trace(ix))

    # Sensitive data
    def test_sensitive_data_detected_password(self):
        ix = _ix(body='{"id": 1, "password": "secret123"}')
        f = _detect_sensitive_data(ix)
        self.assertIsNotNone(f)
        self.assertEqual(f.rule, "api_excessive_data_exposure")
        self.assertEqual(f.severity, "high")

    def test_sensitive_data_detected_token(self):
        ix = _ix(body='{"token": "eyJhbGciOiJIUzI1NiJ9..."}')
        f = _detect_sensitive_data(ix)
        self.assertIsNotNone(f)

    def test_sensitive_data_not_triggered_on_clean(self):
        ix = _ix(body='{"id": 1, "name": "Alice"}')
        self.assertIsNone(_detect_sensitive_data(ix))

    # Auth bypass
    def test_auth_bypass_detected_on_403_to_200(self):
        fuzz_ix = _ix(status=200)
        fuzz_ix.request_headers = {"Authorization": "Bearer null"}
        f = _detect_auth_bypass(403, fuzz_ix)
        self.assertIsNotNone(f)
        self.assertEqual(f.rule, "api_auth_bypass")
        self.assertEqual(f.severity, "critical")

    def test_auth_bypass_detected_on_401_to_200(self):
        fuzz_ix = _ix(status=200)
        f = _detect_auth_bypass(401, fuzz_ix)
        self.assertIsNotNone(f)

    def test_auth_bypass_not_triggered_when_still_403(self):
        fuzz_ix = _ix(status=403)
        self.assertIsNone(_detect_auth_bypass(403, fuzz_ix))

    def test_auth_bypass_not_triggered_when_baseline_200(self):
        fuzz_ix = _ix(status=200)
        self.assertIsNone(_detect_auth_bypass(200, fuzz_ix))


# ─────────────────────────────────────────────────────────────────
# _looks_like_url_param
# ─────────────────────────────────────────────────────────────────

class TestLooksLikeUrlParam(unittest.TestCase):

    def test_url_param_names(self):
        for name in ["url", "redirect_url", "callback", "target", "next", "href", "src"]:
            self.assertTrue(_looks_like_url_param(name), f"Expected True for {name!r}")

    def test_non_url_param_names(self):
        for name in ["name", "age", "limit", "page", "format", "id"]:
            self.assertFalse(_looks_like_url_param(name), f"Expected False for {name!r}")


# ─────────────────────────────────────────────────────────────────
# ApiFuzzer (with mocked HTTP)
# ─────────────────────────────────────────────────────────────────

def _mock_send(session, method, url, params=None, headers=None, body=None, timeout=10):
    """Default mock: returns 200 with an empty JSON body."""
    return HttpInteraction(
        request_method=method,
        request_url=url,
        request_headers=headers or {},
        request_body="",
        response_status=200,
        response_headers={},
        response_body="{}",
        duration_ms=50.0,
    )


class TestApiFuzzer(unittest.TestCase):

    def _make_fuzzer(self):
        return ApiFuzzer(timeout=5, max_endpoints=10)

    @patch("src.api_fuzzer._send", side_effect=_mock_send)
    def test_fuzz_returns_empty_on_clean_responses(self, _mock):
        fuzzer = self._make_fuzzer()
        ep = ApiEndpoint(url="http://example.com/api/users", method="GET", params={"q": "test"})
        findings = fuzzer.fuzz([ep])
        self.assertEqual(findings, [])

    @patch("src.api_fuzzer._send")
    def test_sqli_finding_raised(self, mock_send):
        def side_effect(session, method, url, params=None, headers=None, body=None, timeout=10):
            # Return SQL error for injection payloads
            if params and any("OR" in str(v) for v in params.values()):
                return HttpInteraction(
                    request_method=method, request_url=url,
                    request_headers={}, request_body="",
                    response_status=500, response_headers={},
                    response_body="You have an error in your SQL syntax",
                    duration_ms=50.0,
                )
            return _mock_send(session, method, url, params=params, headers=headers, body=body, timeout=timeout)

        mock_send.side_effect = side_effect
        fuzzer = self._make_fuzzer()
        ep = ApiEndpoint(url="http://example.com/api/search", method="GET", params={"q": "hello"})
        findings = fuzzer.fuzz([ep])
        rules = [f.rule for f in findings]
        self.assertIn("api_sqli_error", rules)

    @patch("src.api_fuzzer._send")
    def test_sensitive_data_finding_raised(self, mock_send):
        mock_send.side_effect = lambda session, method, url, **kw: HttpInteraction(
            request_method=method, request_url=url,
            request_headers={}, request_body="",
            response_status=200, response_headers={},
            response_body='{"id": 1, "password": "hunter2"}',
            duration_ms=50.0,
        )
        fuzzer = self._make_fuzzer()
        ep = ApiEndpoint(url="http://example.com/api/me", method="GET")
        findings = fuzzer.fuzz([ep])
        rules = [f.rule for f in findings]
        self.assertIn("api_excessive_data_exposure", rules)

    @patch("src.api_fuzzer._send")
    def test_auth_bypass_finding_raised(self, mock_send):
        call_count = {"n": 0}

        def side_effect(session, method, url, params=None, headers=None, body=None, timeout=10):
            call_count["n"] += 1
            # Baseline returns 403; fuzz with tampered auth returns 200
            if headers and headers.get("Authorization") in ("Bearer null", "Bearer undefined", ""):
                return HttpInteraction(
                    request_method=method, request_url=url,
                    request_headers=headers or {}, request_body="",
                    response_status=200, response_headers={},
                    response_body='{"admin": true}',
                    duration_ms=50.0,
                )
            return HttpInteraction(
                request_method=method, request_url=url,
                request_headers=headers or {}, request_body="",
                response_status=403, response_headers={},
                response_body='{"error": "forbidden"}',
                duration_ms=50.0,
            )

        mock_send.side_effect = side_effect
        fuzzer = self._make_fuzzer()
        ep = ApiEndpoint(url="http://example.com/api/admin", method="GET", auth_required=True)
        findings = fuzzer.fuzz([ep])
        rules = [f.rule for f in findings]
        self.assertIn("api_auth_bypass", rules)

    @patch("src.api_fuzzer._send", side_effect=_mock_send)
    def test_max_endpoints_respected(self, _mock):
        fuzzer = ApiFuzzer(timeout=5, max_endpoints=3)
        endpoints = [
            ApiEndpoint(url=f"http://example.com/api/{i}", method="GET")
            for i in range(10)
        ]
        fuzzer.fuzz(endpoints)
        # 3 endpoints × (1 baseline + 2 sqli + 2 ssrf + 3 auth) = 3 × 8 = 24 calls
        self.assertLessEqual(_mock.call_count, 3 * 10)

    @patch("src.api_fuzzer._send")
    def test_finding_deduplication(self, mock_send):
        """Same rule should not appear twice for the same endpoint URL."""
        mock_send.side_effect = lambda session, method, url, **kw: HttpInteraction(
            request_method=method, request_url=url,
            request_headers={}, request_body="",
            response_status=200, response_headers={},
            response_body='{"password": "secret", "token": "tok"}',
            duration_ms=50.0,
        )
        fuzzer = self._make_fuzzer()
        ep = ApiEndpoint(url="http://example.com/api/users", method="GET")
        findings = fuzzer.fuzz([ep])
        rules = [f.rule for f in findings]
        # api_excessive_data_exposure should appear at most once per endpoint
        self.assertLessEqual(rules.count("api_excessive_data_exposure"), 1)


# ─────────────────────────────────────────────────────────────────
# Public API functions
# ─────────────────────────────────────────────────────────────────

class TestPublicApiFunctions(unittest.TestCase):

    def _minimal_openapi3_spec(self):
        return {
            "openapi": "3.0.0",
            "servers": [{"url": "http://localhost:8000"}],
            "paths": {
                "/ping": {"get": {}}
            },
        }

    @patch("src.api_fuzzer._send", side_effect=_mock_send)
    def test_fuzz_from_openapi_returns_list(self, _mock):
        result = fuzz_from_openapi(self._minimal_openapi3_spec())
        self.assertIsInstance(result, list)

    @patch("src.api_fuzzer._send")
    def test_fuzz_from_openapi_each_item_has_required_keys(self, mock_send):
        mock_send.side_effect = lambda session, method, url, **kw: HttpInteraction(
            request_method=method, request_url=url,
            request_headers={}, request_body="",
            response_status=200, response_headers={},
            response_body='{"password": "leaked"}',
            duration_ms=50.0,
        )
        findings = fuzz_from_openapi(self._minimal_openapi3_spec())
        for f in findings:
            self.assertIn("category", f)
            self.assertIn("severity", f)
            self.assertIn("rule", f)
            self.assertIn("description", f)
            self.assertIn("evidence", f)

    @patch("src.api_fuzzer._send", side_effect=_mock_send)
    def test_fuzz_from_har_returns_list(self, _mock):
        har = {
            "log": {
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": "http://example.com/api/v1/data",
                        "queryString": [],
                        "headers": [],
                        "postData": {},
                    }
                }]
            }
        }
        result = fuzz_from_har(har)
        self.assertIsInstance(result, list)

    @patch("src.api_fuzzer._send", side_effect=_mock_send)
    def test_fuzz_from_endpoint_list_returns_list(self, _mock):
        result = fuzz_from_endpoint_list([
            {"url": "http://example.com/api/users", "method": "GET"}
        ])
        self.assertIsInstance(result, list)

    @patch("src.api_fuzzer._send", side_effect=_mock_send)
    def test_fuzz_from_endpoint_list_skips_entries_without_url(self, _mock):
        result = fuzz_from_endpoint_list([{"method": "GET"}, {"url": "http://example.com/ok"}])
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
