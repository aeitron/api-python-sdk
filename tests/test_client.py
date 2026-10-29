"""
Unit tests for Aeitron Python SDK using standard library unittest and http.server.
"""

import hashlib
import hmac
import json
import os
import sys
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

pkg_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)

from aeitron import (
    ChatMessage,
    AeitronClient,
    AeitronError,
    AuthenticationError,
    PermissionDeniedError,
    ApprovalRequiredError,
    NotFoundError,
    ConflictError,
    ExpiredError,
    ValidationError,
    RateLimitError,
    ServerError,
    NetworkError,
    WebhookSignature,
)


class MockServerHandler(BaseHTTPRequestHandler):
    """Mock HTTP Handler simulating Aeitron BFF Endpoints."""

    transient_counter: int = 0
    idempotent_post_counter: int = 0

    def log_message(self, format: str, *args) -> None:
        pass  # Suppress console logging during test runs

    def do_GET(self) -> None:
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr != "Bearer nke_live_test_key_01":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unauthorized: invalid key", "code": 401}).encode("utf-8"))
            return

        if self.path == "/api/proxy/domains":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "domains": [
                    {
                        "id": "dom_001",
                        "project_id": "proj_core",
                        "hostname": "api.example.com",
                        "status": "ACTIVE",
                        "cname_target": "edge.aeitron.net",
                        "origin_address": "203.0.113.10",
                        "origin_port": 443,
                        "origin_protocol": "https",
                        "allowed_pops": ["dhaka", "singapore"],
                    }
                ]
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/domains/dom_001":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "id": "dom_001",
                "project_id": "proj_core",
                "hostname": "api.example.com",
                "status": "ACTIVE",
                "cname_target": "edge.aeitron.net",
                "origin_address": "203.0.113.10",
                "origin_port": 443,
                "origin_protocol": "https",
                "allowed_pops": ["dhaka", "singapore"],
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path.startswith("/api/proxy/analytics/summary"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "project_id": "proj_core",
                "total_requests": 1500,
                "p50_latency_ms": 12.4,
                "p95_latency_ms": 28.1,
                "p99_latency_ms": 45.2,
                "cache_hit_ratio": 0.885,
                "threat_blocks": 4,
                "success_rate": 0.998,
                "status_distribution": {"2xx": 1490, "4xx": 8, "5xx": 2},
                "pop_distribution": {"dhaka": 800, "singapore": 700},
                "rate_limit": {"limit": 60, "remaining": 59},
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/pops/matrix":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "routes": [
                    {"from_pop": "dhaka", "to_pop": "singapore", "latency_ms": 32.5, "status": "OPTIMAL"}
                ],
                "timestamp": "2026-10-16T09:00:00Z",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/pops/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "pops": [
                    {
                        "id": "dhaka",
                        "name": "Dhaka BDIX Edge",
                        "region": "asia-south1",
                        "status": "ACTIVE",
                        "latency_p50_ms": 4.2,
                        "capacity_used_pct": 22.0,
                        "anycast_announced": True,
                    }
                ]
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path in ("/api/proxy/workloads/nodes", "/api/workloads/nodes"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "nodes": [
                    {
                        "node_id": "bd-dhaka-dgx01",
                        "provider": "baremetal-bd",
                        "region": "ap-south-2",
                        "jurisdiction": "BD",
                        "gpu_type": "H100",
                        "total_gpus": 8,
                        "available_gpus": 8,
                        "cost_per_gpu_hour": 2.10,
                        "carbon_intensity": 480.0,
                    }
                ],
                "count": 1,
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path.startswith("/api/proxy/storage/buckets"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if "/objects" in self.path:
                if self.path.endswith("/objects"):
                    self.end_headers()
                    resp = {"bucket": "vault-model-weights", "objects": [{"bucket_name": "vault-model-weights", "key": "model.safetensors", "size_bytes": 1024, "content_type": "application/octet-stream", "etag": "\"abc\"", "sha256_checksum": "def", "sovereign_jurisdiction": "BD", "encryption": "AES256-GCM", "created_at": "2026-10-17T00:00:00Z", "updated_at": "2026-10-17T00:00:00Z"}]}
                    self.wfile.write(json.dumps(resp).encode("utf-8"))
                    return
                else:
                    self.send_header("ETag", "\"abc\"")
                    self.send_header("X-Aeitron-SHA256", "def")
                    self.send_header("X-Aeitron-Sovereignty", "BD")
                    self.end_headers()
                    self.wfile.write(b"mock object payload bytes")
                    return
            elif self.path == "/api/proxy/storage/buckets" or self.path.startswith("/api/proxy/storage/buckets?"):
                self.end_headers()
                resp = {"buckets": [{"name": "vault-model-weights", "project_id": "proj-core", "tenant_id": "tenant-system", "sovereignty_policy": "GLOBAL_REDUNDANT", "replication_topology": "MULTI_REGION_NVME_CACHE", "primary_region": "ap-south-2", "stored_bytes": 1024, "object_count": 1, "max_size_bytes": 53687091200, "status": "ACTIVE", "created_at": "2026-10-17T00:00:00Z", "updated_at": "2026-10-17T00:00:00Z"}]}
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                return
            else:
                self.end_headers()
                resp = {"name": "vault-model-weights", "project_id": "proj-core", "tenant_id": "tenant-system", "sovereignty_policy": "GLOBAL_REDUNDANT", "replication_topology": "MULTI_REGION_NVME_CACHE", "primary_region": "ap-south-2", "stored_bytes": 1024, "object_count": 1, "max_size_bytes": 53687091200, "status": "ACTIVE", "created_at": "2026-10-17T00:00:00Z", "updated_at": "2026-10-17T00:00:00Z"}
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                return

        if self.path.startswith("/api/proxy/network/cables"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if self.path == "/api/proxy/network/cables":
                resp = {"cables": [{"id": "smw6", "name": "SEA-ME-WE 6", "landing_points": ["Cox's Bazar", "Singapore"], "capacity_gbps": 30000, "normal_latency_ms": 32.0, "current_latency_ms": 32.0, "status": "ONLINE", "active_bgp_paths": 4, "alternate_route": "SMW5"}]}
            else:
                resp = {"id": "smw6", "name": "SEA-ME-WE 6", "landing_points": ["Cox's Bazar", "Singapore"], "capacity_gbps": 30000, "normal_latency_ms": 32.0, "current_latency_ms": 32.0, "status": "ONLINE", "active_bgp_paths": 4, "alternate_route": "SMW5"}
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/v1/catalog":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "products": [{"id": "prod_gpu_h100", "name": "NVIDIA H100 GPU", "price_cents": 25000}]
            }).encode("utf-8"))
            return

        if self.path == "/v1/dns/zones":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "zones": [{"id": "zone_01", "name": "aeitron.io", "status": "ACTIVE", "record_count": 12}]
            }).encode("utf-8"))
            return

        if self.path == "/v1/compute/instances":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "instances": [{"id": "inst_01", "name": "gpu-node-01", "type": "gpu", "region": "dhaka", "status": "ACTIVE"}]
            }).encode("utf-8"))
            return

        if self.path.startswith("/v1/test-typed-errors"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            status_code = int(params.get("status", [200])[0])
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            if status_code == 429:
                self.send_header("Retry-After", "12")
            self.end_headers()
            err_body = {
                "error": f"Error status {status_code}",
                "code": f"ERR_{status_code}",
            }
            if status_code == 422:
                err_body["fields"] = {"ip": "bad"}
            self.wfile.write(json.dumps(err_body).encode("utf-8"))
            return

        if self.path == "/v1/transient-test":
            MockServerHandler.transient_counter += 1
            if MockServerHandler.transient_counter < 3:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Service Unavailable", "code": "SERVICE_UNAVAILABLE"}).encode("utf-8"))
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "attempts": MockServerHandler.transient_counter}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr != "Bearer nke_live_test_key_01":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unauthorized", "code": 401}).encode("utf-8"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        payload = json.loads(body)

        if self.path == "/api/proxy/slow":
            import time
            time.sleep(1.0)
            self.send_response(200)
            self.end_headers()
            return

        if self.path == "/api/proxy/inference":
            if payload.get("model") == "trigger-429":
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", "1")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "rate limit exceeded: max 60 req/min for key",
                    "code": "RATE_LIMIT_EXCEEDED"
                }).encode("utf-8"))
                return

            routing = self.headers.get("X-Aeitron-Routing-Strategy", "")
            jurisdiction = self.headers.get("X-Aeitron-Jurisdiction", "")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("x-aeitron-provider", "Groq-Llama-Engine")
            self.send_header("x-aeitron-cost", "0.000150")
            self.send_header("x-aeitron-ttft-ms", "42")
            self.send_header("x-aeitron-region", "dhaka-bdix")
            self.end_headers()

            resp = {
                "id": "chatcmpl_mock_001",
                "object": "chat.completion",
                "created": 1729065600,
                "model": payload.get("model", "meta-llama/Llama-3.3-70B-Instruct"),
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"Echo: strategy={routing}, jurisdiction={jurisdiction}",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 12, "total_tokens": 22},
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/domains":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "domain_id": "dom_new_123",
                "hostname": payload.get("hostname"),
                "cname_target": "edge.aeitron.net",
                "verification_token": "nke_token_abc123",
                "status": "PENDING_VERIFICATION",
                "allowed_pops": payload.get("allowed_pops", []),
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path.startswith("/api/proxy/domains/dom_001/verify"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "status": "ok",
                "domain_id": "dom_001",
                "hostname": "api.example.com",
                "state": "ACTIVE",
                "message": "CNAME and TLS verified",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path in ("/api/proxy/policies/sovereignty/evaluate", "/api/policies/sovereignty/evaluate"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            is_bd_breach = payload.get("source_jurisdiction") == "BD" and payload.get("target_jurisdiction") != "BD" and payload.get("data_classification") == "CII"
            resp = {
                "allowed": not is_bd_breach,
                "decision_code": "BD_NDMA_2026_CII_BREACH" if is_bd_breach else "SOVEREIGN_POLICY_COMPLIANT",
                "reason": "CII data cannot leave Bangladesh without export permit" if is_bd_breach else "Workload satisfies data residency policies",
                "source_jurisdiction": payload.get("source_jurisdiction"),
                "target_jurisdiction": payload.get("target_jurisdiction"),
                "data_classification": payload.get("data_classification"),
                "enforced_law": "Bangladesh NDMA 2026" if is_bd_breach else None,
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path in ("/api/proxy/workloads/schedule", "/api/workloads/schedule"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "workload_id": payload.get("workload_id", "wl-01"),
                "status": "SCHEDULED",
                "assigned_node": "bd-dhaka-dgx01",
                "provider": "baremetal-bd",
                "region": "ap-south-2",
                "jurisdiction": "BD",
                "measured_rtt_ms": 4,
                "hourly_cost": 2.10,
                "carbon_gco2_kwh": 480.0,
                "carbon_classification": "STANDARD_GRID",
                "remaining_node_gpus": 7,
                "optimization_score": -28.0,
                "reason": "Optimized via Universal Scheduler",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/storage/buckets":
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "name": payload.get("name", "test-bucket"),
                "project_id": payload.get("project_id", "proj-core"),
                "tenant_id": "tenant-system",
                "sovereignty_policy": payload.get("sovereignty_policy", "GLOBAL_REDUNDANT"),
                "replication_topology": payload.get("replication_topology", "SINGLE_REGION_NVME"),
                "primary_region": payload.get("primary_region", "ap-south-2"),
                "stored_bytes": 0,
                "object_count": 0,
                "max_size_bytes": payload.get("max_size_bytes", 53687091200),
                "status": "ACTIVE",
                "created_at": "2026-10-17T00:00:00Z",
                "updated_at": "2026-10-17T00:00:00Z",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/network/cables/smw6/cut":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "cable_id": "smw6",
                "status": "SEVERED",
                "bgp_failover_triggered": True,
                "rerouted_to": "SMW5 / Terrestrial",
                "new_latency_ms": 121.6,
                "message": "Subsea cable severed. BGP failover triggered.",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/network/cables/smw6/restore":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "cable_id": "smw6",
                "status": "ONLINE",
                "bgp_failover_triggered": True,
                "rerouted_to": "Primary Subsea Fiber Direct",
                "new_latency_ms": 32.0,
                "message": "Subsea cable restored.",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/v1/dns/request-deletion":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "requestId": "del_req_mock_123",
                "domain": payload.get("domain"),
                "recordId": payload.get("record_id"),
                "requester": "sec_agent_1",
                "status": "PENDING_APPROVAL",
                "expiresAt": "2026-10-30T00:00:00Z",
                "challengeToken": "tok_challenge_abc",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/v1/dns/approve-deletion":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "status": "APPROVED",
                "requestId": payload.get("requestId"),
                "approvedBy": payload.get("actor", "human_lead"),
                "approvalToken": "tok_challenge_abc",
                "validUntil": "2026-10-30T00:10:00Z",
                "message": "Deletion approved",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/v1/idempotency-test":
            idem_key = self.headers.get("Idempotency-Key")
            MockServerHandler.idempotent_post_counter += 1
            if MockServerHandler.idempotent_post_counter < 2:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Transient 503 error"}).encode("utf-8"))
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"received_key": idem_key, "attempts": MockServerHandler.idempotent_post_counter}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_DELETE(self) -> None:
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr != "Bearer nke_live_test_key_01":
            self.send_response(401)
            self.end_headers()
            return

        if "/v1/dns/zones/" in self.path and "/records/" in self.path:
            parsed = urllib.parse.urlparse(self.path)
            qs_params = urllib.parse.parse_qs(parsed.query)
            confirm = qs_params.get("confirm", ["false"])[0] == "true"
            token = qs_params.get("approval_token", [""])[0]

            if not confirm or token != "tok_challenge_abc":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "APPROVAL_REQUIRED: Record deletion requires challenge approval",
                    "requestId": "del_req_mock_123",
                    "domain": "aeitron.io",
                    "recordId": "rec_001",
                }).encode("utf-8"))
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "DELETED", "record_id": "rec_001"}).encode("utf-8"))
            return

        if self.path == "/api/proxy/domains/dom_001":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "deleted", "domain_id": "dom_001"}).encode("utf-8"))
            return

        if self.path.startswith("/api/proxy/storage/buckets"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "DELETED"}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_PUT(self) -> None:
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr != "Bearer nke_live_test_key_01":
            self.send_response(401)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)

        if "/objects/" in self.path:
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "bucket_name": "vault-model-weights",
                "key": "test.bin",
                "size_bytes": 100,
                "content_type": "application/octet-stream",
                "etag": "\"mock-etag\"",
                "sha256_checksum": "mock-checksum",
                "sovereign_jurisdiction": "BD",
                "encryption": "AES256-GCM",
                "created_at": "2026-10-17T00:00:00Z",
                "updated_at": "2026-10-17T00:00:00Z",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


class AeitronPythonSDKTests(unittest.TestCase):
    """Test suite verifying official Python SDK behavior."""

    server: Optional[HTTPServer] = None
    server_thread: Optional[threading.Thread] = None
    port: int = 0

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), MockServerHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()

    def setUp(self) -> None:
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.api_key = "nke_live_test_key_01"
        self.client = AeitronClient(api_key=self.api_key, base_url=self.base_url, timeout_seconds=5.0)

    def test_client_initialization_validation(self) -> None:
        """Verifies that client rejects empty or missing API keys."""
        with self.assertRaises(AeitronError) as cm:
            AeitronClient(api_key="")
        self.assertEqual(cm.exception.status, 400)
        self.assertEqual(cm.exception.code, "INVALID_API_KEY")

    def test_unauthorized_rejection(self) -> None:
        """Verifies 401 Unauthorized handling with invalid API keys."""
        bad_client = AeitronClient(api_key="nke_live_bad_key", base_url=self.base_url)
        with self.assertRaises(AeitronError) as cm:
            bad_client.domains.list()
        self.assertEqual(cm.exception.status, 401)

    def test_multi_objective_inference_completion(self) -> None:
        """Verifies AI inference with custom routing strategy, jurisdiction, and telemetry."""
        messages = [
            ChatMessage(role="system", content="You are an edge AI assistant."),
            {"role": "user", "content": "Ping!"},
        ]
        resp = self.client.inference.create_completion(
            messages=messages,
            model="meta-llama/Llama-3.3-70B-Instruct",
            routing_strategy="LATENCY_OPTIMAL",
            jurisdiction="BD",
        )
        self.assertEqual(resp.model, "meta-llama/Llama-3.3-70B-Instruct")
        self.assertTrue(len(resp.choices) > 0)
        self.assertIn("LATENCY_OPTIMAL", resp.choices[0].message.content)
        self.assertIn("BD", resp.choices[0].message.content)

        # Telemetry verification
        self.assertEqual(resp.telemetry.provider, "Groq-Llama-Engine")
        self.assertEqual(resp.telemetry.cost, 0.00015)
        self.assertEqual(resp.telemetry.ttft_ms, 42)
        self.assertEqual(resp.telemetry.region, "dhaka-bdix")

    def test_custom_domains_lifecycle(self) -> None:
        """Verifies full domain lifecycle: list, onboard, get, verify, delete."""
        # 1. List
        domains = self.client.domains.list()
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0].hostname, "api.example.com")
        self.assertEqual(domains[0].allowed_pops, ["dhaka", "singapore"])

        # 2. Onboard
        new_dom = self.client.domains.onboard(
            hostname="app.example.com",
            origin_address="198.51.100.5",
            origin_port=443,
            origin_protocol="https",
            allowed_pops=["dhaka"],
        )
        self.assertEqual(new_dom.domain_id, "dom_new_123")
        self.assertEqual(new_dom.verification_token, "nke_token_abc123")
        self.assertEqual(new_dom.status, "PENDING_VERIFICATION")

        # 3. Get
        d = self.client.domains.get("dom_001")
        self.assertEqual(d.id, "dom_001")
        self.assertEqual(d.status, "ACTIVE")

        # 4. Verify
        v = self.client.domains.verify("dom_001", force=True)
        self.assertEqual(v.state, "ACTIVE")

        # 5. Delete
        del_res = self.client.domains.delete("dom_001")
        self.assertEqual(del_res.get("status"), "deleted")

    def test_real_time_telemetry_and_health(self) -> None:
        """Verifies telemetry summary, pop health, and latency matrix."""
        # 1. Summary
        summary = self.client.telemetry.get_summary(project_id="proj_core")
        self.assertEqual(summary.total_requests, 1500)
        self.assertEqual(summary.p50_latency_ms, 12.4)
        self.assertEqual(summary.p99_latency_ms, 45.2)
        self.assertEqual(summary.cache_hit_ratio, 0.885)
        self.assertIsNotNone(summary.rate_limit)
        if summary.rate_limit:
            self.assertEqual(summary.rate_limit.limit, 60)
            self.assertEqual(summary.rate_limit.remaining, 59)

        # 2. Latency Matrix
        matrix = self.client.telemetry.get_latency_matrix()
        self.assertEqual(len(matrix.routes), 1)
        self.assertEqual(matrix.routes[0].from_pop, "dhaka")
        self.assertEqual(matrix.routes[0].to_pop, "singapore")
        self.assertEqual(matrix.routes[0].latency_ms, 32.5)

        # 3. PoP Health
        health = self.client.telemetry.get_pop_health()
        self.assertEqual(len(health), 1)
        self.assertEqual(health[0].id, "dhaka")
        self.assertEqual(health[0].region, "asia-south1")
        self.assertTrue(health[0].anycast_announced)

    def test_rate_limit_429_error(self) -> None:
        """Verifies 429 Rate Limit error parsing and exception details."""
        with self.assertRaises(AeitronError) as cm:
            self.client.inference.create_completion(
                messages=[{"role": "user", "content": "Hello"}],
                model="trigger-429"
            )
        self.assertEqual(cm.exception.status, 429)
        self.assertEqual(cm.exception.code, "RATE_LIMIT_EXCEEDED")
        self.assertIn("rate limit exceeded", cm.exception.message)

    def test_parameter_validation_errors(self) -> None:
        """Verifies client-side validation errors for missing or invalid parameters."""
        # 1. Empty messages list
        with self.assertRaises(AeitronError) as cm1:
            self.client.inference.create_completion(messages=[])
        self.assertEqual(cm1.exception.status, 400)
        self.assertEqual(cm1.exception.code, "INVALID_PARAMS")

        # 2. Missing hostname or origin_address
        with self.assertRaises(AeitronError) as cm2:
            self.client.domains.onboard(hostname="", origin_address="10.0.0.1")
        self.assertEqual(cm2.exception.status, 400)

        # 3. Missing domain_id
        with self.assertRaises(AeitronError) as cm3:
            self.client.domains.get("")
        self.assertEqual(cm3.exception.status, 400)

    def test_client_request_timeout(self) -> None:
        """Verifies timeout handling when endpoint response exceeds configured timeout."""
        fast_timeout_client = AeitronClient(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout_seconds=0.2
        )
        with self.assertRaises(AeitronError) as cm:
            fast_timeout_client.request("/api/proxy/slow", method="POST", body={"test": 1})
        self.assertEqual(cm.exception.status, 504)
        self.assertEqual(cm.exception.code, "TIMEOUT")

    def test_sovereign_policy_evaluation(self) -> None:
        """Verifies Sovereign Policy Evaluator via Python SDK."""
        # 1. BD CII to US breach
        res = self.client.policies.evaluate_sovereignty(
            tenant_id="tenant-fintech-bd",
            project_id="proj-core",
            workload_id="core-banking-01",
            source_jurisdiction="BD",
            target_jurisdiction="US",
            data_classification="CII",
            strict_sovereignty=True,
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.decision_code, "BD_NDMA_2026_CII_BREACH")
        self.assertIn("CII data cannot leave Bangladesh", res.reason)

        # 2. BD CII within BD compliant
        res_ok = self.client.policies.evaluate_sovereignty(
            tenant_id="tenant-fintech-bd",
            project_id="proj-core",
            workload_id="core-banking-01",
            source_jurisdiction="BD",
            target_jurisdiction="BD",
            data_classification="CII",
            strict_sovereignty=True,
        )
        self.assertTrue(res_ok.allowed)
        self.assertEqual(res_ok.decision_code, "SOVEREIGN_POLICY_COMPLIANT")

    def test_workload_scheduler_and_nodes(self) -> None:
        """Verifies Universal Workload Placement Scheduler via Python SDK."""
        # 1. Optimal placement
        decision = self.client.scheduler.find_optimal_placement(
            workload_type="BANKING_API",
            client_origin="dhaka",
            required_jurisdiction="BD",
            strict_sovereignty=True,
            data_classification="CII",
            max_latency_p95_ms=20,
            max_cost_per_hour=5.0,
            gpus_requested=1,
        )
        self.assertEqual(decision.status, "SCHEDULED")
        self.assertEqual(decision.assigned_node, "bd-dhaka-dgx01")
        self.assertEqual(decision.jurisdiction, "BD")
        self.assertEqual(decision.measured_rtt_ms, 4)
        self.assertEqual(decision.hourly_cost, 2.10)

        # 2. Node listing
        nodes = self.client.scheduler.list_nodes()
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].node_id, "bd-dhaka-dgx01")
        self.assertEqual(nodes[0].provider, "baremetal-bd")

    def test_verify_ssl_option(self) -> None:
        """Verifies verify_ssl flag configuration on client."""
        custom_client = AeitronClient(
            api_key=self.api_key,
            base_url=self.base_url,
            verify_ssl=False,
        )
        self.assertFalse(custom_client.verify_ssl)
        nodes = custom_client.scheduler.list_nodes()
        self.assertEqual(len(nodes), 1)

    def test_storage_bucket_and_object_lifecycle(self) -> None:
        """Verifies S3-compatible sovereign object storage operations."""
        # 1. List buckets
        buckets = self.client.storage.list_buckets()
        self.assertGreaterEqual(len(buckets), 1)
        self.assertEqual(buckets[0].name, "vault-model-weights")

        # 2. Create bucket
        new_bucket = self.client.storage.create_bucket(
            name="new-checkpoints-bd",
            sovereignty_policy="BD_ONLY",
            replication_topology="SINGLE_REGION_NVME",
            primary_region="ap-south-2",
        )
        self.assertEqual(new_bucket.name, "new-checkpoints-bd")

        # 3. Get bucket
        b = self.client.storage.get_bucket("vault-model-weights")
        self.assertEqual(b.name, "vault-model-weights")

        # 4. Put object
        obj_meta = self.client.storage.put_object("vault-model-weights", "test.bin", b"test data")
        self.assertEqual(obj_meta.key, "test.bin")
        self.assertEqual(obj_meta.sovereign_jurisdiction, "BD")

        # 5. List objects
        objs = self.client.storage.list_objects("vault-model-weights")
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0].key, "model.safetensors")

        # 6. Get object
        data, meta = self.client.storage.get_object("vault-model-weights", "model.safetensors", destination_jurisdiction="BD")
        self.assertEqual(data, b"mock object payload bytes")
        self.assertEqual(meta.etag, "\"abc\"")

        # 7. Delete object and bucket
        del_obj = self.client.storage.delete_object("vault-model-weights", "model.safetensors")
        self.assertTrue(del_obj)

        del_b = self.client.storage.delete_bucket("vault-model-weights")
        self.assertTrue(del_b)

    def test_network_subsea_cables_and_bgp_failover(self) -> None:
        """Verifies subsea cable telemetry and dynamic BGP failover triggers."""
        # 1. List cables
        cables = self.client.network.list_cables()
        self.assertGreaterEqual(len(cables), 1)
        self.assertEqual(cables[0].id, "smw6")

        # 2. Get specific cable
        c = self.client.network.get_cable("smw6")
        self.assertEqual(c.id, "smw6")
        self.assertEqual(c.status, "ONLINE")

        # 3. Simulate cut
        cut = self.client.network.simulate_cable_cut("smw6")
        self.assertEqual(cut.status, "SEVERED")
        self.assertTrue(cut.bgp_failover_triggered)
        self.assertGreater(cut.new_latency_ms, 32.0)

        # 4. Restore cable
        restored = self.client.network.restore_cable("smw6")
        self.assertEqual(restored.status, "ONLINE")
        self.assertEqual(restored.new_latency_ms, 32.0)

    def test_generated_openapi_namespaces(self) -> None:
        """Verifies auto-generated OpenAPI namespaces (Catalog, DNS, Compute)."""
        catalog = self.client.catalog.list_products()
        self.assertIn("products", catalog)
        self.assertEqual(catalog["products"][0]["id"], "prod_gpu_h100")

        zones = self.client.dns.list_zones()
        self.assertIn("zones", zones)
        self.assertEqual(zones["zones"][0]["name"], "aeitron.io")

        instances = self.client.compute.list_instances()
        self.assertIn("instances", instances)
        self.assertEqual(instances["instances"][0]["name"], "gpu-node-01")

    def test_date_based_api_versioning_and_deprecation(self) -> None:
        """Verifies date-based version negotiation and deprecation header handling."""
        # 1. Default baseline version
        self.assertEqual(self.client.api_version, "2026-11-01")

        # 2. Custom pinned version
        custom_client = AeitronClient(
            api_key="nke_live_test_key_01",
            base_url=self.base_url,
            api_version="2026-01-01",
        )
        self.assertEqual(custom_client.api_version, "2026-01-01")

    def test_specialized_typed_error_hierarchy(self) -> None:
        """Verifies that specialized typed errors are thrown according to HTTP status code."""
        # 400 Bad Request -> ValidationError
        with self.assertRaises(ValidationError) as cm:
            self.client.request("/v1/test-typed-errors?status=400")
        self.assertEqual(cm.exception.status, 400)
        self.assertIsInstance(cm.exception, ValidationError)

        # 401 Unauthorized -> AuthenticationError
        bad_auth_client = AeitronClient(api_key="nke_bad_key", base_url=self.base_url)
        with self.assertRaises(AuthenticationError) as cm:
            bad_auth_client.request("/api/proxy/domains")
        self.assertEqual(cm.exception.status, 401)
        self.assertIsInstance(cm.exception, AuthenticationError)

        # 403 Forbidden -> PermissionDeniedError
        with self.assertRaises(PermissionDeniedError) as cm:
            self.client.request("/v1/test-typed-errors?status=403")
        self.assertEqual(cm.exception.status, 403)
        self.assertIsInstance(cm.exception, PermissionDeniedError)

        # 404 Not Found -> NotFoundError
        with self.assertRaises(NotFoundError) as cm:
            self.client.request("/v1/test-typed-errors?status=404")
        self.assertEqual(cm.exception.status, 404)
        self.assertIsInstance(cm.exception, NotFoundError)

        # 409 Conflict -> ConflictError
        with self.assertRaises(ConflictError) as cm:
            self.client.request("/v1/test-typed-errors?status=409")
        self.assertEqual(cm.exception.status, 409)
        self.assertIsInstance(cm.exception, ConflictError)

        # 410 Gone -> ExpiredError
        with self.assertRaises(ExpiredError) as cm:
            self.client.request("/v1/test-typed-errors?status=410")
        self.assertEqual(cm.exception.status, 410)
        self.assertIsInstance(cm.exception, ExpiredError)

        # 422 Unprocessable Entity -> ValidationError
        with self.assertRaises(ValidationError) as cm:
            self.client.request("/v1/test-typed-errors?status=422")
        self.assertEqual(cm.exception.status, 422)
        self.assertIsInstance(cm.exception, ValidationError)
        self.assertIsNotNone(cm.exception.validation_errors)
        self.assertEqual(cm.exception.validation_errors.get("fields"), {"ip": "bad"})

        # 429 Rate Limit -> RateLimitError
        with self.assertRaises(RateLimitError) as cm:
            self.client.request("/v1/test-typed-errors?status=429")
        self.assertEqual(cm.exception.status, 429)
        self.assertIsInstance(cm.exception, RateLimitError)
        self.assertEqual(cm.exception.retry_after_seconds, 12)

        # 502 Bad Gateway -> ServerError
        with self.assertRaises(ServerError) as cm:
            self.client.request("/v1/test-typed-errors?status=502")
        self.assertEqual(cm.exception.status, 502)
        self.assertIsInstance(cm.exception, ServerError)

    def test_dual_control_dns_deletion_workflow(self) -> None:
        """Verifies dual-control human operator approval workflow for DNS deletions."""
        # 1. Request deletion (Actor A)
        req = self.client.dns.request_deletion(
            domain="aeitron.io",
            record_id="rec_001",
            reason="Decommissioning legacy CNAME",
        )
        self.assertEqual(req["status"], "PENDING_APPROVAL")
        self.assertEqual(req["requestId"], "del_req_mock_123")
        self.assertEqual(req["challengeToken"], "tok_challenge_abc")

        # 2. Operator approval (Actor B)
        approved = self.client.dns.approve_deletion(
            request_id=req["requestId"],
            actor="operator_human_lead",
        )
        self.assertEqual(approved["status"], "APPROVED")
        self.assertEqual(approved["approvalToken"], "tok_challenge_abc")

        # 3. Complete deletion with approved token and confirm=True
        del_res = self.client.dns.delete_record(
            zone_id="zone_01",
            record_id="rec_001",
            approval_token=approved["approvalToken"],
            confirm=True,
        )
        self.assertEqual(del_res["status"], "DELETED")
        self.assertEqual(del_res["record_id"], "rec_001")

    def test_challenge_guard_triggers_approval_required_error(self) -> None:
        """Verifies that calling delete without approval triggers ApprovalRequiredError."""
        with self.assertRaises(ApprovalRequiredError) as cm:
            self.client.dns.delete_record("zone_01", "rec_001", confirm=False)
        self.assertEqual(cm.exception.status, 403)
        self.assertEqual(cm.exception.challenge_request_id, "del_req_mock_123")
        self.assertEqual(cm.exception.domain, "aeitron.io")
        self.assertEqual(cm.exception.record_id, "rec_001")

    def test_webhook_signature_verification_and_anti_replay(self) -> None:
        """Verifies HMAC-SHA256 signature verification and replay prevention."""
        secret = "whsec_test_secret_key_888"
        payload = json.dumps({"event": "dns.record.updated", "zone": "aeitron.io"})
        now = int(time.time())

        # 1. Valid signature
        signed_payload = f"{now}.{payload}".encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
        valid_header = f"t={now},v1={sig}"

        self.assertTrue(WebhookSignature.verify(payload, valid_header, secret))

        # 2. Tampered body
        tampered_payload = json.dumps({"event": "dns.record.updated", "zone": "malicious.com"})
        with self.assertRaises(AuthenticationError):
            WebhookSignature.verify(tampered_payload, valid_header, secret)

        # 3. Wrong secret
        with self.assertRaises(AuthenticationError):
            WebhookSignature.verify(payload, valid_header, "whsec_wrong_secret")

        # 4. Replay attack with timestamp outside 300s tolerance
        stale_time = now - 600
        stale_signed = f"{stale_time}.{payload}".encode("utf-8")
        stale_sig = hmac.new(secret.encode("utf-8"), stale_signed, hashlib.sha256).hexdigest()
        stale_header = f"t={stale_time},v1={stale_sig}"

        with self.assertRaises(ValidationError) as cm:
            WebhookSignature.verify(payload, stale_header, secret, tolerance_seconds=300)
        self.assertIn("tolerance", str(cm.exception).lower())

    def test_automatic_retries_on_transient_503_errors(self) -> None:
        """Verifies automatic retry loop on transient 503 errors."""
        MockServerHandler.transient_counter = 0
        data, headers = self.client.request("/v1/transient-test", method="GET")
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("attempts"), 3)

    def test_idempotency_key_enables_retry_on_post(self) -> None:
        """Verifies Idempotency-Key header is transmitted and allows safe retry on POST."""
        MockServerHandler.idempotent_post_counter = 0
        data, headers = self.client.request(
            "/v1/idempotency-test",
            method="POST",
            body={"action": "test"},
            idempotency_key="idemp_key_test_777",
        )
        self.assertEqual(data.get("received_key"), "idemp_key_test_777")
        self.assertEqual(data.get("attempts"), 2)


if __name__ == "__main__":
    unittest.main()


