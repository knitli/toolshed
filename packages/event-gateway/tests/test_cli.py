"""Exercise the shipped CLI boundary in disposable private state."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import base64
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess  # nosec B404 - exercise our CLI with fixed interpreter, no shell
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from event_gateway import cli
from event_gateway.cloud import CloudError, _iso
from event_gateway.daemon import _execute_control_command
from event_gateway.security import SecurityError
from event_gateway.store import IDENTITY, Store


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name).resolve() / "state"
        self.command = [sys.executable, "-m", "event_gateway.cli",
                        "--state-dir", str(self.state)]

    def cli(self, *args, code=0):
        result = subprocess.run(  # nosec B603 - fixed interpreter and synthetic test arguments
            self.command + list(args), capture_output=True,
            text=True, timeout=10)
        self.assertEqual(result.returncode, code, result.stderr)
        return result.stdout

    def assert_disabled(self, value):
        self.assertFalse(value["automaticWakeEnabled"])
        self.assertIn("native_client_binding_unavailable", value["blockers"])
        self.assertIn("cloud_authority_not_integrated", value["blockers"])

    def test_launch_keyboard_interrupt_is_sanitized(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(cli, "launch", side_effect=KeyboardInterrupt("private interrupt detail")),
            redirect_stdout(stdout), redirect_stderr(stderr),
        ):
            try:
                code = cli.main([
                    "--state-dir", str(self.state), "launch",
                    "--codex-binary", "/unused/codex", "--binary-sha256", "unused",
                    "--cwd", str(self.state.parent),
                ])
            except KeyboardInterrupt:
                self.fail("KeyboardInterrupt escaped the CLI boundary")
        self.assertEqual(code, 130)
        self.assertEqual(json.loads(stderr.getvalue()), {"reason": "interrupted"})
        self.assertEqual(stdout.getvalue(), "")
        self.assertFalse(self.state.exists())

    def test_help_status_and_attachment_arguments(self):
        self.assertIn("knitli-event-gateway", self.cli("--help"))
        self.assertFalse(self.state.exists())
        self.assert_disabled(json.loads(self.cli("status")))
        help_text = self.cli("attach", "--help")
        self.assertIn("--session-id", help_text)
        self.assertIn("--cloud-config", help_text)
        self.assertNotIn("--thread-id", help_text)

    def test_attach_commits_challenge_sample_rechecks_and_persists_mapping(self):
        runtime_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
        binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                   "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                   "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
        challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": "2026-10-09T12:00:00.000Z",
                     "expiresAt": "2026-10-09T12:00:30.000Z"}
        evidence = {"observedAt": "2026-10-09T12:00:00.100Z",
                    "validUntilMonotonic": time.monotonic() + 0.5, "witness": {"fixture": True}}
        response = {"status": "attached", "runtimeId": runtime_id, "runtimeGeneration": 1,
                    "nodeId": str(uuid.uuid4()), "nodeGeneration": 1, "attachmentGeneration": 1,
                    "leaseUntil": _iso(time.time() + 90), "nativeBinding": binding}

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "adam@knitli.com", "codex"
            node_id, node_generation = str(uuid.uuid4()), 1

            async def native_challenge(self, intent):
                self.intent = intent
                return challenge

            async def attach(self, intent, request_challenge, request_evidence, *, on_first_send=None):
                self.asserted = (intent, request_challenge, request_evidence)
                if on_first_send:
                    on_first_send(b'{"prepared":"body"}')
                return response

        fake = FakeCloud()
        output, error = io.StringIO(), io.StringIO()
        with (
            patch.object(cli, "load_cloud_client", return_value=fake),
            patch.object(cli, "session_binding", side_effect=[binding, binding]),
            patch.object(cli, "session_challenge", return_value=evidence),
            redirect_stdout(output), redirect_stderr(error),
        ):
            code = cli.main(["--state-dir", str(self.state), "attach", "--runtime-id", runtime_id,
                             "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json")])
        self.assertEqual(code, 0, error.getvalue())
        self.assertEqual(error.getvalue(), "")
        value = json.loads(output.getvalue())
        self.assertEqual(value["remoteStatus"], "attached")
        self.assertEqual(value["localStatus"], "current")
        self.assertEqual(fake.intent["expectedNativeBinding"], binding)
        self.assertEqual(fake.asserted, (fake.intent, challenge, evidence))
        with Store(self.state) as store:
            mapping = store.get_attachment(runtime_id)
            self.assertEqual(mapping["nativeBinding"], binding)
            self.assertEqual(mapping["runtimeGeneration"], 1)
        self.assertIsNone(cli.load_pending_commit(self.state, "attach", session_id))

    def test_ambiguous_challenge_failure_is_definite_without_sampling_or_commit(self):
        for operation in ("attach", "renew", "transfer"):
            with self.subTest(operation=operation):
                state = self.state / operation
                session_id = str(uuid.uuid4())
                binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                           "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                           "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}

                class FakeCloud:
                    origin, principal, agent = "https://events.example.com", "adam@knitli.com", "codex"
                    node_id, node_generation = str(uuid.uuid4()), 1

                    async def native_challenge(self, _intent):
                        raise CloudError("request_timeout", ambiguous=True)

                    async def attach(self, *_args, **_kwargs):
                        raise AssertionError("challenge failure cannot reach attach commit")

                    async def renew(self, *_args, **_kwargs):
                        raise AssertionError("challenge failure cannot reach renew commit")

                    async def transfer(self, *_args, **_kwargs):
                        raise AssertionError("challenge failure cannot reach transfer commit")

                argv = ["--state-dir", str(state), operation]
                if operation == "attach":
                    argv.extend(("--runtime-id", str(uuid.uuid4())))
                elif operation == "renew":
                    argv.extend(("--runtime-id", str(uuid.uuid4()),
                                 "--expected-runtime-generation", "1",
                                 "--expected-attachment-generation", "2"))
                else:
                    argv.extend(("--source-runtime-id", str(uuid.uuid4()),
                                 "--expected-source-runtime-generation", "1",
                                 "--expected-source-attachment-generation", "2",
                                 "--replacement-runtime-id", str(uuid.uuid4()),
                                 "--expected-replacement-runtime-generation", "1",
                                 "--expected-replacement-attachment-generation", "2"))
                argv.extend(("--session-id", session_id, "--cloud-config", str(state / "cloud.json")))
                output = io.StringIO()
                with (patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
                      patch.object(cli, "session_binding", return_value=binding),
                      patch.object(cli, "session_challenge", side_effect=AssertionError(
                          "a failed cloud challenge cannot request a native sample")),
                      redirect_stdout(output)):
                    code = cli.main(argv)

                self.assertEqual(code, 2)
                result = json.loads(output.getvalue())
                result_key = {"attach": "attached", "renew": "renewed", "transfer": "transferred"}[operation]
                self.assertFalse(result[result_key])
                self.assertEqual(result["reason"], "challenge_outcome_unknown")
                self.assertFalse((state / ".native-pending").exists())

    def test_definitive_replay_refusal_preserves_prior_unknown_commit(self):
        for error_code in ("denied", "conflict"):
            with self.subTest(error_code=error_code):
                runtime_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
                binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                           "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                           "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
                challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time()),
                             "expiresAt": _iso(time.time() + 30)}
                intent = {"operation": "attach", "runtimeId": runtime_id,
                          "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
                          "expectedNativeBinding": binding}
                evidence = {"observedAt": challenge["issuedAt"], "witness": {"sequence": 1}}
                body = json.dumps({"challengeId": challenge["challengeId"], "runtimeId": runtime_id,
                                   "expectedRuntimeGeneration": None,
                                   "expectedAttachmentGeneration": None,
                                   "nativeEvidence": evidence}, separators=(",", ":")).encode()
                cloud_id = {"origin": "https://events.example.com", "principal": "adam@knitli.com",
                            "agent": "codex", "nodeId": str(uuid.uuid4()), "nodeGeneration": 1}
                artifact = {"version": 1, "operation": "attach", "sessionId": session_id,
                            "cloudIdentity": cloud_id, "intent": intent, "challenge": challenge,
                            "evidence": evidence, "bodyB64": base64.b64encode(body).decode("ascii"),
                            "safeExpiryAt": _iso(time.time() + 60)}
                cli.save_pending_commit(self.state, "attach", session_id, artifact)

                class FakeCloud:
                    origin, principal, agent = cloud_id["origin"], cloud_id["principal"], cloud_id["agent"]
                    node_id, node_generation = cloud_id["nodeId"], cloud_id["nodeGeneration"]

                    async def attach(self, *_args, **_kwargs):
                        raise CloudError(error_code)

                output = io.StringIO()
                with (patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
                      patch.object(cli, "session_binding", return_value=binding),
                      patch.object(cli, "session_challenge", side_effect=AssertionError("must not resample")),
                      redirect_stdout(output)):
                    code = cli.main([
                        "--state-dir", str(self.state), "attach", "--runtime-id", runtime_id,
                        "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json"),
                    ])

                self.assertEqual(code, 2)
                result = json.loads(output.getvalue())
                self.assertIsNone(result["attached"])
                self.assertEqual(result["reason"], "commit_outcome_unknown")
                self.assertEqual(result["lastError"], error_code)
                retained = cli.load_pending_commit(self.state, "attach", session_id)
                self.assertEqual(retained, artifact)
                self.assertEqual(base64.b64decode(retained["bodyB64"]), body)

    def test_postcommit_launcher_transport_error_reports_remote_success_and_keeps_pending(self):
        for error in (OSError("launcher socket disappeared"), TimeoutError("launcher timed out")):
            with self.subTest(error=type(error).__name__):
                runtime_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
                binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                           "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                           "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
                challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time()),
                             "expiresAt": _iso(time.time() + 30)}
                response = {"status": "attached", "runtimeId": runtime_id, "runtimeGeneration": 1,
                            "nodeId": str(uuid.uuid4()), "nodeGeneration": 1, "attachmentGeneration": 1,
                            "leaseUntil": _iso(time.time() + 90), "nativeBinding": binding}

                class FakeCloud:
                    origin, principal, agent = "https://events.example.com", "adam@knitli.com", "codex"
                    node_id, node_generation = response["nodeId"], 1

                    async def native_challenge(self, _intent):
                        return challenge

                    async def attach(self, *_args, on_first_send=None):
                        on_first_send(b'{"prepared":"body"}')
                        return response

                output = io.StringIO()
                with (patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
                      patch.object(cli, "session_binding", side_effect=[binding, error]),
                      patch.object(cli, "session_challenge", return_value={
                          "observedAt": challenge["issuedAt"],
                          "validUntilMonotonic": time.monotonic() + 0.5,
                          "witness": {"fixture": True},
                      }),
                      redirect_stdout(output)):
                    code = cli.main([
                        "--state-dir", str(self.state), "attach", "--runtime-id", runtime_id,
                        "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json"),
                    ])

                self.assertEqual(code, 2)
                result = json.loads(output.getvalue())
                self.assertEqual(result["remoteStatus"], "attached")
                self.assertEqual(result["localStatus"], "not_current")
                self.assertEqual(result["reason"], "native_client_unavailable_after_commit")
                self.assertEqual(cli.load_pending_commit(self.state, "attach", session_id)["operation"], "attach")

    def test_attach_lost_commit_reply_reports_unknown_without_false_detach(self):
        runtime_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
        binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                   "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                   "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "adam@knitli.com", "codex"
            node_id, node_generation = str(uuid.uuid4()), 1

            async def native_challenge(self, _intent):
                return {"challengeId": str(uuid.uuid4()), "issuedAt": "2026-10-09T12:00:00.000Z",
                        "expiresAt": "2026-10-09T12:00:30.000Z"}

            async def attach(self, *_args, on_first_send=None):
                on_first_send(b'{"prepared":"body"}')
                raise CloudError("request_timeout", ambiguous=True)

        output = io.StringIO()
        with (patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
              patch.object(cli, "session_binding", return_value=binding),
              patch.object(cli, "session_challenge", return_value={
                  "observedAt": "2026-10-09T12:00:00.100Z", "witness": {"fixture": True},
                  "validUntilMonotonic": time.monotonic() + 0.5,
              }),
              redirect_stdout(output)):
            code = cli.main(["--state-dir", str(self.state), "attach", "--runtime-id", runtime_id,
                             "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json")])
        self.assertEqual(code, 2)
        value = json.loads(output.getvalue())
        self.assertEqual(value["attached"], None)
        self.assertEqual(value["reason"], "commit_outcome_unknown")
        self.assertEqual(value["pendingCommit"]["status"], "outcome_unknown")
        self.assertEqual(value["pendingCommit"]["operation"], "attach")
        self.assertTrue(self.state.exists())
        pending = cli.load_pending_commit(self.state, "attach", session_id)
        self.assertEqual(base64.b64decode(pending["bodyB64"]), b'{"prepared":"body"}')

    def test_pending_commit_survives_launcher_transport_oserror_and_timeout(self):
        for error in (OSError("launcher socket disappeared"), TimeoutError("launcher timed out")):
            with self.subTest(error=type(error).__name__):
                runtime_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
                binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                           "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                           "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
                cloud_id = {"origin": "https://events.example.com", "principal": "adam@knitli.com",
                            "agent": "codex", "nodeId": str(uuid.uuid4()), "nodeGeneration": 1}
                challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time()),
                             "expiresAt": _iso(time.time() + 30)}
                intent = {"operation": "attach", "runtimeId": runtime_id,
                          "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
                          "expectedNativeBinding": binding}
                evidence = {"observedAt": challenge["issuedAt"], "witness": {"sequence": 1}}
                body = json.dumps({"challengeId": challenge["challengeId"], "runtimeId": runtime_id,
                                   "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
                                   "nativeEvidence": evidence}, separators=(",", ":")).encode()
                artifact = {"version": 1, "operation": "attach", "sessionId": session_id,
                            "cloudIdentity": cloud_id, "intent": intent, "challenge": challenge,
                            "evidence": evidence, "bodyB64": base64.b64encode(body).decode("ascii"),
                            "safeExpiryAt": _iso(time.time() + 90)}
                cli.save_pending_commit(self.state, "attach", session_id, artifact)

                class FakeCloud:
                    origin, principal, agent = cloud_id["origin"], cloud_id["principal"], cloud_id["agent"]
                    node_id, node_generation = cloud_id["nodeId"], cloud_id["nodeGeneration"]

                    async def attach(self, *_args, **_kwargs):
                        raise AssertionError("must not replay before confirming the native binding")

                output, stderr = io.StringIO(), io.StringIO()
                with (
                    patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
                    patch.object(cli, "session_binding", side_effect=error),
                    patch.object(cli, "session_challenge", side_effect=AssertionError("must not resample")),
                    redirect_stdout(output), redirect_stderr(stderr),
                ):
                    code = cli.main(["--state-dir", str(self.state), "attach", "--runtime-id", runtime_id,
                                     "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json")])

                self.assertEqual(code, 2)
                self.assertEqual(stderr.getvalue(), "")
                result = json.loads(output.getvalue())
                self.assertIsNone(result["attached"])
                self.assertEqual(result["reason"], "commit_outcome_unknown")
                self.assertEqual(result["pendingCommit"]["status"], "outcome_unknown")
                self.assertEqual(cli.load_pending_commit(self.state, "attach", session_id), artifact)

    def test_stale_control_socket_falls_back_only_when_store_lock_is_available(self):
        binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                   "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                   "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}

        def run_case(label, request_error, *, hold_writer=False, forbid_fallback=False):
            state = self.state / label
            state.mkdir(parents=True, mode=0o700)
            (state / "control.sock").touch(mode=0o600)
            runtime_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
            cloud_id = {"origin": "https://events.example.com", "principal": "adam@knitli.com",
                        "agent": "codex", "nodeId": str(uuid.uuid4()), "nodeGeneration": 1}
            challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time()),
                         "expiresAt": _iso(time.time() + 30)}
            evidence = {"observedAt": challenge["issuedAt"], "validUntilMonotonic": time.monotonic() + 0.5,
                        "witness": {"fixture": True}}
            response = {"status": "attached", "runtimeId": runtime_id, "runtimeGeneration": 1,
                        "nodeId": cloud_id["nodeId"], "nodeGeneration": 1, "attachmentGeneration": 1,
                        "leaseUntil": _iso(time.time() + 90), "nativeBinding": binding}

            class FakeCloud:
                origin, principal, agent = cloud_id["origin"], cloud_id["principal"], cloud_id["agent"]
                node_id, node_generation = cloud_id["nodeId"], cloud_id["nodeGeneration"]

                async def native_challenge(self, _intent):
                    return challenge

                async def attach(self, _intent, _challenge, _evidence, *, on_first_send=None):
                    on_first_send(b'{"prepared":"body"}')
                    return response

            async def daemon_request(_state_dir, _command):
                raise request_error

            output, stderr = io.StringIO(), io.StringIO()

            def invoke():
                with ExitStack() as stack:
                    stack.enter_context(patch.object(cli, "load_cloud_client", return_value=FakeCloud()))
                    stack.enter_context(patch.object(cli, "session_binding", side_effect=[binding, binding]))
                    stack.enter_context(patch.object(cli, "session_challenge", return_value=evidence))
                    stack.enter_context(patch.object(cli, "request", side_effect=daemon_request))
                    if forbid_fallback:
                        stack.enter_context(patch.object(cli, "Store", side_effect=AssertionError(
                            "a control timeout is not proof that the daemon has stopped")))
                    stack.enter_context(redirect_stdout(output))
                    stack.enter_context(redirect_stderr(stderr))
                    return cli.main(["--state-dir", str(state), "attach", "--runtime-id", runtime_id,
                                     "--session-id", session_id, "--cloud-config", str(state / "cloud.json")])

            result = None
            if hold_writer:
                with Store(state) as daemon_store:
                    sentinel_id = str(uuid.uuid4())
                    sentinel = {"runtimeId": sentinel_id, "principal": cloud_id["principal"],
                                "agent": cloud_id["agent"], "nodeGeneration": 1,
                                "runtimeGeneration": 1, "attachmentGeneration": 1,
                                "leaseExpiresAt": time.time() + 90}
                    daemon_store.put_attachment(sentinel)
                    before = daemon_store.get_attachment(sentinel_id)
                    code = invoke()
                    result = json.loads(output.getvalue())
                    self.assertEqual(daemon_store.get_attachment(sentinel_id), before)
                    self.assertIsNone(daemon_store.get_attachment(runtime_id))
            else:
                code = invoke()
                result = json.loads(output.getvalue())
                with Store(state) as store:
                    self.assertEqual(store.get_attachment(runtime_id) is not None, request_error.__class__ in (
                        ConnectionRefusedError, FileNotFoundError,
                    ))

            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(code, 0 if result["localStatus"] == "current" else 2)
            self.assertEqual(result["remoteStatus"], "attached")
            if request_error.__class__ in (ConnectionRefusedError, FileNotFoundError) and not hold_writer:
                self.assertEqual(result["localStatus"], "current")
                self.assertIsNone(cli.load_pending_commit(state, "attach", session_id))
            else:
                self.assertEqual(result["localStatus"], "unavailable")
                self.assertEqual(result["reason"], "local_mapping_unavailable")
                self.assertIsNotNone(cli.load_pending_commit(state, "attach", session_id))

        run_case("refused", ConnectionRefusedError("stale daemon socket"))
        run_case("disappeared", FileNotFoundError("control socket disappeared"))
        run_case("busy", ConnectionRefusedError("daemon stopped"), hold_writer=True)
        run_case("timed-out", TimeoutError("daemon socket timed out"), forbid_fallback=True)

    def test_pending_commit_restart_replays_exact_body_without_native_resampling(self):
        runtime_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
        binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                   "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                   "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
        challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time()),
                     "expiresAt": _iso(time.time() + 30)}
        intent = {"operation": "attach", "runtimeId": runtime_id,
                  "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
                  "expectedNativeBinding": binding}
        witness = {"version": 2, "nonce": 0, "clientId": binding["clientId"],
                   "backendPid": binding["backendPid"], "connectionId": binding["connectionId"],
                   "threadId": binding["threadId"], "generation": binding["generation"],
                   "eligible": True, "sequence": 1, "cause": "",
                   "serverInstanceId": binding["serverInstanceId"],
                   "serverGeneration": binding["serverGeneration"], "leaseMs": 750}
        evidence = {"observedAt": challenge["issuedAt"], "witness": witness}
        body = json.dumps({"challengeId": challenge["challengeId"], "runtimeId": runtime_id,
                           "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
                           "nativeEvidence": evidence}, separators=(",", ":"), ensure_ascii=False).encode()
        cloud_id = {"origin": "https://events.example.com", "principal": "adam@knitli.com",
                    "agent": "codex", "nodeId": str(uuid.uuid4()), "nodeGeneration": 1}
        artifact = {"version": 1, "operation": "attach", "sessionId": session_id,
                    "cloudIdentity": cloud_id, "intent": intent, "challenge": challenge,
                    "evidence": evidence, "bodyB64": base64.b64encode(body).decode("ascii"),
                    "safeExpiryAt": _iso(time.time() + 90)}
        cli.save_pending_commit(self.state, "attach", session_id, artifact)
        response = {"status": "attached", "runtimeId": runtime_id, "runtimeGeneration": 1,
                    "nodeId": cloud_id["nodeId"], "nodeGeneration": 1, "attachmentGeneration": 1,
                    "leaseUntil": _iso(time.time() + 90), "nativeBinding": binding}

        class FakeCloud:
            origin, principal, agent = cloud_id["origin"], cloud_id["principal"], cloud_id["agent"]
            node_id, node_generation = cloud_id["nodeId"], cloud_id["nodeGeneration"]

            async def attach(self, request, saved_challenge, saved_evidence, *, prepared_body=None, recovery=False):
                self.replayed = (request, saved_challenge, saved_evidence, prepared_body, recovery)
                return response

        fake = FakeCloud()
        output = io.StringIO()
        with (patch.object(cli, "load_cloud_client", return_value=fake),
              patch.object(cli, "session_binding", side_effect=[binding, binding]),
              patch.object(cli, "session_challenge", side_effect=AssertionError("must not resample")),
              redirect_stdout(output)):
            code = cli.main(["--state-dir", str(self.state), "attach", "--runtime-id", runtime_id,
                             "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json")])
        self.assertEqual(code, 0)
        self.assertEqual(fake.replayed, (intent, challenge, evidence, body, True))
        self.assertIsNone(cli.load_pending_commit(self.state, "attach", session_id))

    def test_concurrent_loser_preserves_winner_pending_commit(self):
        runtime_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
        binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                   "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                   "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
        challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time()),
                     "expiresAt": _iso(time.time() + 30)}

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "adam@knitli.com", "codex"
            node_id, node_generation = str(uuid.uuid4()), 1

            async def native_challenge(self, _intent):
                return challenge

            async def attach(self, _intent, _challenge, _evidence, *, on_first_send=None):
                on_first_send(b'{"loser":"body"}')

        original_save = cli.save_pending_commit

        def another_invocation_won(state_dir, operation, ident, candidate):
            original_save(state_dir, operation, ident, candidate)
            raise SecurityError("pending_commit_exists")

        output = io.StringIO()
        with (patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
              patch.object(cli, "save_pending_commit", side_effect=another_invocation_won),
              patch.object(cli, "session_binding", return_value=binding),
              patch.object(cli, "session_challenge", return_value={
                  "observedAt": challenge["issuedAt"],
                  "validUntilMonotonic": time.monotonic() + 0.5,
                  "witness": {"fixture": True},
              }),
              redirect_stdout(output)):
            code = cli.main(["--state-dir", str(self.state), "attach", "--runtime-id", runtime_id,
                             "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json")])
        self.assertEqual(code, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["reason"], "commit_outcome_unknown")
        self.assertEqual(result["lastError"], "pending_commit_exists")
        pending = cli.load_pending_commit(self.state, "attach", session_id)
        self.assertEqual(base64.b64decode(pending["bodyB64"]), b'{"loser":"body"}')

    def test_pending_commit_past_safe_cutoff_stays_unknown_without_retry(self):
        runtime_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
        binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                   "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                   "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
        challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time() - 120),
                     "expiresAt": _iso(time.time() - 90)}
        intent = {"operation": "attach", "runtimeId": runtime_id,
                  "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
                  "expectedNativeBinding": binding}
        cloud_id = {"origin": "https://events.example.com", "principal": "adam@knitli.com",
                    "agent": "codex", "nodeId": str(uuid.uuid4()), "nodeGeneration": 1}
        artifact = {"version": 1, "operation": "attach", "sessionId": session_id,
                    "cloudIdentity": cloud_id, "intent": intent, "challenge": challenge,
                    "evidence": {"observedAt": _iso(time.time() - 120), "witness": {"sequence": 1}},
                    "bodyB64": base64.b64encode(b"{}").decode("ascii"),
                    "safeExpiryAt": _iso(time.time() - 1)}
        cli.save_pending_commit(self.state, "attach", session_id, artifact)

        class FakeCloud:
            origin, principal, agent = cloud_id["origin"], cloud_id["principal"], cloud_id["agent"]
            node_id, node_generation = cloud_id["nodeId"], cloud_id["nodeGeneration"]

            async def attach(self, *_args, **_kwargs):
                raise AssertionError("expired receipt must not be retried")

        output = io.StringIO()
        with (patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
              patch.object(cli, "session_binding", return_value=binding),
              patch.object(cli, "session_challenge", side_effect=AssertionError("must not resample")),
              redirect_stdout(output)):
            code = cli.main(["--state-dir", str(self.state), "attach", "--runtime-id", runtime_id,
                             "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json")])
        self.assertEqual(code, 2)
        value = json.loads(output.getvalue())
        self.assertEqual(value["reason"], "commit_outcome_unknown")
        self.assertEqual(value["lastError"], "pending_receipt_window_closed")
        self.assertEqual(cli.load_pending_commit(self.state, "attach", session_id), artifact)

    def test_transfer_uses_running_daemon_as_single_store_writer(self):
        source_id, replacement_id, session_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                   "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                   "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
        cloud_id = {"origin": "https://events.example.com", "principal": "adam@knitli.com",
                    "agent": "codex", "nodeId": str(uuid.uuid4()), "nodeGeneration": 1}
        challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time()),
                     "expiresAt": _iso(time.time() + 30)}
        response = {"status": "transferred", "sourceRuntimeId": source_id,
                    "sourceRuntimeGeneration": 3, "sourceAttachmentGeneration": 4,
                    "runtimeId": replacement_id, "runtimeGeneration": 7,
                    "nodeId": cloud_id["nodeId"], "nodeGeneration": 1, "attachmentGeneration": 9,
                    "leaseUntil": _iso(time.time() + 90), "nativeBinding": binding}
        expected_cas = {
            "sourceRuntimeId": source_id,
            "expectedRuntimeGeneration": 2, "expectedAttachmentGeneration": 3,
            "runtimeGeneration": 3, "attachmentGeneration": 4,
        }

        class FakeCloud:
            origin, principal, agent = cloud_id["origin"], cloud_id["principal"], cloud_id["agent"]
            node_id, node_generation = cloud_id["nodeId"], cloud_id["nodeGeneration"]

            async def native_challenge(self, intent):
                self.intent = intent
                return challenge

            async def transfer(self, intent, saved_challenge, evidence, *, on_first_send=None):
                self.commit = (intent, saved_challenge, evidence)
                on_first_send(b'{"exact":"body"}')
                return response

        fake = FakeCloud()
        self.state.mkdir(mode=0o700)
        (self.state / "control.sock").touch(mode=0o600)
        output = io.StringIO()
        with Store(self.state) as daemon_store:
            async def daemon_request(_state_dir, command):
                self.assertEqual(command["command"], "transfer-attachment")
                self.assertEqual(command["transfer"], expected_cas)
                stored = daemon_store.put_attachment(command["mapping"], transfer=command["transfer"])
                return {"stored": True, "runtimeId": stored["runtimeId"]}

            with (patch.object(cli, "load_cloud_client", return_value=fake),
                  patch.object(cli, "session_binding", side_effect=[binding, binding]),
                  patch.object(cli, "session_challenge", return_value={
                      "observedAt": challenge["issuedAt"], "validUntilMonotonic": time.monotonic() + 0.5,
                      "witness": {"fixture": True},
                  }),
                  patch.object(cli, "request", side_effect=daemon_request),
                  patch.object(cli, "Store", side_effect=AssertionError("second writer opened")),
                  redirect_stdout(output)):
                code = cli.main([
                    "--state-dir", str(self.state), "transfer",
                    "--source-runtime-id", source_id,
                    "--expected-source-runtime-generation", "2",
                    "--expected-source-attachment-generation", "3",
                    "--replacement-runtime-id", replacement_id,
                    "--expected-replacement-runtime-generation", "7",
                    "--expected-replacement-attachment-generation", "8",
                    "--session-id", session_id,
                    "--cloud-config", str(self.state / "cloud.json"),
                ])

            self.assertEqual(code, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["remoteStatus"], "transferred")
            self.assertEqual(result["localStatus"], "current")
            self.assertIsNone(daemon_store.get_attachment(source_id))
            self.assertEqual(daemon_store.get_attachment(replacement_id)["attachmentGeneration"], 9)
        pending = cli.load_pending_commit(self.state, "transfer", session_id)
        self.assertIsNone(pending)

    def test_confirmed_transfer_fences_source_before_native_recheck_and_recovers_target(self):
        fixture_path = Path(__file__).resolve().parents[1] / "contracts/event-v1/protocol-v1.json"
        event = json.loads(fixture_path.read_text())["validEnvelopes"][0]
        fixed_now = 1791201630

        def run_case(label, post_commit_binding, *, recover):
            state = self.state / label
            state.mkdir(mode=0o700, parents=True)
            (state / "control.sock").touch(mode=0o600)
            source_id, replacement_id, session_id = event["runtimeId"], str(uuid.uuid4()), str(uuid.uuid4())
            binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                       "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                       "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
            cloud_id = {"origin": "https://events.example.com", "principal": event["principal"],
                        "agent": event["agent"], "nodeId": str(uuid.uuid4()), "nodeGeneration": 1}
            challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(time.time()),
                         "expiresAt": _iso(time.time() + 30)}
            response = {"status": "transferred", "sourceRuntimeId": source_id,
                        "sourceRuntimeGeneration": 3, "sourceAttachmentGeneration": 4,
                        "runtimeId": replacement_id, "runtimeGeneration": 7,
                        "nodeId": cloud_id["nodeId"], "nodeGeneration": 1, "attachmentGeneration": 9,
                        "leaseUntil": _iso(fixed_now + 3600), "nativeBinding": binding}

            class FakeCloud:
                origin, principal, agent = cloud_id["origin"], cloud_id["principal"], cloud_id["agent"]
                node_id, node_generation = cloud_id["nodeId"], cloud_id["nodeGeneration"]

                def __init__(self):
                    self.recoveries = []

                async def native_challenge(self, _intent):
                    return challenge

                async def transfer(self, _intent, _challenge, _evidence, *, on_first_send=None,
                                   prepared_body=None, recovery=False):
                    self.recoveries.append(recovery)
                    if on_first_send is not None:
                        on_first_send(b'{"transfer":"exact-body"}')
                    return response

            fake = FakeCloud()
            daemon_commands = []
            with Store(state, clock=lambda: fixed_now) as daemon_store:
                source = {key: event[key] for key in IDENTITY}
                source["leaseExpiresAt"] = fixed_now + 3600
                daemon_store.put_attachment(source)
                queued = daemon_store.accept(event)["deliveryId"]

                def daemon_request(_state_dir, command):
                    daemon_commands.append(command["command"])
                    return _execute_control_command(daemon_store, command)

                initial_bindings = [binding, post_commit_binding]
                first_output = io.StringIO()
                with (patch.object(cli, "load_cloud_client", return_value=fake),
                      patch.object(cli, "session_binding", side_effect=initial_bindings),
                      patch.object(cli, "session_challenge", return_value={
                          "observedAt": challenge["issuedAt"],
                          "validUntilMonotonic": time.monotonic() + 0.5,
                          "witness": {"fixture": True},
                      }),
                      patch.object(cli, "request", side_effect=daemon_request),
                      redirect_stdout(first_output)):
                    first_code = cli.main([
                        "--state-dir", str(state), "transfer",
                        "--source-runtime-id", source_id,
                        "--expected-source-runtime-generation", "2",
                        "--expected-source-attachment-generation", "3",
                        "--replacement-runtime-id", replacement_id,
                        "--expected-replacement-runtime-generation", "7",
                        "--expected-replacement-attachment-generation", "8",
                        "--session-id", session_id, "--cloud-config", str(state / "cloud.json"),
                    ])
                first_result = json.loads(first_output.getvalue())
                self.assertEqual(first_code, 2)
                self.assertEqual(first_result["remoteStatus"], "transferred")
                self.assertEqual(first_result["localStatus"], "not_current")
                self.assertIsNone(daemon_store.get_attachment(source_id))
                self.assertIsNone(daemon_store.get_attachment(replacement_id))
                self.assertEqual(daemon_store.get(queued)["status"], "stale")
                source_tombstone = json.loads(daemon_store.db.execute(
                    "SELECT data FROM attachments WHERE runtime=?", (source_id,),
                ).fetchone()[0])
                self.assertEqual(source_tombstone["leaseExpiresAt"], 0)
                self.assertEqual(daemon_commands, ["revoke-transfer-source"])
                self.assertIsNotNone(cli.load_pending_commit(state, "transfer", session_id))

                if recover:
                    second_output = io.StringIO()
                    with (patch.object(cli, "load_cloud_client", return_value=fake),
                          patch.object(cli, "session_binding", side_effect=[binding, binding]),
                          patch.object(cli, "session_challenge", side_effect=AssertionError("must not resample")),
                          patch.object(cli, "request", side_effect=daemon_request),
                          redirect_stdout(second_output)):
                        second_code = cli.main([
                            "--state-dir", str(state), "transfer",
                            "--source-runtime-id", source_id,
                            "--expected-source-runtime-generation", "2",
                            "--expected-source-attachment-generation", "3",
                            "--replacement-runtime-id", replacement_id,
                            "--expected-replacement-runtime-generation", "7",
                            "--expected-replacement-attachment-generation", "8",
                            "--session-id", session_id, "--cloud-config", str(state / "cloud.json"),
                        ])
                    self.assertEqual(second_code, 0)
                    self.assertEqual(json.loads(second_output.getvalue())["localStatus"], "current")
                    self.assertEqual(fake.recoveries, [False, True])
                    self.assertEqual(daemon_commands, ["revoke-transfer-source", "transfer-attachment"])
                    self.assertEqual(daemon_store.get_attachment(replacement_id)["attachmentGeneration"], 9)
                    self.assertEqual(daemon_store.get(queued)["status"], "stale")
                    self.assertIsNone(cli.load_pending_commit(state, "transfer", session_id))
                else:
                    self.assertEqual(first_result["reason"], "native_binding_changed_after_commit")
                    self.assertIsNotNone(cli.load_pending_commit(state, "transfer", session_id))

        run_case("native-gone", OSError("launcher socket disappeared"), recover=True)
        changed_binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                           "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 3,
                           "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
        run_case("native-changed", changed_binding, recover=False)

    def test_client_status_labels_presence_only(self):
        output = io.StringIO()
        presence = {"attached": False, "selection": "selected"}
        with (patch.object(cli, "session_status", return_value=presence), redirect_stdout(output)):
            code = cli.main(["--state-dir", str(self.state), "client-status", "--session-id", str(uuid.uuid4())])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue()), {
            "scope": "local_native_presence_only", "presence": presence,
        })

    def test_enrollment_is_pending_and_key_stays_private(self):
        result = json.loads(self.cli("enroll", "--challenge", "owner-123", code=2))
        self.assertEqual(result["status"], "owner_enrollment_pending")
        self.assertEqual(result["reason"], "cloud_enrollment_not_integrated")
        self.assertEqual(result["challenge"], "owner-123")
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        key = self.state / "node-key.pem"
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        original = key.read_bytes()
        again = json.loads(self.cli("enroll", "--challenge", "owner-456", code=2))
        self.assertEqual(result["publicKey"], again["publicKey"])
        self.assertEqual(original, key.read_bytes())
        self.assertNotIn("PRIVATE", json.dumps(result))

    @unittest.skipUnless(os.name == "posix", "Unix control socket")
    def test_daemon_status_and_clean_signal_stop(self):
        process = subprocess.Popen(  # nosec B603 - fixed interpreter and literal daemon command
            self.command + ["run"], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        try:
            socket = self.state / "control.sock"
            deadline = time.monotonic() + 5
            while not socket.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIsNone(process.poll(), "daemon exited before opening control socket")
            self.assertTrue(socket.exists(), "daemon did not open control socket")
            self.assertEqual(stat.S_IMODE(socket.stat().st_mode), 0o600)
            self.assert_disabled(json.loads(self.cli("status")))
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stdout + stderr)
            self.assertFalse(socket.exists())
            self.assert_disabled(json.loads(self.cli("status")))
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
