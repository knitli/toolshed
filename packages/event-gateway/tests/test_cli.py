"""Exercise the shipped CLI boundary in disposable private state."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import base64
from concurrent.futures import ThreadPoolExecutor
import fcntl
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess  # nosec B404 - exercise our CLI with fixed interpreter, no shell
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from event_gateway import cli
from event_gateway.cloud import CloudError, _iso
from event_gateway.daemon import _execute_control_command
from event_gateway.protocol import derive_delivery_id
from event_gateway.security import SecurityError
from event_gateway.store import IDENTITY, Store
from test_daemon import control_socket_ready


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

    def test_enrollment_cli_only_exposes_enroll_and_status(self):
        help_output = io.StringIO()
        with redirect_stdout(help_output), self.assertRaises(SystemExit) as exit_info:
            cli.enrollment_main(["--help"])
        self.assertEqual(exit_info.exception.code, 0)
        self.assertIn("{status,enroll}", help_output.getvalue())
        self.assertNotIn("run", help_output.getvalue())
        self.assertNotIn("attach", help_output.getvalue())

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.enrollment_main(["--state-dir", str(self.state), "status"]), 0)
        self.assert_disabled(json.loads(output.getvalue()))

        with patch.object(cli, "_execute_enrollment", return_value=0) as enroll:
            self.assertEqual(cli.enrollment_main([
                "--state-dir", str(self.state), "enroll", "--challenge", "owner-approved",
            ]), 0)
        enroll.assert_called_once()

    def test_enrollment_cli_rejects_runtime_commands_before_state_or_external_work(self):
        commands = (
            "run", "launch", "client-status", "attach", "renew", "transfer",
            "runtime-status", "stock-control", "github-event-read", "github-source-read",
            "github-source-material", "reconcile", "detach",
        )
        arguments = {
            "launch": ["--codex-binary", "/unused", "--binary-sha256", "unused", "--cwd", "/unused"],
            "client-status": ["--session-id", "session"],
            "attach": ["--runtime-id", "runtime", "--session-id", "session", "--cloud-config", "config"],
            "renew": ["--runtime-id", "runtime", "--session-id", "session", "--cloud-config", "config",
                       "--expected-runtime-generation", "1", "--expected-attachment-generation", "1"],
            "transfer": ["--source-runtime-id", "source", "--expected-source-runtime-generation", "1",
                         "--expected-source-attachment-generation", "1", "--replacement-runtime-id", "target",
                         "--expected-replacement-runtime-generation", "1", "--expected-replacement-attachment-generation", "1",
                         "--session-id", "session", "--cloud-config", "config"],
            "runtime-status": ["--runtime-id", "runtime", "--cloud-config", "config"],
            "stock-control": ["attach", "--runtime-id", "runtime", "--conversation-id", "conversation", "--cloud-config", "config"],
            "github-event-read": ["--cloud-config", "config", "--event-reference", "reference"],
            "github-source-read": ["--cloud-config", "config", "--installation-id", "1", "--repository-id", "1",
                                   "--pr-number", "1", "--from-version", "1", "--to-version", "1"],
            "github-source-material": ["--cloud-config", "config", "--installation-id", "1", "--repository-id", "1",
                                       "--pr-number", "1", "--from-version", "1", "--to-version", "1",
                                       "--source-id", "source", "--fingerprint", "fingerprint", "--private-output", "output"],
            "reconcile": ["--operation", "attach", "--original-session-id", "original", "--session-id", "session",
                          "--cloud-config", "config"],
            "detach": ["runtime"],
        }
        for command in commands:
            with self.subTest(command=command):
                state = self.state / command
                stderr = io.StringIO()
                with (
                    redirect_stderr(stderr),
                    patch.object(cli, "_execute_command", side_effect=AssertionError("dispatched")),
                    patch.object(cli, "serve", side_effect=AssertionError("started daemon")),
                    patch.object(cli, "launch", side_effect=AssertionError("started client")),
                    patch.object(cli, "load_cloud_client", side_effect=AssertionError("network auth")),
                    self.assertRaises(SystemExit) as exit_info,
                ):
                    cli.enrollment_main(["--state-dir", str(state), command, *arguments.get(command, [])])
                self.assertEqual(exit_info.exception.code, 2)
                self.assertIn("invalid choice", stderr.getvalue())
                self.assertFalse(state.exists())

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
        enroll_help = self.cli("enroll", "--help")
        self.assertIn("prepares the local node key", enroll_help)
        self.assertNotIn("Legacy", enroll_help)

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
                    on_first_send(b'{"prepared":"body","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}')
                return response

            renew = attach

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
            self.assertEqual(mapping["sessionId"], session_id)
            self.assertEqual(mapping["nativeThreadId"], binding["threadId"])
            self.assertEqual(mapping["runtimeGeneration"], 1)
        self.assertIsNone(cli.load_pending_commit(self.state, "attach", session_id))

        response.update(status="renewed", leaseUntil=_iso(time.time() + 180))
        output = io.StringIO()
        with (
            patch.object(cli, "load_cloud_client", return_value=fake),
            patch.object(cli, "session_binding", side_effect=[binding, binding]),
            patch.object(cli, "session_challenge", return_value=evidence),
            redirect_stdout(output),
        ):
            code = cli.main(["--state-dir", str(self.state), "renew", "--runtime-id", runtime_id,
                             "--expected-runtime-generation", "1", "--expected-attachment-generation", "1",
                             "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json")])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["remoteStatus"], "renewed")
        with Store(self.state) as store:
            renewed = store.get_attachment(runtime_id)
            self.assertGreater(renewed["leaseExpiresAt"], mapping["leaseExpiresAt"])
            self.assertEqual({key: value for key, value in renewed.items() if key != "leaseExpiresAt"},
                             {key: value for key, value in mapping.items() if key != "leaseExpiresAt"})
        self.assertIsNone(cli.load_pending_commit(self.state, "renew", session_id))

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
                        on_first_send(b'{"prepared":"body","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}')
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
                on_first_send(b'{"prepared":"body","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}')
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
        self.assertEqual(
            base64.b64decode(pending["bodyB64"]),
            b'{"prepared":"body","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}',
        )

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
                    on_first_send(b'{"prepared":"body","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}')
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
        with Store(self.state) as store:
            mapping = store.get_attachment(runtime_id)
            self.assertEqual(mapping["sessionId"], artifact["sessionId"])
            self.assertEqual(mapping["nativeThreadId"], binding["threadId"])
            self.assertEqual(mapping["nativeBinding"], binding)
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
                on_first_send(b'{"loser":"body","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}')

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
        self.assertEqual(
            base64.b64decode(pending["bodyB64"]),
            b'{"loser":"body","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}',
        )

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
                on_first_send(b'{"exact":"body","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}')
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
            mapping = daemon_store.get_attachment(replacement_id)
            self.assertEqual(mapping["attachmentGeneration"], 9)
            self.assertEqual(mapping["sessionId"], session_id)
            self.assertEqual(mapping["nativeThreadId"], binding["threadId"])
            self.assertEqual(mapping["nativeBinding"], binding)
        pending = cli.load_pending_commit(self.state, "transfer", session_id)
        self.assertIsNone(pending)

    def test_confirmed_transfer_fences_source_before_native_recheck_and_recovers_target(self):
        fixture_path = Path(__file__).resolve().parents[1] / "contracts/event-v1/protocol-v1.json"
        event = json.loads(fixture_path.read_text())["validEnvelopes"][0]
        fixed_now = 1791201630

        def run_case(label, post_commit_binding, *, recover, capacity_fail=False):
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
                        on_first_send(b'{"transfer":"exact-body","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}')
                    return response

            fake = FakeCloud()
            daemon_commands = []
            with Store(state, clock=lambda: fixed_now) as daemon_store:
                source = {key: event[key] for key in IDENTITY}
                source["leaseExpiresAt"] = fixed_now + 3600
                daemon_store.put_attachment(source)
                queued = daemon_store.accept(event)["deliveryId"]
                if capacity_fail:
                    daemon_store.max_bytes = daemon_store._size()

                def daemon_request(_state_dir, command):
                    daemon_commands.append(command["command"])
                    return _execute_control_command(daemon_store, command)

                initial_bindings = [binding, binding if capacity_fail else post_commit_binding]
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
                self.assertEqual(first_result["localStatus"],
                                 "unavailable" if capacity_fail else "not_current")
                self.assertIsNone(daemon_store.get_attachment(source_id))
                self.assertIsNone(daemon_store.get_attachment(replacement_id))
                self.assertEqual(daemon_store.get(queued)["status"], "stale")
                source_tombstone = json.loads(daemon_store.db.execute(
                    "SELECT data FROM attachments WHERE runtime=?", (source_id,),
                ).fetchone()[0])
                self.assertEqual(source_tombstone["leaseExpiresAt"], 0)
                self.assertEqual(daemon_commands, (
                    ["transfer-attachment", "revoke-transfer-source"]
                    if capacity_fail else ["revoke-transfer-source"]
                ))
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
                    mapping = daemon_store.get_attachment(replacement_id)
                    self.assertEqual(mapping["attachmentGeneration"], 9)
                    self.assertEqual(mapping["sessionId"], session_id)
                    self.assertEqual(mapping["nativeThreadId"], binding["threadId"])
                    self.assertEqual(mapping["nativeBinding"], binding)
                    self.assertEqual(daemon_store.get(queued)["status"], "stale")
                    self.assertIsNone(cli.load_pending_commit(state, "transfer", session_id))
                elif capacity_fail:
                    self.assertEqual(first_result["reason"], "local_mapping_unavailable")
                    self.assertEqual(first_result["lastError"], "capacity")
                else:
                    self.assertEqual(first_result["reason"], "native_binding_changed_after_commit")
                    self.assertIsNotNone(cli.load_pending_commit(state, "transfer", session_id))

        run_case("native-gone", OSError("launcher socket disappeared"), recover=True)
        changed_binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                           "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 3,
                           "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
        run_case("native-changed", changed_binding, recover=False)
        run_case("target-capacity", None, recover=False, capacity_fail=True)

    def test_confirmed_transfer_capacity_failure_fences_source_and_keeps_pending(self):
        now = time.time()
        fixture_path = Path(__file__).resolve().parents[1] / "contracts/event-v1/protocol-v1.json"
        event = json.loads(fixture_path.read_text())["validEnvelopes"][0]
        event["eventId"], event["attemptId"] = str(uuid.uuid4()), str(uuid.uuid4())
        event["issuedAt"], event["expiresAt"] = _iso(now), _iso(now + 60)
        event["deliveryId"] = derive_delivery_id(event)
        source_id, target_id = event["runtimeId"], str(uuid.uuid4())
        binding = {"clientId": str(uuid.uuid4()), "connectionId": str(uuid.uuid4()),
                   "backendPid": 123, "threadId": str(uuid.uuid4()), "generation": 2,
                   "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 3}
        cloud_id = {"origin": "https://events.example.com", "principal": event["principal"],
                    "agent": event["agent"], "nodeId": str(uuid.uuid4()), "nodeGeneration": 1}
        source = {key: event[key] for key in IDENTITY}
        source.update(leaseExpiresAt=now + 3600, nodeId=cloud_id["nodeId"], nativeBinding=binding,
                      sessionId=str(uuid.uuid4()), nativeThreadId=binding["threadId"])
        with Store(self.state) as store:
            store.put_attachment(source)
            queued = store.accept(event)["deliveryId"]
            capacity_limit = max(
                store._size(),
                65536 + 12288 * store.db.execute("PRAGMA page_count").fetchone()[0],
            )

        challenge = {"challengeId": str(uuid.uuid4()), "issuedAt": _iso(now),
                     "expiresAt": _iso(now + 30)}
        response = {"status": "transferred", "sourceRuntimeId": source_id,
                    "sourceRuntimeGeneration": source["runtimeGeneration"] + 1,
                    "sourceAttachmentGeneration": source["attachmentGeneration"] + 1,
                    "runtimeId": target_id, "runtimeGeneration": 7,
                    "nodeId": cloud_id["nodeId"], "nodeGeneration": cloud_id["nodeGeneration"],
                    "attachmentGeneration": 9, "leaseUntil": _iso(now + 90),
                    "nativeBinding": binding}

        class FakeCloud:
            origin, principal, agent = cloud_id["origin"], cloud_id["principal"], cloud_id["agent"]
            node_id, node_generation = cloud_id["nodeId"], cloud_id["nodeGeneration"]

            async def native_challenge(self, _intent):
                return challenge

            async def transfer(self, _intent, _challenge, _evidence, *, on_first_send=None):
                on_first_send(b'{"commit":"confirmed","nativeEvidence":{"observedAt":"2026-10-09T12:00:00.100Z","witness":{"fixture":true}}}')
                return response

        def limited_store(state_dir):
            return Store(state_dir, max_bytes=capacity_limit)

        session_id = str(uuid.uuid4())
        output = io.StringIO()
        with (patch.object(cli, "Store", side_effect=limited_store),
              patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
              patch.object(cli, "session_binding", side_effect=[binding, binding]),
              patch.object(cli, "session_challenge", return_value={
                  "observedAt": challenge["issuedAt"],
                  "validUntilMonotonic": time.monotonic() + 0.5,
                  "witness": {"fixture": True},
              }),
              redirect_stdout(output)):
            code = cli.main([
                "--state-dir", str(self.state), "transfer",
                "--source-runtime-id", source_id,
                "--expected-source-runtime-generation", str(source["runtimeGeneration"]),
                "--expected-source-attachment-generation", str(source["attachmentGeneration"]),
                "--replacement-runtime-id", target_id,
                "--expected-replacement-runtime-generation", "6",
                "--expected-replacement-attachment-generation", "8",
                "--session-id", session_id, "--cloud-config", str(self.state / "cloud.json"),
            ])

        result = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(result["remoteStatus"], "transferred")
        self.assertEqual(result["localStatus"], "unavailable")
        self.assertEqual(result["reason"], "local_mapping_unavailable")
        self.assertEqual(result["lastError"], "capacity")
        self.assertIsNotNone(cli.load_pending_commit(self.state, "transfer", session_id))
        with Store(self.state) as store:
            self.assertIsNone(store.get_attachment(source_id))
            self.assertIsNone(store.get_attachment(target_id))
            self.assertEqual(store.get(queued)["status"], "stale")

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
        self.assertEqual(result["reason"], "owner_approval_required")
        self.assertEqual(result["challenge"], "owner-123")
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        key = self.state / "node-key.pem"
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        original = key.read_bytes()
        again = json.loads(self.cli("enroll", "--challenge", "owner-456", code=2))
        self.assertEqual(result["publicKey"], again["publicKey"])
        self.assertEqual(original, key.read_bytes())
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_enrollment_completion_retries_only_ambiguous_attempt(self):
        challenge_path = self.state.parent / "owner-challenge.json"
        challenge = {"challengeId": str(uuid.uuid4()), "nodeId": str(uuid.uuid4()),
                     "expiresAt": "2030-01-01T00:00:00.000Z", "signingPayload": "owner-approved"}
        challenge_path.write_text(json.dumps(challenge))
        challenge_path.chmod(0o600)

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "owner@example.com", "codex"
            node_id, node_generation = challenge["nodeId"], 1

            calls = 0

            async def complete_enrollment(self, supplied, *, mesh_ip, mesh_port, agents):
                self.calls += 1
                self.call = (supplied, mesh_ip, mesh_port, agents)
                if self.calls == 1:
                    raise CloudError("transport_unavailable", ambiguous=True)
                if self.calls == 2:
                    raise CloudError("invalid_challenge")
                return {"nodeId": self.node_id, "generation": self.node_generation}

        cloud = FakeCloud()
        output = io.StringIO()
        args = ["--state-dir", str(self.state), "enroll", "--challenge-file", str(challenge_path),
                "--cloud-config", str(self.state.parent / "config.json"), "--mesh-ip", "100.96.0.1",
                "--mesh-port", "8789", "--agent", "codex"]
        with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
            self.assertEqual(cli.main(args), 2)
        self.assertEqual(json.loads(output.getvalue()), {"enrolled": None, "reason": "enrollment_outcome_unknown"})
        self.assertEqual(cloud.call, (challenge, "100.96.0.1", 8789, ["codex"]))
        self.assertEqual(stat.S_IMODE((self.state / "enrollment-attempt.json").stat().st_mode), 0o600)

        challenge_path.write_text(json.dumps({**challenge, "signingPayload": "different challenge"}))
        errors = io.StringIO()
        with (patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stderr(errors)):
            self.assertEqual(cli.main(args), 2)
        self.assertEqual(json.loads(errors.getvalue()), {"reason": "enrollment_attempt_mismatch"})
        self.assertEqual(cloud.calls, 1)
        challenge_path.write_text(json.dumps(challenge))
        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
            self.assertEqual(cli.main(args), 2)
        self.assertEqual(json.loads(output.getvalue()), {"enrolled": None, "reason": "enrollment_outcome_unknown"})
        self.assertTrue((self.state / "enrollment-attempt.json").exists())
        challenge_path.write_text(json.dumps(challenge))

        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
            self.assertEqual(cli.main(args), 0)
        self.assertEqual(json.loads(output.getvalue()), {"enrolled": True, "nodeId": cloud.node_id, "generation": 1})
        self.assertFalse((self.state / "enrollment-attempt.json").exists())

        changed = {**challenge, "signingPayload": "different challenge"}
        challenge_path.write_text(json.dumps(changed))
        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
            self.assertEqual(cli.main(args), 0)
        self.assertEqual(json.loads(output.getvalue()), {"enrolled": True, "nodeId": cloud.node_id, "generation": 1})

    def test_enrollment_definite_refusal_clears_attempt_and_missing_key_fails_before_attempt(self):
        challenge_path = self.state.parent / "owner-challenge.json"
        challenge = {"challengeId": str(uuid.uuid4()), "nodeId": str(uuid.uuid4()),
                     "expiresAt": "2030-01-01T00:00:00.000Z", "signingPayload": "owner-approved"}
        challenge_path.write_text(json.dumps(challenge))
        challenge_path.chmod(0o600)

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "owner@example.com", "codex"
            node_id, node_generation = challenge["nodeId"], 1
            calls = 0

            async def complete_enrollment(self, *_args, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise CloudError("invalid_challenge")
                return {"nodeId": self.node_id, "generation": self.node_generation}

        cloud = FakeCloud()
        args = ["--state-dir", str(self.state), "enroll", "--challenge-file", str(challenge_path),
                "--cloud-config", str(self.state.parent / "config.json"), "--mesh-ip", "100.96.0.1",
                "--mesh-port", "8789", "--agent", "codex"]
        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
            self.assertEqual(cli.main(args), 2)
        self.assertEqual(json.loads(output.getvalue()), {"enrolled": False, "reason": "invalid_challenge"})
        self.assertFalse((self.state / "enrollment-attempt.json").exists())

        challenge["challengeId"] = str(uuid.uuid4())
        challenge_path.write_text(json.dumps(challenge))
        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
            self.assertEqual(cli.main(args), 0)

        fresh_state = self.state.parent / "missing-key-state"
        output, errors = io.StringIO(), io.StringIO()
        with (patch.object(cli, "load_cloud_client", side_effect=SecurityError("invalid_signing_key")),
              redirect_stdout(output), redirect_stderr(errors)):
            self.assertEqual(cli.main(["--state-dir", str(fresh_state), *args[2:]]), 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(json.loads(errors.getvalue()), {"reason": "invalid_signing_key"})
        self.assertFalse((fresh_state / "enrollment-attempt.json").exists())

    def test_concurrent_enrollment_attempts_are_serialized(self):
        challenge_path = self.state.parent / "owner-challenge.json"
        challenge = {"challengeId": str(uuid.uuid4()), "nodeId": str(uuid.uuid4()),
                     "expiresAt": "2030-01-01T00:00:00.000Z", "signingPayload": "approved"}
        challenge_path.write_text(json.dumps(challenge))
        challenge_path.chmod(0o600)
        started, release = threading.Event(), threading.Event()

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "owner@example.com", "codex"
            node_id, node_generation = challenge["nodeId"], 1
            calls = 0

            async def complete_enrollment(self, *_args, **_kwargs):
                self.calls += 1
                started.set()
                if not release.wait(5):
                    raise AssertionError("test did not release first request")
                raise CloudError("transport_unavailable", ambiguous=True)

        cloud = FakeCloud()
        from types import SimpleNamespace
        args = SimpleNamespace(challenge_file=challenge_path,
                               cloud_config=self.state.parent / "config.json",
                               mesh_ip="100.96.0.1", mesh_port=8789, agent=["codex"])
        with patch.object(cli, "load_cloud_client", return_value=cloud):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(cli._complete_enrollment, args, self.state)
                self.assertTrue(started.wait(2), "first completion did not reach its request")
                challenge_path.write_text(json.dumps({**challenge, "signingPayload": "different"}))
                second = pool.submit(cli._complete_enrollment, args, self.state)
                self.assertEqual(cloud.calls, 1, "second request passed the attempt lock")
                release.set()
                self.assertEqual(first.result(timeout=5), 2)
                with self.assertRaisesRegex(SecurityError, "^enrollment_attempt_mismatch$"):
                    second.result(timeout=5)
        self.assertEqual(cloud.calls, 1)

    def test_enrollment_interrupt_preserves_attempt_for_same_challenge_retry(self):
        challenge_path = self.state.parent / "owner-challenge.json"
        challenge = {"challengeId": str(uuid.uuid4()), "nodeId": str(uuid.uuid4()),
                     "expiresAt": "2030-01-01T00:00:00.000Z", "signingPayload": "approved"}
        challenge_path.write_text(json.dumps(challenge))
        challenge_path.chmod(0o600)

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "owner@example.com", "codex"
            node_id, node_generation = challenge["nodeId"], 1
            calls = 0

            async def complete_enrollment(self, *_args, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise KeyboardInterrupt()
                return {"nodeId": self.node_id, "generation": self.node_generation}

        cloud = FakeCloud()
        args = ["--state-dir", str(self.state), "enroll", "--challenge-file", str(challenge_path),
                "--cloud-config", str(self.state.parent / "config.json"), "--mesh-ip", "100.96.0.1",
                "--mesh-port", "8789", "--agent", "codex"]
        output, errors = io.StringIO(), io.StringIO()
        with (patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output),
              redirect_stderr(errors)):
            self.assertEqual(cli.main(args), 130)
        self.assertEqual(json.loads(errors.getvalue()), {"reason": "interrupted"})
        self.assertTrue((self.state / "enrollment-attempt.json").exists())

        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
            self.assertEqual(cli.main(args), 0)
        self.assertEqual(json.loads(output.getvalue()), {"enrolled": True, "nodeId": cloud.node_id, "generation": 1})
        self.assertFalse((self.state / "enrollment-attempt.json").exists())

    def test_enrollment_post_send_validation_errors_keep_attempt_fenced(self):
        for code in ("invalid_response", "identity_mismatch"):
            with self.subTest(code=code):
                state = self.state.parent / code
                challenge_path = self.state.parent / f"{code}.json"
                challenge = {"challengeId": str(uuid.uuid4()), "nodeId": str(uuid.uuid4()),
                             "expiresAt": "2030-01-01T00:00:00.000Z", "signingPayload": "approved"}
                challenge_path.write_text(json.dumps(challenge))
                challenge_path.chmod(0o600)

                class FakeCloud:
                    origin, principal, agent = "https://events.example.com", "owner@example.com", "codex"
                    node_id, node_generation = challenge["nodeId"], 1
                    calls = 0

                    async def complete_enrollment(self, *_args, **_kwargs):
                        self.calls += 1
                        if self.calls == 1:
                            raise CloudError(code)
                        return {"nodeId": self.node_id, "generation": self.node_generation}

                cloud, output = FakeCloud(), io.StringIO()
                args = ["--state-dir", str(state), "enroll", "--challenge-file", str(challenge_path),
                        "--cloud-config", str(self.state.parent / "config.json"), "--mesh-ip", "100.96.0.1",
                        "--mesh-port", "8789", "--agent", "codex"]
                with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
                    self.assertEqual(cli.main(args), 2)
                self.assertEqual(json.loads(output.getvalue()), {
                    "enrolled": None, "reason": "enrollment_outcome_unknown",
                })
                self.assertTrue((state / "enrollment-attempt.json").exists())
                output = io.StringIO()
                with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
                    self.assertEqual(cli.main(args), 0)
                self.assertFalse((state / "enrollment-attempt.json").exists())

    def test_enrollment_maximum_agent_binding_retries_from_private_record(self):
        challenge_path = self.state.parent / "owner-challenge.json"
        challenge = {"challengeId": str(uuid.uuid4()), "nodeId": str(uuid.uuid4()),
                     "expiresAt": "2030-01-01T00:00:00.000Z", "signingPayload": "approved"}
        challenge_path.write_text(json.dumps(challenge))
        challenge_path.chmod(0o600)
        agents = ["a" * 29 + f"{index:03d}" for index in range(128)]

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "owner@example.com", agents[0]
            node_id, node_generation = challenge["nodeId"], 1
            calls = 0

            async def complete_enrollment(self, _challenge, *, agents, **_kwargs):
                self.calls += 1
                self.asserted_agents = agents
                if self.calls == 1:
                    raise CloudError("transport_unavailable", ambiguous=True)
                return {"nodeId": self.node_id, "generation": self.node_generation}

        cloud = FakeCloud()
        args = ["--state-dir", str(self.state), "enroll", "--challenge-file", str(challenge_path),
                "--cloud-config", str(self.state.parent / "config.json"), "--mesh-ip", "100.96.0.1",
                "--mesh-port", "8789"] + [item for agent in agents for item in ("--agent", agent)]
        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(output):
            self.assertEqual(cli.main(args), 2)
        self.assertGreater((self.state / "enrollment-attempt.json").stat().st_size, 4096)
        with patch.object(cli, "load_cloud_client", return_value=cloud), redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(args), 0)
        self.assertEqual(cloud.asserted_agents, agents)

    def test_enrollment_cloud_config_errors_use_enrolled_result_key(self):
        challenge_path = self.state.parent / "owner-challenge.json"
        challenge_path.write_text("{}")
        challenge_path.chmod(0o600)
        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", side_effect=CloudError("invalid_configuration")), redirect_stdout(output):
            code = cli.main(["--state-dir", str(self.state), "enroll", "--challenge-file", str(challenge_path),
                             "--cloud-config", "/unused", "--mesh-ip", "100.96.0.1",
                             "--mesh-port", "8789", "--agent", "codex"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue()), {"enrolled": False, "reason": "invalid_configuration"})
        self.assertFalse((self.state / "enrollment-attempt.json").exists())

        output = io.StringIO()
        with patch.object(cli, "load_cloud_client",
                          side_effect=CloudError("unavailable", ambiguous=True)), redirect_stdout(output):
            code = cli.main(["--state-dir", str(self.state), "enroll", "--challenge-file", str(challenge_path),
                             "--cloud-config", "/unused", "--mesh-ip", "100.96.0.1",
                             "--mesh-port", "8789", "--agent", "codex"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue()), {
            "enrolled": None, "reason": "enrollment_outcome_unknown",
        })

    def test_enrollment_cleanup_precedes_terminal_success_output(self):
        challenge_path = self.state.parent / "owner-challenge.json"
        challenge = {"challengeId": str(uuid.uuid4()), "nodeId": str(uuid.uuid4()),
                     "expiresAt": "2030-01-01T00:00:00.000Z", "signingPayload": "approved"}
        challenge_path.write_text(json.dumps(challenge))
        challenge_path.chmod(0o600)

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "owner@example.com", "codex"
            node_id, node_generation = challenge["nodeId"], 1

            async def complete_enrollment(self, *_args, **_kwargs):
                return {"nodeId": self.node_id, "generation": self.node_generation}

        real_fsync = os.fsync
        calls = 0

        def fail_cleanup_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("simulated directory sync failure")
            return real_fsync(fd)

        output, errors = io.StringIO(), io.StringIO()
        with (patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
              patch.object(cli.os, "fsync", side_effect=fail_cleanup_fsync),
              redirect_stdout(output), redirect_stderr(errors)):
            code = cli.main(["--state-dir", str(self.state), "enroll", "--challenge-file", str(challenge_path),
                             "--cloud-config", str(self.state.parent / "config.json"), "--mesh-ip", "100.96.0.1",
                             "--mesh-port", "8789", "--agent", "codex"])
        self.assertEqual(code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(json.loads(errors.getvalue()), {"reason": "local_operation_unavailable"})
        lock_fd = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    def test_enrollment_partial_attempt_write_is_removed_before_network(self):
        challenge_path = self.state.parent / "owner-challenge.json"
        challenge = {"challengeId": str(uuid.uuid4()), "nodeId": str(uuid.uuid4()),
                     "expiresAt": "2030-01-01T00:00:00.000Z", "signingPayload": "approved"}
        challenge_path.write_text(json.dumps(challenge))
        challenge_path.chmod(0o600)

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "owner@example.com", "codex"
            node_id, node_generation = challenge["nodeId"], 1

            async def complete_enrollment(self, *_args, **_kwargs):
                raise AssertionError("persistence failure must precede the network")

        real_fsync = os.fsync
        calls = 0

        def fail_first_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("simulated attempt write sync failure")
            return real_fsync(fd)

        errors = io.StringIO()
        with (patch.object(cli, "load_cloud_client", return_value=FakeCloud()),
              patch.object(cli.os, "fsync", side_effect=fail_first_fsync), redirect_stderr(errors)):
            code = cli.main(["--state-dir", str(self.state), "enroll", "--challenge-file", str(challenge_path),
                             "--cloud-config", str(self.state.parent / "config.json"), "--mesh-ip", "100.96.0.1",
                             "--mesh-port", "8789", "--agent", "codex"])
        self.assertEqual(code, 2)
        self.assertFalse((self.state / "enrollment-attempt.json").exists())

    def test_enrollment_uncertain_response_is_not_reported_as_success(self):
        challenge_path = self.state.parent / "owner-challenge.json"
        challenge_path.write_text("{}")
        challenge_path.chmod(0o600)

        class FakeCloud:
            origin, principal, agent = "https://events.example.com", "owner@example.com", "codex"
            node_id, node_generation = str(uuid.uuid4()), 1

            async def complete_enrollment(self, *_args, **_kwargs):
                raise CloudError("transport_unavailable", ambiguous=True)

        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), redirect_stdout(output):
            code = cli.main(["--state-dir", str(self.state), "enroll", "--challenge-file", str(challenge_path),
                             "--cloud-config", str(self.state.parent / "config.json"), "--mesh-ip", "100.96.0.1",
                             "--mesh-port", "8789", "--agent", "codex"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue()), {"enrolled": None, "reason": "enrollment_outcome_unknown"})
        self.assertNotIn("signature", output.getvalue())

    @unittest.skipUnless(os.name == "posix", "Unix control socket")
    def test_daemon_status_and_clean_signal_stop(self):
        process = subprocess.Popen(  # nosec B603 - fixed interpreter and literal daemon command
            self.command + ["run"], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        try:
            socket = self.state / "control.sock"
            deadline = time.monotonic() + 5
            while process.poll() is None and time.monotonic() < deadline:
                if control_socket_ready(socket):
                    break
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
