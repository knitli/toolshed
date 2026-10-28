"""Typed CoreFoundation checks and fake-only SCPreferences adapter tests."""

import ctypes
from datetime import datetime
import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "softnet_preferences.py"
SPEC = importlib.util.spec_from_file_location("softnet_preferences", SCRIPT)
softnet_preferences = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(softnet_preferences)


def _cstring(cf, ref):
    cf.CFStringGetCString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_long,
        ctypes.c_uint32,
    ]
    cf.CFStringGetCString.restype = ctypes.c_ubyte
    buffer = ctypes.create_string_buffer(256)
    if not cf.CFStringGetCString(ref, buffer, len(buffer), 0x08000100):
        raise AssertionError("CFStringGetCString failed")
    return buffer.value.decode("utf-8")


class FakeSCPreferences:
    """In-memory stand-in. It never calls into SystemConfiguration."""

    def __init__(self, adapter):
        """Keep fake state and borrowed CF refs isolated from host preferences."""
        self.adapter = adapter
        self.current = None
        self.staged = None
        self.error = 0
        self.lock_result = True
        self.set_result = True
        self.remove_result = True
        self.commit_result = True
        self.apply_result = True
        self.unlock_result = True
        self.values = []
        self.calls = []

    def SCPreferencesCreate(self, _allocator, name, prefs_id):
        self.calls.append(("create", _cstring(self.adapter.cf, name), _cstring(self.adapter.cf, prefs_id)))
        return self.adapter._string("fake preferences session")

    def SCPreferencesLock(self, prefs, wait):
        self.calls.append(("lock", prefs, wait))
        if not self.lock_result:
            self.error = 3002
        return self.lock_result

    def SCPreferencesUnlock(self, prefs):
        self.calls.append(("unlock", prefs))
        if not self.unlock_result:
            self.error = 1001
        return self.unlock_result

    def SCPreferencesGetValue(self, prefs, key):
        self.calls.append(("get", prefs, _cstring(self.adapter.cf, key)))
        if self.current is None:
            self.error = 1004
            return None
        value = self.adapter._parse(self.current)
        self.values.append(value)
        return value

    def SCPreferencesSetValue(self, prefs, key, value):
        self.calls.append(("set", prefs, _cstring(self.adapter.cf, key)))
        if not self.set_result:
            self.error = 1001
            return False
        self.staged = self.adapter._serialize(value)
        return True

    def SCPreferencesRemoveValue(self, prefs, key):
        self.calls.append(("remove", prefs, _cstring(self.adapter.cf, key)))
        if not self.remove_result:
            self.error = 1001
            return False
        self.staged = None
        return True

    def SCPreferencesCommitChanges(self, prefs):
        self.calls.append(("commit", prefs))
        if not self.commit_result:
            self.error = 1001
            return False
        self.current = self.staged
        return True

    def SCPreferencesApplyChanges(self, prefs):
        self.calls.append(("apply", prefs))
        if not self.apply_result:
            self.error = 1001
            return False
        return True

    def SCPreferencesSynchronize(self, prefs):
        self.calls.append(("synchronize", prefs))
        self.staged = self.current

    def SCError(self):
        self.calls.append(("error", self.error))
        return self.error

    @staticmethod
    def SCErrorString(code):
        return f"fake_{code}".encode()


@unittest.skipUnless(sys.platform == "darwin", "CoreFoundation is available only on macOS")
class SoftnetPreferencesTests(unittest.TestCase):
    def setUp(self):
        self.adapter = softnet_preferences.Preferences.__new__(softnet_preferences.Preferences)
        softnet_preferences.CoreFoundation.__init__(self.adapter)
        self.sc = FakeSCPreferences(self.adapter)
        self.adapter.sc = self.sc
        self.adapter._prefs = None
        self.adapter._locked = False

    def tearDown(self):
        for value in self.sc.values:
            self.adapter.cf.CFRelease(value)

    def test_target_has_exact_typed_values_and_native_equal_roundtrip(self):
        cf = self.adapter.cf
        original_number_create = cf.CFNumberCreate
        number_inputs = []

        def record_number_create(allocator, number_type, value_ptr):
            value = ctypes.cast(value_ptr, ctypes.POINTER(ctypes.c_int32)).contents.value
            number_inputs.append((number_type, value))
            return original_number_create(allocator, number_type, value_ptr)

        cf.CFNumberCreate = record_number_create
        cf.CFPropertyListCreateWithData.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_long), ctypes.POINTER(ctypes.c_void_p),
        ]
        cf.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        cf.CFDictionaryGetValue.restype = ctypes.c_void_p
        cf.CFNumberGetTypeID.restype = ctypes.c_ulong
        cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
        cf.CFGetTypeID.argtypes = [ctypes.c_void_p]
        cf.CFGetTypeID.restype = ctypes.c_ulong

        try:
            target = self.adapter.encode_target()
        finally:
            cf.CFNumberCreate = original_number_create
        self.assertEqual(number_inputs, [(3, 600)])
        self.adapter.validate(target)
        self.assertTrue(self.adapter.equal(target, self.adapter.encode_target()))
        self.assertEqual(plistlib.loads(target), {
            "DHCPLeaseTimeSecs": 600,
            "dhcp_ignore_client_identifier": True,
        })

        parsed = self.adapter._parse(target)
        lease_key = self.adapter._string("DHCPLeaseTimeSecs")
        bool_key = self.adapter._string("dhcp_ignore_client_identifier")
        try:
            lease = cf.CFDictionaryGetValue(parsed, lease_key)
            boolean = cf.CFDictionaryGetValue(parsed, bool_key)
            self.assertEqual(cf.CFGetTypeID(lease), cf.CFNumberGetTypeID())
            self.assertEqual(plistlib.loads(target)["DHCPLeaseTimeSecs"], 600)
            self.assertEqual(cf.CFGetTypeID(boolean), cf.CFBooleanGetTypeID())
        finally:
            cf.CFRelease(bool_key)
            cf.CFRelease(lease_key)
            cf.CFRelease(parsed)

    def test_native_equal_preserves_nested_data_date_and_bool_integer_distinction(self):
        left = plistlib.dumps({
            "nested": {"data": b"\x00\xff", "date": datetime(2020, 1, 2)},
            "flag": True,
            "flags": [False, {"nestedFlag": True}],
        }, fmt=plistlib.FMT_BINARY)
        same = plistlib.dumps({
            "nested": {"data": b"\x00\xff", "date": datetime(2020, 1, 2)},
            "flag": True,
            "flags": [False, {"nestedFlag": True}],
        }, fmt=plistlib.FMT_BINARY)
        integer = plistlib.dumps({
            "nested": {"data": b"\x00\xff", "date": datetime(2020, 1, 2)},
            "flag": 1,
            "flags": [0, {"nestedFlag": 1}],
        }, fmt=plistlib.FMT_BINARY)
        self.assertTrue(self.adapter.equal(left, same))
        self.assertFalse(self.adapter.equal(left, integer))
        integer_number = plistlib.dumps({"count": 600, "nested": [{"count": 600}]}, fmt=plistlib.FMT_BINARY)
        real_number = plistlib.dumps({"count": 600.0, "nested": [{"count": 600.0}]}, fmt=plistlib.FMT_BINARY)
        with self.subTest(number_mismatch="root"):
            self.assertFalse(self.adapter.equal(integer_number, real_number))
        nested_integer = plistlib.dumps({"count": 600, "nested": [{"count": 600}]}, fmt=plistlib.FMT_BINARY)
        nested_real = plistlib.dumps({"count": 600, "nested": [{"count": 600.0}]}, fmt=plistlib.FMT_BINARY)
        with self.subTest(number_mismatch="nested_array_dictionary"):
            self.assertFalse(self.adapter.equal(nested_integer, nested_real))
        self.assertTrue(self.adapter.equal(None, None))
        self.assertFalse(self.adapter.equal(left, None))

    def test_validate_rejects_invalid_and_oversized_data(self):
        for blob in (b"not a plist", b"x" * (softnet_preferences.MAX_PLIST_BYTES + 1)):
            with self.subTest(length=len(blob)), self.assertRaises(softnet_preferences.PreferencesError):
                self.adapter.validate(blob)

    def test_enter_uses_fixed_domain_nonblocking_lock_and_fixed_key(self):
        with self.adapter as preferences:
            self.assertIsNone(preferences.read())
        self.assertIn(("create", "Softnet preferences snapshot", "com.apple.InternetSharing.default.plist"), self.sc.calls)
        self.assertTrue(any(call[0] == "lock" and call[2] == 0 for call in self.sc.calls))
        self.assertTrue(any(call[0] == "get" and call[2] == "bootpd" for call in self.sc.calls))
        self.assertEqual(self.sc.calls[-1][0], "unlock")

    def test_missing_key_is_absence_but_other_null_read_error_raises(self):
        with self.adapter:
            self.assertIsNone(self.adapter.read())
        self.sc.error = 3001
        with self.adapter:
            self.sc.SCPreferencesGetValue = lambda *_: None
            self.sc.SCError = lambda: self.sc.error
            with self.assertRaisesRegex(softnet_preferences.PreferencesError, "preferences_read_failed:3001"):
                self.adapter.read()

    def test_lock_failure_captures_error_and_does_not_unlock(self):
        self.sc.lock_result = False
        with self.assertRaisesRegex(softnet_preferences.PreferencesError, "preferences_lock_failed:3002"):
            self.adapter.__enter__()
        self.assertIsNone(self.adapter._prefs)
        self.assertFalse(self.adapter._locked)
        self.assertFalse(any(call[0] == "unlock" for call in self.sc.calls))

    def test_nested_enter_is_rejected_without_replacing_locked_session(self):
        with self.adapter:
            with self.assertRaisesRegex(softnet_preferences.PreferencesError, "preferences_already_open"):
                self.adapter.__enter__()
        self.assertEqual(sum(call[0] == "create" for call in self.sc.calls), 1)

    def test_partial_corefoundation_construction_releases_created_refs(self):
        cf = self.adapter.cf
        original_string = self.adapter._string
        original_release = cf.CFRelease
        released = []

        def track_release(ref):
            released.append(ref)
            original_release(ref)

        def fail_second_string(value):
            if value in ("DHCPLeaseTimeSecs", softnet_preferences.PREFERENCES_ID):
                raise softnet_preferences.PreferencesError("injected_string_failure")
            return original_string(value)

        cf.CFRelease = track_release
        self.adapter._string = fail_second_string
        try:
            with self.assertRaisesRegex(softnet_preferences.PreferencesError, "injected_string_failure"):
                self.adapter.encode_target()
            self.assertGreaterEqual(len(released), 2)  # lease number and first target key
            released.clear()
            with self.assertRaisesRegex(softnet_preferences.PreferencesError, "injected_string_failure"):
                self.adapter.__enter__()
            self.assertEqual(len(released), 1)  # preferences name before prefsID creation failed
            self.assertFalse(any(call[0] == "create" for call in self.sc.calls))
        finally:
            self.adapter._string = original_string
            cf.CFRelease = original_release

    def test_write_set_remove_commit_apply_and_synchronize_trace(self):
        target = self.adapter.encode_target()
        with self.adapter:
            self.adapter.write(target)
            self.assertTrue(self.adapter.commit_apply())
            self.assertTrue(self.adapter.equal(self.sc.current, target))
            self.adapter.write(None)
            self.assertTrue(self.adapter.commit_apply())
            self.assertIsNone(self.sc.current)
            self.adapter.synchronize()
        names = [call[0] for call in self.sc.calls]
        self.assertIn("set", names)
        self.assertIn("remove", names)
        self.assertEqual(names.count("commit"), 2)
        self.assertEqual(names.count("apply"), 2)
        self.assertEqual(names.count("synchronize"), 1)

    def test_unlock_failure_preserves_primary_error_without_add_note(self):
        class Python39StyleError(RuntimeError):
            add_note = None

        primary = Python39StyleError("target write failed")
        self.sc.unlock_result = False
        with self.assertRaises(Python39StyleError) as raised:
            with self.adapter:
                raise primary
        self.assertIs(raised.exception, primary)
        self.assertIsNone(self.adapter._prefs)
        self.assertFalse(self.adapter._locked)
        self.assertEqual(sum(call[0] == "unlock" for call in self.sc.calls), 1)

    def test_set_commit_apply_and_unlock_failures_are_reported(self):
        target = self.adapter.encode_target()
        with self.adapter:
            self.sc.set_result = False
            with self.assertRaisesRegex(softnet_preferences.PreferencesError, "preferences_set_failed:1001"):
                self.adapter.write(target)
            self.sc.set_result = True
            self.sc.commit_result = False
            with self.assertRaisesRegex(softnet_preferences.PreferencesError, "preferences_commit_failed:1001"):
                self.adapter.commit_apply()
            self.sc.commit_result = True
            self.sc.apply_result = False
            with self.assertRaisesRegex(softnet_preferences.PreferencesError, "preferences_apply_failed:1001"):
                self.adapter.commit_apply()
        self.sc.unlock_result = False
        with self.assertRaisesRegex(softnet_preferences.PreferencesError, "preferences_unlock_failed:1001"):
            with self.adapter:
                pass


if __name__ == "__main__":
    unittest.main()
