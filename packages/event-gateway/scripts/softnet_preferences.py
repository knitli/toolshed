"""Typed SCPreferences access for Softnet's fixed Internet Sharing preference."""

import ctypes
import sys


PREFERENCES_ID = "com.apple.InternetSharing.default.plist"
PREFERENCES_KEY = "bootpd"
MAX_PLIST_BYTES = 1024 * 1024
_BINARY_PLIST = 200  # kCFPropertyListBinaryFormat_v1_0
_IMMUTABLE = 0  # kCFPropertyListImmutable
_UTF8 = 0x08000100  # kCFStringEncodingUTF8
_SINT32 = 3  # kCFNumberSInt32Type
_STATUS_NO_KEY = 1004  # kSCStatusNoKey


class PreferencesError(RuntimeError):
    """A bounded, stable failure from CoreFoundation or SCPreferences."""


class CoreFoundation:
    def __init__(self):
        if sys.platform != "darwin":
            raise PreferencesError("macOS_required")
        self.cf = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        self._bind()

    def _bind(self):
        cf = self.cf
        void = ctypes.c_void_p
        index = ctypes.c_long
        cf.CFStringCreateWithCString.argtypes = [void, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFStringCreateWithCString.restype = void
        cf.CFNumberCreate.argtypes = [void, ctypes.c_long, ctypes.POINTER(ctypes.c_int32)]
        cf.CFNumberCreate.restype = void
        cf.CFDictionaryCreateMutable.argtypes = [void, index, void, void]
        cf.CFDictionaryCreateMutable.restype = void
        cf.CFDictionarySetValue.argtypes = [void, void, void]
        cf.CFDictionarySetValue.restype = None
        cf.CFDataCreate.argtypes = [void, ctypes.POINTER(ctypes.c_uint8), index]
        cf.CFDataCreate.restype = void
        cf.CFDataGetLength.argtypes = [void]
        cf.CFDataGetLength.restype = index
        cf.CFDataGetBytePtr.argtypes = [void]
        cf.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_uint8)
        cf.CFPropertyListCreateData.argtypes = [void, void, index, ctypes.c_ulong, ctypes.POINTER(void)]
        cf.CFPropertyListCreateData.restype = void
        cf.CFPropertyListCreateWithData.argtypes = [void, void, ctypes.c_ulong, ctypes.POINTER(index), ctypes.POINTER(void)]
        cf.CFPropertyListCreateWithData.restype = void
        cf.CFEqual.argtypes = [void, void]
        cf.CFEqual.restype = ctypes.c_ubyte
        cf.CFGetTypeID.argtypes = [void]
        cf.CFGetTypeID.restype = ctypes.c_ulong
        cf.CFNumberGetTypeID.argtypes = []
        cf.CFNumberGetTypeID.restype = ctypes.c_ulong
        cf.CFNumberIsFloatType.argtypes = [void]
        cf.CFNumberIsFloatType.restype = ctypes.c_ubyte
        cf.CFArrayGetTypeID.argtypes = []
        cf.CFArrayGetTypeID.restype = ctypes.c_ulong
        cf.CFArrayGetCount.argtypes = [void]
        cf.CFArrayGetCount.restype = index
        cf.CFArrayGetValueAtIndex.argtypes = [void, index]
        cf.CFArrayGetValueAtIndex.restype = void
        cf.CFDictionaryGetTypeID.argtypes = []
        cf.CFDictionaryGetTypeID.restype = ctypes.c_ulong
        cf.CFDictionaryGetCount.argtypes = [void]
        cf.CFDictionaryGetCount.restype = index
        cf.CFDictionaryGetKeysAndValues.argtypes = [
            void, ctypes.POINTER(void), ctypes.POINTER(void)
        ]
        cf.CFDictionaryGetKeysAndValues.restype = None
        cf.CFDictionaryGetValue.argtypes = [void, void]
        cf.CFDictionaryGetValue.restype = void
        cf.CFRelease.argtypes = [void]
        cf.CFRelease.restype = None

    def _string(self, value):
        ref = self.cf.CFStringCreateWithCString(None, value.encode("utf-8"), _UTF8)
        if not ref:
            raise PreferencesError("cf_string_create_failed")
        return ref

    def _data(self, blob):
        if not isinstance(blob, bytes) or not blob or len(blob) > MAX_PLIST_BYTES:
            raise PreferencesError("invalid_or_oversized_plist")
        raw = (ctypes.c_uint8 * len(blob)).from_buffer_copy(blob)
        ref = self.cf.CFDataCreate(None, raw, len(blob))
        if not ref:
            raise PreferencesError("cf_data_create_failed")
        return ref

    def _serialize(self, value):
        error = ctypes.c_void_p()
        data = self.cf.CFPropertyListCreateData(None, value, _BINARY_PLIST, 0, ctypes.byref(error))
        try:
            if not data:
                raise PreferencesError("plist_serialize_failed")
            length = self.cf.CFDataGetLength(data)
            if length <= 0 or length > MAX_PLIST_BYTES:
                raise PreferencesError("invalid_or_oversized_plist")
            ptr = self.cf.CFDataGetBytePtr(data)
            if not ptr:
                raise PreferencesError("plist_data_unavailable")
            return ctypes.string_at(ptr, length)
        finally:
            if data:
                self.cf.CFRelease(data)
            if error:
                self.cf.CFRelease(error)

    def _parse(self, blob):
        data = self._data(blob)
        error = ctypes.c_void_p()
        try:
            value = self.cf.CFPropertyListCreateWithData(
                None, data, _IMMUTABLE, None, ctypes.byref(error)
            )
            if not value:
                raise PreferencesError("plist_parse_failed")
            return value
        finally:
            self.cf.CFRelease(data)
            if error:
                self.cf.CFRelease(error)

    def encode_target(self):
        """Create the exact typed bootpd dictionary Softnet writes."""
        lease_seconds = ctypes.c_int32(600)
        number = self.cf.CFNumberCreate(None, _SINT32, ctypes.byref(lease_seconds))
        if not number:
            raise PreferencesError("cf_number_create_failed")
        ignore_key = lease_key = target = None
        try:
            ignore_key = self._string("dhcp_ignore_client_identifier")
            lease_key = self._string("DHCPLeaseTimeSecs")
            target = self.cf.CFDictionaryCreateMutable(None, 0, None, None)
            boolean = ctypes.c_void_p.in_dll(self.cf, "kCFBooleanTrue").value
            if not target or not boolean:
                raise PreferencesError("cf_target_create_failed")
            self.cf.CFDictionarySetValue(target, lease_key, number)
            self.cf.CFDictionarySetValue(target, ignore_key, boolean)
            return self._serialize(target)
        finally:
            if target:
                self.cf.CFRelease(target)
            if lease_key:
                self.cf.CFRelease(lease_key)
            if ignore_key:
                self.cf.CFRelease(ignore_key)
            self.cf.CFRelease(number)

    def validate(self, blob):
        """Reject malformed, non-plist, or oversized serialized values."""
        value = self._parse(blob)
        try:
            self._serialize(value)
        finally:
            self.cf.CFRelease(value)

    def equal(self, left, right):
        """Compare typed plist values, including bool/number distinctions."""
        if left is None or right is None:
            return left is None and right is None
        a = self._parse(left)
        try:
            b = self._parse(right)
            try:
                return self._equal_values(a, b)
            finally:
                self.cf.CFRelease(b)
        finally:
            self.cf.CFRelease(a)

    def _equal_values(self, first, second):
        # CFEqual alone equates boolean/number and integer/real plist nodes.
        pending = [(first, second)]
        dictionary_type = self.cf.CFDictionaryGetTypeID()
        array_type = self.cf.CFArrayGetTypeID()
        number_type = self.cf.CFNumberGetTypeID()
        while pending:
            left, right = pending.pop()
            left_type = self.cf.CFGetTypeID(left)
            if left_type != self.cf.CFGetTypeID(right):
                return False
            if (left_type == number_type
                    and self.cf.CFNumberIsFloatType(left) != self.cf.CFNumberIsFloatType(right)):
                return False
            if left_type == dictionary_type:
                if not self._dictionary_pairs(left, right, pending):
                    return False
            elif left_type == array_type:
                if not self._array_pairs(left, right, pending):
                    return False
            elif not self.cf.CFEqual(left, right):
                return False
        return True

    def _dictionary_pairs(self, left, right, pending):
        count = self.cf.CFDictionaryGetCount(left)
        if count != self.cf.CFDictionaryGetCount(right):
            return False
        keys = (ctypes.c_void_p * count)()
        values = (ctypes.c_void_p * count)()
        self.cf.CFDictionaryGetKeysAndValues(left, keys, values)
        for index in range(count):
            value = self.cf.CFDictionaryGetValue(right, keys[index])
            if not value:
                return False
            pending.append((values[index], value))
        return True

    def _array_pairs(self, left, right, pending):
        count = self.cf.CFArrayGetCount(left)
        if count != self.cf.CFArrayGetCount(right):
            return False
        pending.extend(
            (self.cf.CFArrayGetValueAtIndex(left, index),
             self.cf.CFArrayGetValueAtIndex(right, index))
            for index in range(count)
        )
        return True


class Preferences(CoreFoundation):
    """Locked access to only com.apple.InternetSharing.default.plist/bootpd."""

    def __init__(self):
        super().__init__()
        self.sc = ctypes.CDLL(
            "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration"
        )
        self._bind_sc()
        self._prefs = None
        self._locked = False

    def _bind_sc(self):
        sc = self.sc
        void = ctypes.c_void_p
        sc.SCPreferencesCreate.argtypes = [void, void, void]
        sc.SCPreferencesCreate.restype = void
        sc.SCPreferencesLock.argtypes = [void, ctypes.c_ubyte]
        sc.SCPreferencesLock.restype = ctypes.c_ubyte
        sc.SCPreferencesUnlock.argtypes = [void]
        sc.SCPreferencesUnlock.restype = ctypes.c_ubyte
        sc.SCPreferencesGetValue.argtypes = [void, void]
        sc.SCPreferencesGetValue.restype = void
        sc.SCPreferencesSetValue.argtypes = [void, void, void]
        sc.SCPreferencesSetValue.restype = ctypes.c_ubyte
        sc.SCPreferencesRemoveValue.argtypes = [void, void]
        sc.SCPreferencesRemoveValue.restype = ctypes.c_ubyte
        sc.SCPreferencesCommitChanges.argtypes = [void]
        sc.SCPreferencesCommitChanges.restype = ctypes.c_ubyte
        sc.SCPreferencesApplyChanges.argtypes = [void]
        sc.SCPreferencesApplyChanges.restype = ctypes.c_ubyte
        sc.SCPreferencesSynchronize.argtypes = [void]
        sc.SCPreferencesSynchronize.restype = None
        sc.SCError.argtypes = []
        sc.SCError.restype = ctypes.c_int
        sc.SCErrorString.argtypes = [ctypes.c_int]
        sc.SCErrorString.restype = ctypes.c_char_p

    def _sc_error(self, operation):
        code = self.sc.SCError()
        detail = self.sc.SCErrorString(code)
        label = detail.decode("utf-8", "replace") if detail else str(code)
        return PreferencesError(f"{operation}_failed:{code}:{label}")

    def _require_locked(self):
        if not self._locked or not self._prefs:
            raise PreferencesError("preferences_not_locked")

    def __enter__(self):
        if self._prefs or self._locked:
            raise PreferencesError("preferences_already_open")
        name = prefs_id = None
        try:
            name = self._string("Softnet preferences snapshot")
            prefs_id = self._string(PREFERENCES_ID)
            self._prefs = self.sc.SCPreferencesCreate(None, name, prefs_id)
        finally:
            if name:
                self.cf.CFRelease(name)
            if prefs_id:
                self.cf.CFRelease(prefs_id)
        if not self._prefs:
            raise self._sc_error("preferences_create")
        if not self.sc.SCPreferencesLock(self._prefs, 0):
            error = self._sc_error("preferences_lock")
            self.cf.CFRelease(self._prefs)
            self._prefs = None
            raise error
        self._locked = True
        return self

    def __exit__(self, error_type, error, traceback):
        unlock_error = None
        if self._locked:
            if not self.sc.SCPreferencesUnlock(self._prefs):
                unlock_error = self._sc_error("preferences_unlock")
            self._locked = False
        if self._prefs:
            self.cf.CFRelease(self._prefs)
            self._prefs = None
        if unlock_error:
            if error is not None:
                error.add_note(str(unlock_error))
            else:
                raise unlock_error
        return False

    def read(self):
        self._require_locked()
        key = self._string(PREFERENCES_KEY)
        try:
            value = self.sc.SCPreferencesGetValue(self._prefs, key)
            if not value:
                code = self.sc.SCError()
                if code == _STATUS_NO_KEY:
                    return None
                raise self._sc_error("preferences_read")
            # SCPreferencesGetValue returns a borrowed value owned by prefs.
            return self._serialize(value)
        finally:
            self.cf.CFRelease(key)

    def write(self, blob):
        self._require_locked()
        key = self._string(PREFERENCES_KEY)
        try:
            if blob is None:
                if self.read() is None:
                    return
                if not self.sc.SCPreferencesRemoveValue(self._prefs, key):
                    raise self._sc_error("preferences_remove")
                return
            value = self._parse(blob)
            try:
                if not self.sc.SCPreferencesSetValue(self._prefs, key, value):
                    raise self._sc_error("preferences_set")
            finally:
                self.cf.CFRelease(value)
        finally:
            self.cf.CFRelease(key)

    def commit_apply(self):
        self._require_locked()
        if not self.sc.SCPreferencesCommitChanges(self._prefs):
            raise self._sc_error("preferences_commit")
        if not self.sc.SCPreferencesApplyChanges(self._prefs):
            raise self._sc_error("preferences_apply")
        return True

    def synchronize(self):
        self._require_locked()
        self.sc.SCPreferencesSynchronize(self._prefs)
