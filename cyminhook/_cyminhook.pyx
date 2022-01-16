# cython: language_level=3str
"""
Hook functions on Windows using minhook.
"""
import enum
import ctypes

from libc.stdint cimport uintptr_t
from . cimport cminhook


class Status(enum.IntEnum):
    """MinHook status codes."""
    MH_UNKNOWN = cminhook.MH_UNKNOWN
    MH_OK = cminhook.MH_OK
    MH_ERROR_ALREADY_INITIALIZED = cminhook.MH_ERROR_ALREADY_INITIALIZED
    MH_ERROR_NOT_INITIALIZED = cminhook.MH_ERROR_NOT_INITIALIZED
    MH_ERROR_ALREADY_CREATED = cminhook.MH_ERROR_ALREADY_CREATED
    MH_ERROR_NOT_CREATED = cminhook.MH_ERROR_NOT_CREATED
    MH_ERROR_ENABLED = cminhook.MH_ERROR_ENABLED
    MH_ERROR_DISABLED = cminhook.MH_ERROR_DISABLED
    MH_ERROR_NOT_EXECUTABLE = cminhook.MH_ERROR_NOT_EXECUTABLE
    MH_ERROR_UNSUPPORTED_FUNCTION = cminhook.MH_ERROR_UNSUPPORTED_FUNCTION
    MH_ERROR_MEMORY_ALLOC = cminhook.MH_ERROR_MEMORY_ALLOC
    MH_ERROR_MEMORY_PROTECT = cminhook.MH_ERROR_MEMORY_PROTECT
    MH_ERROR_MODULE_NOT_FOUND = cminhook.MH_ERROR_MODULE_NOT_FOUND
    MH_ERROR_FUNCTION_NOT_FOUND = cminhook.MH_ERROR_FUNCTION_NOT_FOUND


class Error(Exception):
    """MinHook error."""
    def __init__(self, status):
        super().__init__(status)
        self.status = Status(status)


status = cminhook.MH_Initialize()
if status != cminhook.MH_OK:
    raise Error(status)


cdef class MinHook:
    """
    MinHook hook.

    *signature* is a :mod:`ctypes` function signature created by either :cls:`ctypes.CFUNCTYPE`,
    :cls:`ctypes.WINFUNCTYPE`, :cls:`ctypes.PYFUNCTYPE`. *target* is either the address to hook or a
    :mod:`ctypes` function object for the function to hook. *detour* is the Python callable that
    will be called by the hook.
    """
    cdef public object signature
    cdef public object target
    cdef cminhook.LPVOID _target
    cdef public object detour
    cdef object _detour
    cdef cminhook.LPVOID _original
    cdef readonly object original

    def __init__(self, *, signature=None, target=None, detour=None):
        if signature is None:
            signature = self.signature
            if signature is None:
                raise ValueError("signature not specified")
        else:
            self.signature = signature

        if target is None:
            target = self.target
            if target is None:
                raise ValueError("target not specified")
        else:
            self.target = target

        if hasattr(self.target, 'argtypes'):
            self.target = ctypes.cast(self.target, ctypes.c_void_p).value

        self._target = <cminhook.LPVOID><uintptr_t>self.target

        if detour is None:
            detour = self.detour
            if detour is None:
                raise ValueError("detour not specified")
        else:
            self.detour = detour

        self._detour = self.signature(self.detour)

        status = cminhook.MH_CreateHook(
            self._target,
            <cminhook.LPVOID><uintptr_t>ctypes.cast(self._detour, ctypes.c_void_p).value,
            &self._original
        )
        if status != cminhook.MH_OK:

            raise Error(status)

        self.original = self.signature(<uintptr_t>self._original)

    def __dealloc__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        """Close the hook. Removing it."""
        if self._original is not NULL:
            cminhook.MH_RemoveHook(self._target)
            self._original = NULL

    cdef _check_closed(self):
        if self._original is NULL:
            raise ValueError("Operation on closed Pcap")

    def enable(self):
        """Enable the hook."""
        self._check_closed()

        status = cminhook.MH_EnableHook(self._target)
        if status != cminhook.MH_OK:
            raise Error(status)

    def disable(self):
        """Disable the hook."""
        self._check_closed()

        status = cminhook.MH_DisableHook(self._target)
        if status != cminhook.MH_OK:
            raise Error(status)
