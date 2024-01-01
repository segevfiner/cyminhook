# cython: language_level=3str, binding=True
"""
Hook functions on Windows using MinHook.
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

    *signature* is a :mod:`ctypes` function signature created by either :func:`ctypes.CFUNCTYPE`,
    :func:`ctypes.WINFUNCTYPE`, :func:`ctypes.PYFUNCTYPE`. *target* is either the address to hook
    or a :mod:`ctypes` function object for the function to hook. *detour* is the Python callable
    that will be called by the hook.

    .. warning:: Be careful not to enter an infinite recursion from the *detour* function.
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
            self.signature = getattr(self, 'signature', None)
            if self.signature is None:
                raise ValueError("signature not specified")
        else:
            self.signature = signature

        if target is None:
            self.target = getattr(self, 'target', None)
            if self.target is None:
                raise ValueError("target not specified")
        else:
            self.target = target

        if hasattr(self.target, 'argtypes'):
            self.target = ctypes.cast(self.target, ctypes.c_void_p).value

        self._target = <cminhook.LPVOID><uintptr_t>self.target

        if detour is None:
            self.detour = getattr(self, 'detour', None)
            if self.detour is None:
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

    cpdef close(self):
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


def queue_enable(MinHook hook not None):
    """Queue to enable an already created hook."""
    status = cminhook.MH_QueueEnableHook(hook._target)
    if status != cminhook.MH_OK:
        raise Error(status)


def queue_disable(MinHook hook not None):
    """Queue to disable an already created hook."""
    status = cminhook.MH_QueueDisableHook(hook._target)
    if status != cminhook.MH_OK:
        raise Error(status)


def apply_queued():
    """Apply all queued changes in one go."""
    status = cminhook.MH_ApplyQueued()
    if status != cminhook.MH_OK:
        raise Error(status)
