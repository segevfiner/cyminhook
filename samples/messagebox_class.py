import ctypes
import ctypes.wintypes
import cyminhook
import win32api
import win32con


class MessageBoxExWHook(cyminhook.MinHook):
    signature = ctypes.WINFUNCTYPE(
        ctypes.c_int,
        ctypes.wintypes.HWND,
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.UINT,
        ctypes.wintypes.WORD,
        use_last_error=True,
    )

    target = ctypes.windll.user32.MessageBoxExW

    def detour(self, hWnd, lpText, lpCaption, uType, langId):
        return self.original(hWnd, "Hooked", "Hooked", uType, langId)


with MessageBoxExWHook() as hook:
    hook.enable()

    win32api.MessageBox(None, "Hello, World!", "Python", win32con.MB_OK)
