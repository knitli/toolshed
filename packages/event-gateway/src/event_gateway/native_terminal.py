"""Forward an owned native PTY through the caller's foreground terminal."""

import errno
import fcntl
import os
import select
import signal
import sys
import termios
import tty


def _write_all(fd, data, stop_event):
    while data:
        try:
            count = os.write(fd, data)
        except BlockingIOError:
            if stop_event.is_set():
                return False
            select.select([], [fd], [], 0.1)
            continue
        if count == 0:
            raise OSError("terminal write made no progress")
        data = data[count:]
        if data and stop_event.is_set():
            return False
    return True


def run_terminal(master_fd, *, stop_event):
    """Forward bytes until PTY EOF or stop; caller owns descriptors and child cleanup.

    Call on the main thread. Raw mode forwards Ctrl-C to the native client rather
    than interrupting this launcher. No child process is signalled or reaped here.
    """
    input_fd, output_fd = sys.stdin.fileno(), sys.stdout.fileno()
    if not os.isatty(input_fd):
        raise ValueError("native terminal requires tty stdin")
    previous_mode = termios.tcgetattr(input_fd)
    previous_resize = signal.getsignal(signal.SIGWINCH)
    previous_blocking = [(fd, os.get_blocking(fd)) for fd in (master_fd, output_fd)]

    def resize(*_):
        size = fcntl.ioctl(input_fd, termios.TIOCGWINSZ, b"\0" * 8)
        try:
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, size)
        except OSError as error:
            if error.errno not in (errno.EIO, errno.ENXIO):
                raise

    try:
        for fd, _ in previous_blocking:
            os.set_blocking(fd, False)
        signal.signal(signal.SIGWINCH, resize)
        resize()
        tty.setraw(input_fd, termios.TCSANOW)
        drained = 0
        while True:
            stopping = stop_event.is_set()
            ready, _, _ = select.select(
                [master_fd] if stopping else [master_fd, input_fd], [], [],
                0 if stopping else 0.1,
            )
            if stopping and not ready:
                return
            # Deliver pending output before consuming more user input.
            for fd in ready:
                try:
                    data = os.read(fd, 4096)
                except BlockingIOError:
                    continue
                except OSError as error:
                    if fd == master_fd and error.errno == errno.EIO:
                        return
                    raise
                if not data:
                    return
                if not _write_all(output_fd if fd == master_fd else master_fd, data, stop_event):
                    return
                if stopping:
                    drained += len(data)
                    # ponytail: bound exit draining to 1 MiB; use a deadline if
                    # interactive workloads demonstrably need larger tails.
                    if drained >= 1024 * 1024:
                        return
    finally:
        try:
            termios.tcsetattr(input_fd, termios.TCSANOW, previous_mode)
        finally:
            try:
                for fd, blocking in previous_blocking:
                    os.set_blocking(fd, blocking)
            finally:
                signal.signal(signal.SIGWINCH, previous_resize)
