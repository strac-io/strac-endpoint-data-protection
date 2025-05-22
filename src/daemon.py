import atexit
import errno
import logging
import os
import signal
import sys
import time

import config

logger = logging.getLogger(__name__)

V = config.APP_VERSION


class Daemon:
    """
    A generic daemon class.

    Usage: subclass the Daemon class and override the run() method.
    """

    def __init__(
        self,
        pidfile,
        stdin=os.devnull,
        stdout=os.devnull,
        stderr=os.devnull,
        home_dir=".",
        umask=0o22,
        verbose=1,
        use_gevent=False,
        use_eventlet=False,
        use_cleanup=False,
        svc_name=config.APP_NAME,
        console=None,
    ):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.home_dir = home_dir
        self.verbose = verbose
        self.umask = umask
        self.daemon_alive = True
        self.use_gevent = use_gevent
        self.use_eventlet = use_eventlet
        self.use_cleanup = use_cleanup
        self.svc_name = svc_name
        self.console = console
        self.restart_intervals = [900, 720, 540, 450]

    def log(self, msg):
        """
        Log a message to the logger or the logger and a rich console.
        """
        if self.console:
            self.console.print(f"[bold green]{msg}[/bold green]")
        logger.debug(msg)

    def daemonize(self):
        """
        Do the UNIX double-fork magic, see Stevens' "Advanced Programming
        in the UNIX Environment" for details (ISBN 0201563177).
        """
        if self.use_eventlet:
            import eventlet.tpool

            eventlet.tpool.killall()
        try:
            pid = os.fork()
            if pid > 0:
                # Exit first parent
                sys.exit(0)
        except OSError as e:
            self.log("fork #1 failed: %d (%s)", e.errno, e.strerror)
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # Decouple from parent environment
        os.chdir(self.home_dir)
        os.setsid()
        os.umask(self.umask)

        # Do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # Exit from second parent
                sys.exit(0)
        except OSError as e:
            logger.error("fork #2 failed: %d (%s)", e.errno, e.strerror)
            # sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        if sys.platform != "darwin":  # This block breaks on OS X
            # Redirect standard file descriptors
            sys.stdout.flush()
            sys.stderr.flush()
            si = open(self.stdin, "r")
            so = open(self.stdout, "a+")
            if self.stderr:
                try:
                    se = open(self.stderr, "a+", 0)
                except ValueError:
                    # Python 3 can't have unbuffered text I/O
                    se = open(self.stderr, "a+", 1)
            else:
                se = so
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno())
            os.dup2(se.fileno(), sys.stderr.fileno())

        def sigtermhandler(signum, frame):  # pylint: disable=W0613
            if self.use_cleanup:
                self.cleanup()
                time.sleep(0.1)
            self.daemon_alive = False
            sys.exit()

        if self.use_gevent:
            import gevent

            gevent.reinit()
            gevent.signal_handler(signal.SIGTERM, sigtermhandler, signal.SIGTERM, None)
            gevent.signal_handler(signal.SIGINT, sigtermhandler, signal.SIGINT, None)
        else:
            signal.signal(signal.SIGTERM, sigtermhandler)
            signal.signal(signal.SIGINT, sigtermhandler)

        self.log(f"[blue]{self.svc_name}[/blue] [green]Started.[/green]")

        # Write pidfile
        atexit.register(self.delpid)  # Make sure pid file is removed if we quit
        pid = str(os.getpid())
        open(self.pidfile, "w+", encoding="utf-8").write(f"{pid}\n")

    def delpid(self):
        """
        Remove PID file if they are using it.
        """
        try:
            # the process may fork itself again
            pid = int(open(self.pidfile, "r", encoding="utf-8").read().strip())
            if pid == os.getpid():
                os.remove(self.pidfile)
        except OSError as e:
            if e.errno == errno.ENOENT:
                pass
            else:
                raise

    def start(self, *args, **kwargs):
        """
        Start the daemon by checking if it is already running and then
        calling the daemonize method to start the process.
        """

        self.console.print(
            f"[blue]{self.svc_name}[/blue] [green]is Starting...[/green]"
        )
        logger.debug(f"daemon {self.svc_name} is starting")
        # Check for a pidfile to see if the daemon already runs
        try:
            pfile = open(self.pidfile, "r", encoding="utf-8")
            pid = int(pfile.read().strip())
            pfile.close()
        except IOError:
            pid = None
        except SystemExit:
            pid = None

        if pid:
            self.console.print(
                f"[blue]{self.svc_name}[/blue] [green]is already running under process id: [yellow]{self.get_pid()}[/yellow]"
            )
            logger.debug(
                f"daemon {self.svc_name} is already running under process id: {self.get_pid()}"
            )
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run(*args, **kwargs)

    def status(self):
        """
        Get status from the daemon by checking if the process is running.
        """
        _ = self.is_running()

    def stop(self):
        """
        Stop the daemon by sending a SIGTERM signal to the process.
        """

        self.console.print(
            f"[blue]{self.svc_name}[/blue] [green]is Stopping...[/green]"
        )
        logger.debug(f"daemon {self.svc_name} is stopping")
        # Get the pid from the pidfile
        pid = self.get_pid()

        if not pid:
            self.console.print(
                f"[blue]{self.svc_name}[/blue] [green]is [dark_orange]not[/dark_orange] running.[/green]"
            )
            logger.debug(f"daemon {self.svc_name} is not running")
            # Just to be sure. A ValueError might occur if the PID file is
            # empty but does actually exist
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)

            return  # Not an error in a restart

        # Try killing the daemon process
        try:
            i = 0
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
                i = i + 1
                if i % 10 == 0:
                    os.kill(pid, signal.SIGHUP)
        except OSError as err:
            if err.errno == errno.ESRCH:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                logger.debug(str(err))
                sys.exit(1)

        try:
            os.remove(self.pidfile)
        except Exception as e:
            logger.error(f"couldn't remove pidfile: {e}")
        self.console.print(f"[blue]{self.svc_name}[/blue] [green]Stopped.[/green]")
        logger.debug(f"daemon {self.svc_name} is stopped")

    def restart(self):
        """
        Restart the daemon by stopping and starting it.
        """
        self.stop()
        self.start()

    def cleanup(self):
        """
        You should override this method if you need cleanup handlers on
        shutdown (ie, prior to sigterm handling) and set use_cleanup to
        ``True`` when you subclass Daemon().
        """
        raise NotImplementedError

    def get_pid(self):
        """
        Get process ID of the daemon.

        :return pid: daemon process ID
        :rtype int:
        """
        try:
            pfile = open(self.pidfile, "r", encoding="utf-8")
            pid = int(pfile.read().strip())
            pfile.close()
        except IOError:
            pid = None
        except SystemExit:
            pid = None
        return pid

    def is_running(self):
        """
        Check whether the daemon is running.

        :return: True if running, else False
        """
        pid = self.get_pid()

        if pid is None:
            self.console.print(
                f"[blue]{self.svc_name}[/blue] [green]process is [dark_orange]not[/dark_orange] running[/green]"
            )
            logger.debug(f"daemon {self.svc_name} is not running")
            return False
        if os.path.exists(self.pidfile):
            self.console.print(
                f"[blue]{self.svc_name}[/blue] [green]process ([/green][yellow]pid {pid}[/yellow][green]) [green_yellow]is[/green_yellow] running...[/green]"
            )
            logger.debug(f"daemon {self.svc_name} is running under process id: {pid}")
            return True
        self.console.print(
            f"[blue]{self.svc_name}[/blue] [green]process ([/green][yellow]pid {pid}[/yellow][green]) is killed[/green]"
        )
        logger.debug(f"daemon {self.svc_name} is killed under process id: {pid}")
        return False

    def run(self):
        """
        You should override this method when you subclass Daemon.
        It will be called after the process has been
        daemonized by start() or restart().
        """
        raise NotImplementedError
