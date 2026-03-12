# =============================================================================
# GhostSecure 2.0  -  Active Directory Attack Detector
# Main Entry Point / Windows Service
# Coded by Egyan
# =============================================================================

import logging
import logging.handlers
import os
import sys
import time
import threading

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

import config


def setup_logging():
    """Configure file + console logging."""
    try:
        os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
    except OSError as e:
        print(f"WARNING: Could not create log dir: {e}")

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()

    try:
        svc_log = os.path.join(config.LOG_DIRECTORY, "ghostsecure_service.log")
        fh = logging.handlers.RotatingFileHandler(
            svc_log, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
        )
        fh.setLevel(getattr(logging, config.FILE_LOG_LEVEL, logging.DEBUG))
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        root_logger.addHandler(fh)
    except (IOError, OSError) as e:
        print(f"WARNING: Log file handler failed: {e}")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(getattr(logging, config.CONSOLE_LOG_LEVEL, logging.INFO))
    ch.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'
    ))
    root_logger.addHandler(ch)
    return root_logger


# --- Windows Service ---
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import win32timezone
    HAS_WIN32_SERVICE = True
except ImportError:
    HAS_WIN32_SERVICE = False


if HAS_WIN32_SERVICE:
    class GhostSecureService(win32serviceutil.ServiceFramework):
        _svc_name_ = config.SERVICE_NAME
        _svc_display_name_ = config.APP_DISPLAY_NAME
        _svc_description_ = config.SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._engine = None
            self._thread = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self._engine:
                self._engine.stop()
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            setup_logging()
            logger = logging.getLogger("GhostSecure2.Service")
            logger.info(f"{config.APP_NAME} service starting...")

            try:
                from core.detector_engine import DetectorEngine
                self._engine = DetectorEngine()
                self._thread = threading.Thread(
                    target=self._engine.run, daemon=True
                )
                self._thread.start()
                logger.info("Detection engine started.")
                win32event.WaitForSingleObject(
                    self.hWaitStop, win32event.INFINITE
                )
                if self._engine:
                    self._engine.stop()
                if self._thread and self._thread.is_alive():
                    self._thread.join(timeout=30)
                logger.info(f"{config.APP_NAME} service stopped.")
            except Exception as e:
                logger.critical(f"Service fatal error: {e}", exc_info=True)

            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, '')
            )


def run_console_mode():
    """Run in interactive console mode for debugging."""
    setup_logging()
    logger = logging.getLogger("GhostSecure2.Console")
    print()
    print("=" * 70)
    print(f"  \U0001f47b {config.APP_NAME} v{config.APP_VERSION}")
    print(f"  Active Directory Attack Detector  -  Coded by {config.APP_AUTHOR}")
    print(f"  Red Parrot Accounting Ltd")
    print("=" * 70)
    print(f"  Console Mode | Log: {config.LOG_FILE}")
    print("  Press Ctrl+C to stop.")
    print()

    try:
        from core.detector_engine import DetectorEngine
        engine = DetectorEngine()
        engine.run()
    except KeyboardInterrupt:
        print("\n  Shutting down...")
        if 'engine' in locals():
            engine.stop()
    except Exception as e:
        logger.critical(f"Fatal: {e}", exc_info=True)
        sys.exit(1)


def run_self_test():
    """Quick self-test to verify all modules load."""
    setup_logging()
    print(f"\n  \U0001f47b {config.APP_NAME}  -  Self Test")
    print("  " + "=" * 50)

    passed = failed = 0

    def check(name, func):
        nonlocal passed, failed
        try:
            func()
            print(f"  \u2705 {name}")
            passed += 1
        except Exception as e:
            print(f"  \u274c {name}: {e}")
            failed += 1

    check("Config loads", lambda: (
        None if config.APP_NAME == "GhostSecure 2.1" else (_ for _ in ()).throw(Exception("bad"))
    ))

    check("AlertManager", lambda: __import__(
        'core.alert_manager', fromlist=['AlertManager']).AlertManager()
    )

    def test_parsed_event():
        from core.event_reader import ParsedEvent
        pe = ParsedEvent()
        pe.EventID = 4769
        pe.ServiceName = "test"
    check("ParsedEvent", test_parsed_event)

    for det in ["kerberoasting","pass_the_hash","dcsync","golden_ticket",
                "ldap_recon","asrep_roasting","skeleton_key"]:
        check(f"Detector: {det}", lambda d=det: (
            getattr(__import__(f'detectors.{d}', fromlist=['detect']), 'detect')
        ))

    check("DetectorEngine import", lambda: __import__(
        'core.detector_engine', fromlist=['DetectorEngine']
    ))

    check("Time helpers", lambda: (
        __import__('utils.time_helpers', fromlist=['now_timestamp']).now_timestamp()
    ))

    def test_ad():
        from utils.ad_helpers import is_machine_account
        assert is_machine_account("DC01$")
        assert not is_machine_account("john")
    check("AD helpers", test_ad)

    def test_logdir():
        os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
        tf = os.path.join(config.LOG_DIRECTORY, ".test")
        with open(tf, 'w') as f: f.write("t")
        os.remove(tf)
    check("Log directory writable", test_logdir)

    print(f"\n  Results: {passed} passed, {failed} failed")
    print("  " + "=" * 50)
    if failed:
        print("  \u26a0 Some tests failed. Review before deployment.")
    else:
        print("  \u2705 All passed. Ready for deployment.")
    print()


def print_usage():
    print(f"""
  \U0001f47b {config.APP_NAME} v{config.APP_VERSION}  -  Coded by {config.APP_AUTHOR}

  Usage:
    GhostSecure2.exe install     Install as Windows Service
    GhostSecure2.exe start       Start the service
    GhostSecure2.exe stop        Stop the service
    GhostSecure2.exe remove      Remove the service
    GhostSecure2.exe --console   Console/debug mode
    GhostSecure2.exe --gui       Status dashboard
    GhostSecure2.exe --test      Self-test
    GhostSecure2.exe --version   Version info
    GhostSecure2.exe --help      This help
""")


def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ("--console", "-c", "console"):
            run_console_mode(); return
        if arg in ("--gui", "-g", "gui"):
            setup_logging()
            from core.detector_engine import DetectorEngine
            from gui.status_dashboard import launch_dashboard
            engine = DetectorEngine()
            engine_thread = threading.Thread(target=engine.run, daemon=True)
            engine_thread.start()
            launch_dashboard(engine)
            engine.stop()
            return
        if arg in ("--test", "-t", "test"):
            run_self_test(); return
        if arg in ("--version", "-v"):
            print(f"{config.APP_NAME} v{config.APP_VERSION}  -  {config.APP_AUTHOR}")
            return
        if arg in ("--help", "-h"):
            print_usage(); return

    if HAS_WIN32_SERVICE:
        if len(sys.argv) == 1:
            try:
                servicemanager.Initialize()
                servicemanager.PrepareToHostSingle(GhostSecureService)
                servicemanager.StartServiceCtrlDispatcher()
            except Exception:
                run_console_mode()
        else:
            win32serviceutil.HandleCommandLine(GhostSecureService)
    else:
        print("WARNING: pywin32 not installed. Console mode.")
        run_console_mode()


if __name__ == "__main__":
    main()
