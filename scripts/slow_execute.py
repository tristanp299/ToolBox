#!/bin/env python3
import subprocess, os, signal, time, psutil
from threading import Thread, Event

class ThreadController:
    def __init__(self, command):
        """Initialize the thread controller for a command."""
        self.command = command
        self.process = None
        self.pid = None
        self.stop_event = Event()
        self._monitoring_thread = None

    def start_process(self):
        """Start the target process and return its PID."""
        self.process = subprocess.Popen(
            self.command,
            stderr=subprocess.PIPE,
            shell=True
        )
        self.pid = self.process.pid
        return self.pid

    def _get_thread_ids(self):
        """Get all thread IDs for the process."""
        try:
            process = psutil.Process(self.pid)
            return [thread.id for thread in process.threads()]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

    def suspend_thread(self, thread_id=None):
        """
        Suspend a specific thread or all threads of the process.
        thread_id (int, optional): Specific thread ID to suspend. If None, suspends all threads.
        """
        if self.pid is None:
            raise RuntimeError("Process not started")

        if thread_id is None:
            thread_ids = self._get_thread_ids()
        else:
            thread_ids = [thread_id]

        for tid in thread_ids:
            try:
                if os.name == 'nt':  # Windows
                    import win32api
                    import win32con
                    handle = win32api.OpenThread(win32con.THREAD_SUSPEND_RESUME, False, tid)
                    win32api.SuspendThread(handle)
                    win32api.CloseHandle(handle)
                else:  # Linux/Unix
                    os.kill(tid, signal.SIGSTOP)
                print(f"Suspended thread {tid}")
            except Exception as e:
                print(f"Failed to suspend thread {tid}: {e}")

    def resume_thread(self, thread_id=None):
        """
        Resume a specific thread or all threads of the process.
        thread_id (int, optional): Specific thread ID to resume. If None, resumes all threads.
        """
        if self.pid is None:
            raise RuntimeError("Process not started")

        if thread_id is None:
            thread_ids = self._get_thread_ids()
        else:
            thread_ids = [thread_id]

        for tid in thread_ids:
            try:
                if os.name == 'nt':  # Windows
                    import win32api
                    import win32con
                    handle = win32api.OpenThread(win32con.THREAD_SUSPEND_RESUME, False, tid)
                    win32api.ResumeThread(handle)
                    win32api.CloseHandle(handle)
                else:  # Linux/Unix
                    os.kill(tid, signal.SIGCONT)
                print(f"Resumed thread {tid}")
            except Exception as e:
                print(f"Failed to resume thread {tid}: {e}")

    def start_monitoring(self):
        """Start monitoring thread states."""
        def monitor():
            while not self.stop_event.is_set():
                thread_ids = self._get_thread_ids()
                print(f"\nActive threads for PID {self.pid}:")
                for tid in thread_ids:
                    print(f"Thread ID: {tid}")
                time.sleep(1)

        self._monitoring_thread = Thread(target=monitor)
        self._monitoring_thread.daemon = True
        self._monitoring_thread.start()

    def stop_monitoring(self):
        """Stop monitoring thread states."""
        self.stop_event.set()
        if self._monitoring_thread:
            self._monitoring_thread.join()

    def cleanup(self):
        """Clean up resources."""
        self.stop_monitoring()
        if self.process:
            self.process.terminate()
            self.process.wait()

if __name__ == "__main__":
    try:
        
        # Create controller for the command
        command = 'feroxbuster -u [INSERT URL HERE] -x pdf -x js,html -x ini,key,rsa,pub,bak,tgz,php,txt,env,pyjson,docx -g --thorough -t 2 --scan-limit 1 -A'
        controller = ThreadController(command)
        
        # Start the process
        pid = controller.start_process()
        print(f"Started process with PID: {pid}")
        
        # Start monitoring threads
        controller.start_monitoring()
        
        while(True):

            # Demo thread control
            time.sleep(5)
            print("\nSuspending all threads...")
            controller.suspend_thread()
            
            time.sleep(10)
            print("\nResuming all threads...")
            controller.resume_thread()
        
        time.sleep(2)
        
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        # Cleanup
        controller.cleanup()
       
