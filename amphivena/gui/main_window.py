import functools
import logging
import queue
import signal
import tkinter as tk
from tkinter import filedialog, simpledialog
from tkinter.scrolledtext import ScrolledText

import multiprocessing_logging

from amphivena import controller
from amphivena.gui import json_editor

log = logging.getLogger(__name__)


def initialize(iface1, iface2, playbook):
    tk_root = RootWindow(iface1, iface2, playbook)
    tk_root.mainloop()


class QueueHandler(logging.Handler):
    """Log record queue for staging logs destined for the ConsoleFrame"""

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)


class RootWindow(tk.Tk):
    def __init__(self, iface1, iface2, playbook):
        tk.Tk.__init__(self)

        self.title("Amphivena")
        self.geometry("600x400")
        self.minsize(300, 200)
        self.resizable(True, True)
        self.option_add("*tearOff", False)

        self.cntlr = controller.Controller(iface1, iface2, playbook)
        # Duplication of var, but doesnt make sense for Controller to store tk vars, especially when running without GUI
        self.gui_config = {
            "playbook_file_path": tk.StringVar(
                None, self.cntlr.config.get("playbook_file_path")
            )
        }

        self.config(
            menu=RootWindow.MenuBar(self, self.cntlr, self.gui_config), bg="grey2"
        )
        self.main_application = MainApplication(self, self.cntlr, self.gui_config)

        self.protocol("WM_DELETE_WINDOW", self.quit)
        self.bind("<Control-q>", self.quit)
        signal.signal(signal.SIGINT, self.quit)

    def quit(self, *args):
        if self.cntlr.is_running:
            self.cntlr.halt()
        self.destroy()

    class MenuBar(tk.Menu):
        def __init__(self, parent, cntlr, gui_config):
            tk.Menu.__init__(self, parent)

            self.parent = parent
            self.cntlr = cntlr
            self.gui_config = gui_config
            self.add_cascade(label="File", menu=self.file_menu())
            self.add_cascade(label="MitM", menu=self.mitm_menu())

        def file_menu(self):
            filemenu = tk.Menu(self, tearoff=0)
            filemenu.add_command(label="New")
            filemenu.add_command(label="Load", command=self.load_playbook)
            filemenu.add_separator()
            filemenu.add_command(label="Exit", command=self.master.quit)
            return filemenu

        def mitm_menu(self):
            def edit_iface(iface):
                dialog = simpledialog.askstring(
                    title="Edit Interface",
                    prompt="Interface name (ex. 'eth0'):",
                    initialvalue=self.cntlr.config.get(iface),
                    parent=self.parent,
                )
                if dialog == "":
                    self.cntlr.config.update({iface: None})
                elif dialog:
                    self.cntlr.config.update({iface: dialog})
                return

            mitmmenu = tk.Menu(self, tearoff=0)
            mitmmenu.add_command(label="iface1", command=lambda: edit_iface("iface1"))
            mitmmenu.add_command(label="iface2", command=lambda: edit_iface("iface2"))
            return mitmmenu

        def load_playbook(self):
            filename = filedialog.askopenfilename(
                title="Open a Amp playbook file",
                initialdir="./",
                filetypes=[("Json", "*.json")],
            )

            # Verify a file was selected
            if filename:
                self.gui_config.get("playbook_file_path").set(filename)
                self.cntlr.config.update({"playbook_file_path": filename})
                log.info(f"Selected playbook: {filename}")


class MainApplication(tk.Frame):
    """Main Container"""

    def __init__(self, parent, cntlr, gui_config):
        tk.Frame.__init__(self, parent)
        self.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.controls = self.ControlFrame(self, cntlr, gui_config)
        self.console = self.ConsoleFrame(self)

        self.controls.pack(
            anchor=tk.N, fill=tk.X, expand=False, side=tk.TOP, padx=10, pady=15
        )
        self.console.pack(
            anchor=tk.S, fill=tk.BOTH, expand=True, side=tk.BOTTOM, padx=5, pady=5
        )

    ##################
    # Widget Classes #
    ##################

    class ControlFrame(tk.Frame):
        """
        Contains the controls for selecting playbook, opening editor, and beginning execution.
        """

        def __init__(self, parent: tk.Frame, cntlr, gui_config):
            tk.Frame.__init__(self, parent, height=100)

            self.cntlr = cntlr
            self.gui_config = gui_config
            self.is_playbook_running = tk.BooleanVar(value=False)
            self.play_pause_string = tk.StringVar(value=f"{chr(0x25B6)}")

            self.playbook_file_path_button = tk.Button(
                self,
                textvariable=self.gui_config.get("playbook_file_path"),
                command=self.open_edit_window,
            )

            self.run_playbook_button = tk.Button(
                self,
                textvariable=self.play_pause_string,
                command=self.controller_toggle,
            )
            self.update_play_button()

            self.playbook_file_path_button.pack(
                side=tk.LEFT, fill=tk.BOTH, expand=1, padx=10
            )
            self.run_playbook_button.pack(side=tk.RIGHT, expand=0, padx=(0, 10))

        def update_play_button(self):
            # Update play/pause button icon on regular interval
            # This is an easy way to work around there being no easy way to pass information from the controller thread
            if self.cntlr.is_running:
                self.play_pause_string.set(value=f"{chr(0x25AE)}{chr(0x25AE)}")
            else:
                self.play_pause_string.set(value=f"{chr(0x25B6)}")
            self.after(500, self.update_play_button)

        def open_edit_window(self):
            if self.cntlr.config.get("playbook_file_path") != "<no playbook file set>":
                editor_window = json_editor.EditorWindow(
                    self.cntlr.config.get("playbook_file_path")
                )
                if editor_window.winfo_exists():
                    editor_window.transient(self.winfo_toplevel())
                    editor_window.grab_set()
                    self.winfo_toplevel().wait_window(editor_window)

        def controller_toggle(self):
            self.cntlr.onoff_toggle()

    class ConsoleFrame(tk.Frame):
        """
        Display Amphivena logs in real time.
        """

        def __init__(self, parent: tk.Frame):
            tk.Frame.__init__(self, parent, bg="white")

            self.scrolled_text = ScrolledText(self, state="disabled")

            # Create a ScrolledText widget
            self.scrolled_text.configure(font="TkFixedFont")
            self.scrolled_text.tag_config("INFO", foreground="black")
            self.scrolled_text.tag_config("DEBUG", foreground="gray")
            self.scrolled_text.tag_config("WARNING", foreground="orange")
            self.scrolled_text.tag_config("ERROR", foreground="red")
            self.scrolled_text.tag_config("CRITICAL", foreground="red", underline=True)
            # Create a logging handler using a queue
            self.log_queue = queue.Queue()
            self.queue_handler = QueueHandler(self.log_queue)
            formatter = logging.Formatter("%(asctime)s: %(message)s")
            self.queue_handler.setFormatter(formatter)
            amp_log = logging.getLogger("amphivena")
            amp_log.addHandler(self.queue_handler)
            multiprocessing_logging.install_mp_handler(amp_log)
            # Start polling messages from the queue
            self.after(100, self.poll_log_queue)

            self.scrolled_text.pack(fill="both", expand=True)

        def display(self, record):
            msg = self.queue_handler.format(record)
            self.scrolled_text.configure(state="normal")
            self.scrolled_text.insert(tk.END, msg + "\n", record.levelname)
            self.scrolled_text.configure(state="disabled")
            # Autoscroll to the bottom
            self.scrolled_text.yview(tk.END)

        def poll_log_queue(self):
            # Check every 100ms if there is a new message in the queue to display
            while True:
                try:
                    record = self.log_queue.get(block=False)
                except queue.Empty:
                    break
                else:
                    self.display(record)
            self.after(100, self.poll_log_queue)
