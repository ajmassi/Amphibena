import logging
import queue
import signal
import tkinter as tk
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText

from amphivena import mitm
from amphivena.gui import json_editor

log = logging.getLogger(__name__)


def initialize():
    tk_root = RootWindow()
    tk_root.mainloop()


class QueueHandler(logging.Handler):
    """Class to send logging records to a queue
    It can be used from different threads
    The ConsoleUi class polls this queue to display records in a ScrolledText widget
    """

    # Example from Moshe Kaplan: https://gist.github.com/moshekaplan/c425f861de7bbf28ef06
    # (https://stackoverflow.com/questions/13318742/python-logging-to-tkinter-text-widget) is not thread safe!
    # See https://stackoverflow.com/questions/43909849/tkinter-python-crashes-on-new-thread-trying-to-log-on-main-thread

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)


class RootWindow(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)

        self.title("Amphivena")
        self.geometry("600x400")
        self.minsize(300, 200)
        self.resizable(True, True)
        self.option_add("*tearOff", False)

        self.config(menu=RootWindow.MenuBar(self), bg="grey2")
        self.config_file_path = tk.StringVar(self, "<no playbook file set>")

        self.main_application = MainApplication(self)

        self.protocol("WM_DELETE_WINDOW", self.quit)
        self.bind("<Control-q>", self.quit)
        signal.signal(signal.SIGINT, self.quit)

    def quit(self, *args):
        self.destroy()

    class MenuBar(tk.Menu):
        def __init__(self, parent):
            tk.Menu.__init__(self, parent)

            self.winfo_parent()
            self.add_cascade(label="File", menu=self.file_menu())

        def file_menu(self):
            filemenu = tk.Menu(self, tearoff=0)
            filemenu.add_command(label="New")
            filemenu.add_command(label="Load", command=self.load_playbook)
            filemenu.add_separator()
            filemenu.add_command(label="Exit", command=self.master.quit)
            return filemenu

        def load_playbook(self):
            filename = filedialog.askopenfilename(
                title="Open a Amp config file",
                initialdir="./",
                filetypes=[("Json", "*.json")],
            )

            self.master.config_file_path.set(filename)

            log.info(f"Selected playbook: {filename}")


class MainApplication(tk.Frame):
    """Main Container"""

    def __init__(self, parent):
        tk.Frame.__init__(self, parent)
        self.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.controls = self.ControlFrame(self)
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
        def __init__(self, parent: tk.Frame):
            tk.Frame.__init__(self, parent, height=100)

            self.mitm = None
            self.is_playbook_running = tk.BooleanVar(value=False)
            self.play_pause_string = tk.StringVar(value=f"{chr(0x25B6)}")

            self.config_file_button = tk.Button(
                self,
                textvariable=self.winfo_toplevel().config_file_path,
                command=self.open_edit_window,
            )
            self.run_playbook_button = tk.Button(
                self, textvariable=self.play_pause_string, command=self.run_playbook
            )

            self.config_file_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=1, padx=10)
            self.run_playbook_button.pack(side=tk.RIGHT, expand=0, padx=(0, 10))

        def open_edit_window(self):
            if self.winfo_toplevel().config_file_path.get() != "<no playbook file set>":
                editor_window = json_editor.EditorWindow(
                    self.winfo_toplevel().config_file_path
                )
                editor_window.transient(self.winfo_toplevel())
                editor_window.grab_set()
                self.winfo_toplevel().wait_window(editor_window)

        def run_playbook(self):
            if self.is_playbook_running.get():
                # if packet_process.is_alive():
                #     packet_process.terminate()
                #     packet_process.join()
                #     packet_process.close()
                self.mitm.teardown()
                self.mitm = None
                del self.mitm
                self.play_pause_string.set(value=f"{chr(0x25B6)}")
            else:
                try:
                    self.mitm = mitm.MitM("eth1", "eth2")
                    # packet_process.start()
                    self.play_pause_string.set(value=f"{chr(0x25AE)}{chr(0x25AE)}")
                except (PermissionError, RuntimeError) as e:
                    log.error(e)
                    return

            self.is_playbook_running.set(not self.is_playbook_running.get())

    class ConsoleFrame(tk.Frame):
        def __init__(self, parent: tk.Frame):
            tk.Frame.__init__(self, parent, bg="white")

            self.scrolled_text = ScrolledText(self, state="disabled")

            # Create a ScrolledText widget
            self.scrolled_text.configure(font="TkFixedFont")
            self.scrolled_text.tag_config("INFO", foreground="black")
            self.scrolled_text.tag_config("DEBUG", foreground="gray")
            self.scrolled_text.tag_config("WARNING", foreground="orange")
            self.scrolled_text.tag_config("ERROR", foreground="red")
            self.scrolled_text.tag_config("CRITICAL", foreground="red", underline=1)
            # Create a logging handler using a queue
            self.log_queue = queue.Queue()
            self.queue_handler = QueueHandler(self.log_queue)
            formatter = logging.Formatter("%(asctime)s: %(message)s")
            self.queue_handler.setFormatter(formatter)
            amp_log = logging.getLogger("amphivena")
            amp_log.addHandler(self.queue_handler)
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
