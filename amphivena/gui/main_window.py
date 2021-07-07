import json
import tkinter as tk
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText

from amphivena.gui import edit_window, json_editor


def initialize():
    tk_root = RootWindow()
    tk_root.mainloop()


class RootWindow(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)

        self.title("Amphivena")
        self.geometry("600x400")
        self.resizable(True, True)
        self.option_add("*tearOff", False)

        self.config(menu=RootWindow.MenuBar(self), bg="grey2")
        self.config_file_path = tk.StringVar(self, "<no config file set>")

        self.main_application = MainApplication(self)

    class MenuBar(tk.Menu):
        def __init__(self, parent):
            tk.Menu.__init__(self, parent)

            self.winfo_parent()
            self.add_cascade(label="File", menu=self.file_menu())

        def file_menu(self):
            filemenu = tk.Menu(self, tearoff=0)
            filemenu.add_command(label="New")
            filemenu.add_command(label="Load", command=self.load_file)
            filemenu.add_command(label="Save")
            filemenu.add_separator()
            filemenu.add_command(label="Exit", command=self.close_root)
            return filemenu

        def load_file(self):
            filename = filedialog.askopenfilename(
                title="Open a Amp config file",
                initialdir="./",
                filetypes=[("Json", "*.json")],
            )

            self.master.config_file_path.set(filename)

        def close_root(self):
            self.master.destroy()


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
            self.config_file_button = tk.Button(
                self,
                textvariable=self.winfo_toplevel().config_file_path,
                command=self.open_edit_window,
            )
            self.run_config = tk.Button(self, text=chr(0x25B6))

            self.config_file_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=1, padx=10)
            self.run_config.pack(side=tk.RIGHT, expand=0, padx=(0, 10))

        def open_edit_window(self):
            # editor_window = json_editor.JsonEditor(self)
            pass

    class ConsoleFrame(tk.Frame):
        def __init__(self, parent: tk.Frame):
            tk.Frame.__init__(self, parent, bg="white")

            self.console_text = ScrolledText(self, state="disabled")
