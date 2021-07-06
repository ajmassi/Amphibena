import json
import tkinter as tk
from tkinter import filedialog

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
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.config(menu=RootWindow.MenuBar(self))
        self.bind_all("<Button-4>", self.mouse_wheel_handler)
        self.bind_all("<Button-5>", self.mouse_wheel_handler)

        self.main_application = json_editor.JsonEditor(self)

    def mouse_wheel_handler(self, event):
        def scroll_direction():
            if event.num == 5 or event.delta < 0:
                return 1
            return -1

        self.main_application.playbook_view_frame.scroll(scroll_direction())

    class MenuBar(tk.Menu):
        def __init__(self, parent):
            tk.Menu.__init__(self, parent)

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

            with open(filename, "r+") as op_conf:
                data = op_conf.read()

            print(json.loads(data))

        def close_root(self):
            self.master.destroy()


class MainApplication(tk.Frame):
    """Main Container"""

    def __init__(self, parent):
        tk.Frame.__init__(self, parent, bg="gray2")

        self.grid(sticky=tk.NSEW)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.playbook_view_frame = self.PlaybookViewFrame(self)

    ##################
    # Widget Classes #
    ##################

    class PlaybookViewFrame(tk.Frame):
        def __init__(self, parent: tk.Frame):
            tk.Frame.__init__(self, parent)
            self.grid(row=0, column=0, padx=5, pady=5)
            self.grid_rowconfigure(0, weight=1)
            self.grid_columnconfigure(0, weight=1)

            # Canvas used to manage scrollable region
            self.canvas = tk.Canvas(
                self, width=parent.winfo_vrootwidth(), height=parent.winfo_vrootheight()
            )
            self.canvas.grid(row=0, column=0, sticky=tk.NSEW)

            # Create a vertical scrollbar linked to the canvas.
            self.vertical_scroll_bar = tk.Scrollbar(
                self, orient=tk.VERTICAL, command=self.canvas.yview
            )
            self.vertical_scroll_bar.grid(row=0, column=1, sticky=tk.NS)
            self.canvas.configure(yscrollcommand=self.vertical_scroll_bar.set)

            # Create a horizontal scrollbar linked to the canvas.
            self.horizontal_scroll_bar = tk.Scrollbar(
                self, orient=tk.HORIZONTAL, command=self.canvas.xview
            )
            self.horizontal_scroll_bar.grid(row=1, column=0, sticky=tk.EW)
            self.canvas.configure(xscrollcommand=self.horizontal_scroll_bar.set)

            # Canvas Inner-Frame to store actual playbook data
            self.playbook_inner_frame = tk.Frame(self.canvas, bg="cyan")
            self.canvas.create_window(
                (0, 0), window=self.playbook_inner_frame, anchor="nw"
            )
            self.canvas.config(scrollregion=self.canvas.bbox("all"))

        def scroll(self, direction):
            self.canvas.yview_scroll(direction, "unit")

    class ButtonLaunchEditor(tk.Button):
        def __init__(self, parent):
            self.parent = parent
            tk.Button.__init__(
                self, parent, text="Launch Editor", command=self.on_click
            )

        def on_click(self):
            edit_window.initialize(self.parent)
