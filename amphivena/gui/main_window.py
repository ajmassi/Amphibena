import tkinter as tk
import amphivena.gui.edit_window as edit_window


def initialize():
    tk_root = tk.Tk()
    tk_root.title("Amphivena")
    tk_root.geometry("600x400")
    tk_root.resizable(False, False)
    tk_root.option_add('*tearOff', False)

    tk_root.config(menu=_MenuBar(tk_root))
    MainApplication(tk_root).pack()

    tk_root.mainloop()


class MainApplication(tk.Frame):
    """ Main Container """

    def __init__(self, parent):
        tk.Frame.__init__(self, parent)
        b1 = _ButtonLaunchEditor(self)
        b1.pack(side=tk.RIGHT)


class _MenuBar(tk.Menu):
    def __init__(self, parent):
        tk.Menu.__init__(self, parent)

        self.add_cascade(label="File", menu=self.file_menu())

    def file_menu(self):
        filemenu = tk.Menu(self, tearoff=0)
        filemenu.add_command(label="New")
        filemenu.add_command(label="Load")
        filemenu.add_command(label="Save")
        filemenu.add_separator()
        filemenu.add_command(label="Exit")
        return filemenu


class _ButtonLaunchEditor(tk.Button):
    def __init__(self, parent: MainApplication):
        self.parent = parent
        tk.Button.__init__(self, parent, text="Launch Editor", command=self.on_click)

    def on_click(self):
        edit_window.initialize(self.parent)
