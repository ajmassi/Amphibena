import tkinter as tk
import amphivena.gui.edit_window as edit_window


def initialize():
    tk_root = RootWindow()
    tk_root.mainloop()


class RootWindow(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)

        self.title("Amphivena")
        self.geometry("600x400")
        self.resizable(False, False)
        self.option_add('*tearOff', False)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.config(menu=RootWindow.MenuBar(self))

        self.mainApplication = MainApplication(self)

    class MenuBar(tk.Menu):
        def __init__(self, parent):
            tk.Menu.__init__(self, parent)

            self.add_cascade(label="File", menu=self.file_menu())

        def file_menu(self):
            filemenu = tk.Menu(self, tearoff=0)
            filemenu.add_command(label="New")
            filemenu.add_command(label="Load")
            filemenu.add_command(label="Save")
            filemenu.add_separator()
            filemenu.add_command(label="Exit", command=self.close_root)
            return filemenu

        def close_root(self):
            self.master.destroy()


class MainApplication(tk.Frame):
    """ Main Container """

    def __init__(self, parent):
        tk.Frame.__init__(self, parent, bg="cyan")

        self.grid(sticky=tk.NSEW)

        self.playbookViewFrame = self.PlaybookViewFrame(self)

        #b1 = MainApplication.ButtonLaunchEditor(self)
        #b1.pack(side=tk.RIGHT)

    ##################
    # Widget Classes #
    ##################

    class PlaybookViewFrame(tk.Frame):
        def __init__(self, parent):
            tk.Frame.__init__(self, parent)

    class ButtonLaunchEditor(tk.Button):
        def __init__(self, parent):
            self.parent = parent
            tk.Button.__init__(self, parent, text="Launch Editor", command=self.on_click)

        def on_click(self):
            edit_window.initialize(self.parent)
