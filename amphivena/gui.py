import tkinter as tk


def initialize():
    tk_root = tk.Tk()
    tk_root.title("")
    tk_root.geometry("800x600")
    tk_root.resizable(False, False)
    tk_root.option_add('*tearOff', False)

    tk_root.config(menu=MenuBar(tk_root))
    MainApplication(tk_root)
    tk_root.mainloop()


class MainApplication(tk.Frame):
    """ Main Container """

    def __init__(self, parent):
        tk.Frame.__init__(self, parent)


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
        filemenu.add_command(label="Exit")
        return filemenu
