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
        self.resizable(True, True)
        self.option_add('*tearOff', False)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.config(menu=RootWindow.MenuBar(self))
        self.bind_all("<Button-4>", self.mouse_wheel_handler)
        self.bind_all("<Button-5>", self.mouse_wheel_handler)

        self.main_application = MainApplication(self)

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
            self.canvas = tk.Canvas(self, width=parent.winfo_vrootwidth(), height=parent.winfo_vrootheight())
            self.canvas.grid(row=0, column=0, sticky=tk.NSEW)

            # Create a vertical scrollbar linked to the canvas.
            self.vertical_scroll_bar = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.canvas.yview)
            self.vertical_scroll_bar.grid(row=0, column=1, sticky=tk.NS)
            self.canvas.configure(yscrollcommand=self.vertical_scroll_bar.set)

            # Create a horizontal scrollbar linked to the canvas.
            self.horizontal_scroll_bar = tk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.canvas.xview)
            self.horizontal_scroll_bar.grid(row=1, column=0, sticky=tk.EW)
            self.canvas.configure(xscrollcommand=self.horizontal_scroll_bar.set)

            # Below based on:
            # https://stackoverflow.com/questions/43731784/tkinter-canvas-scrollbar-with-grid
            # Canvas Inner-Frame to store actual playbook data
            self.playbook_inner_frame = tk.Frame(self.canvas, bg="cyan")
            self.canvas.create_window((0, 0), window=self.playbook_inner_frame, anchor='nw')

            rows = 100
            columns = 5
            buttons = [[tk.Button() for j in range(columns)] for i in range(rows)]
            for i in range(0, rows):
                for j in range(0, columns):
                    buttons[i][j] = tk.Button(self.playbook_inner_frame, text=("%d,%d" % (i + 1, j + 1)))
                    buttons[i][j].grid(row=i, column=j, sticky='news')

            # Update buttons frames idle tasks to let tkinter calculate buttons sizes
            self.playbook_inner_frame.update_idletasks()

            # Resize the canvas frame to show exactly 5-by-5 buttons and the scrollbar
            first5columns_width = sum([buttons[0][j].winfo_width() for j in range(0, 5)])
            first5rows_height = sum([buttons[i][0].winfo_height() for i in range(0, 5)])
            self.config(width=first5columns_width + self.vertical_scroll_bar.winfo_width(), height=first5rows_height)

            # Set the canvas scrolling region
            self.canvas.config(scrollregion=self.canvas.bbox("all"))

        def scroll(self, direction):
            self.canvas.yview_scroll(direction, "unit")

    class ButtonLaunchEditor(tk.Button):
        def __init__(self, parent):
            self.parent = parent
            tk.Button.__init__(self, parent, text="Launch Editor", command=self.on_click)

        def on_click(self):
            edit_window.initialize(self.parent)
