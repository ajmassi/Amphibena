import tkinter as tk
import scapy.config as sc
import scapy.layers.all


def initialize():
    tk_root = tk.Tk()
    tk_root.title("")
    tk_root.geometry("600x400")
    tk_root.resizable(False, False)
    tk_root.option_add('*tearOff', False)

    tk_root.config(menu=MenuBar(tk_root))
    MainApplication(tk_root).pack()
    tk_root.mainloop()


class MainApplication(tk.Frame):
    """ Main Container """

    def __init__(self, parent):
        tk.Frame.__init__(self, parent)

        self.protocol_group_menu = ProtocolGroupSelector(self)
        self.protocol_layer_menu = ProtocolLayerSelector(self)
        self.protocol_element_menu = ProtocolElementSelector(self)

        self.protocol_group_menu.pack()
        self.protocol_layer_menu.pack()
        self.protocol_element_menu.pack()

    def update_protocol_layers(self, protocol_group):
        self.protocol_element_menu.disable()
        ProtocolLayerSelector.update_contents(self.protocol_layer_menu, protocol_group)

    def update_protocol_elements(self, protocol_layer):
        ProtocolElementSelector.update_contents(self.protocol_element_menu, protocol_layer)


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


class ProtocolGroupSelector(tk.OptionMenu):
    def __init__(self, parent: MainApplication):
        self.protocol_group_details = {y: x for (x, y) in sc.conf.layers.layers()}
        self.protocol_group_labels = self.protocol_group_details.keys()

        self.selection = tk.StringVar(parent)
        self.selection.set("Protocol Group")
        self.selection.trace("w", self.selection_change)

        tk.OptionMenu.__init__(self, parent, self.selection, *self.protocol_group_labels)

    def selection_change(self, *args):
        self.master.update_protocol_layers(self.protocol_group_details.get(self.selection.get()))


class ProtocolLayerSelector(tk.OptionMenu):
    def __init__(self, parent):
        self.protocol_layer_details = {}
        self.protocol_layer_labels = [""]

        self.selection = tk.StringVar(parent)
        self.selection.set("Protocol Layer")
        self.selection.trace("w", self.selection_change)

        tk.OptionMenu.__init__(self, parent, self.selection, *self.protocol_layer_labels)

        self.configure(state="disabled")

    def selection_change(self, *args):
        if self['state'] == "normal":
            self.master.update_protocol_elements(self.protocol_layer_details.get(self.selection.get()))

    def update_contents(self, selected_protocol_group):
        if self['state'] == "disabled":
            self.configure(state="normal")
        else:
            # Reset header default value without triggering selection trace event
            self.configure(state="disabled")
            self.selection.set("Protocol Layer")
            self.configure(state="normal")

        # Retrieve new set of scapy protocol layers
        self.protocol_layer_details = {x.__name__: x for x in sc.conf.layers.ldict[selected_protocol_group]}
        self.protocol_layer_labels = self.protocol_layer_details.keys()

        # Clean and recreate menu elements
        self.children['menu'].delete(0, 'end')
        for layer in self.protocol_layer_labels:
            # noinspection PyProtectedMember
            self.children['menu'].add_command(label=layer,
                                              command=tk._setit(self.selection, layer))


class ProtocolElementSelector(tk.OptionMenu):
    def __init__(self, parent):
        self.protocol_elements = [""]

        self.selection = tk.StringVar(parent)
        self.selection.set("Protocol Element")
        self.selection.trace("w", self.selection_change)

        tk.OptionMenu.__init__(self, parent, self.selection, *self.protocol_elements)

        self.configure(state="disabled")

    def selection_change(self, *args):
        if self['state'] == "normal":
            print(self.selection.get())

    def disable(self):
        self.configure(state="disabled")

    def update_contents(self, selected_protocol_layer):
        if self['state'] == "disabled":
            self.configure(state="normal")
        else:
            # Reset header default value without triggering selection trace event
            self.configure(state="disabled")
            self.selection.set("Protocol Element")
            self.configure(state="normal")

        # Retrieve new set of scapy protocol elements
        elem_lookup = selected_protocol_layer.__module__ + '.' + selected_protocol_layer.__name__ + '.fields_desc'

        # This is the unholy first-attempt solution to executing and assigning a constructed scapy module reference
        exec(compile("self.protocol_elements = " + elem_lookup, '', 'single'))

        # Clean and recreate menu elements
        self.children['menu'].delete(0, 'end')
        for element in self.protocol_elements:
            # noinspection PyProtectedMember
            self.children['menu'].add_command(label=element,
                                              command=tk._setit(self.selection, element))
