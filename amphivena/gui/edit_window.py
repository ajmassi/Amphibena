import tkinter as tk
import scapy.config as sc
import scapy.layers.all


def initialize(parent):
    tk_root = tk.Toplevel(parent)
    tk_root.title("Edit Window")
    tk_root.geometry("600x400")
    tk_root.resizable(False, False)
    tk_root.option_add('*tearOff', False)

    MainApplication(tk_root).pack()
    tk_root.mainloop()


class MainApplication(tk.Frame):
    """ Main Container """

    def __init__(self, parent):
        tk.Frame.__init__(self, parent)

        self._layer_group_menu = _LayerGroupMenu(self)
        self._layer_menu = _LayerMenu(self)
        self._field_menu = _FieldMenu(self)

        self._layer_group_menu.pack()
        self._layer_menu.pack()
        self._field_menu.pack()

    def update_layermenu(self, selected_layer_group):
        self._field_menu.disable()
        _LayerMenu.update_contents(self._layer_menu, selected_layer_group)

    def update_fieldmenu(self, selected_layer):
        _FieldMenu.update_contents(self._field_menu, selected_layer)


class _LayerGroupMenu(tk.OptionMenu):
    def __init__(self, parent: MainApplication):
        self._group_detail_lookup = {y: x for (x, y) in sc.conf.layers.layers()}
        self._group_names = self._group_detail_lookup.keys()

        self._selection = tk.StringVar(parent)
        self._selection.set("Layer Group")
        self._selection.trace("w", self._selection_change)

        tk.OptionMenu.__init__(self, parent, self._selection, *self._group_names)

    def _selection_change(self, *args):
        self.master.update_layermenu(self._group_detail_lookup.get(self._selection.get()))


class _LayerMenu(tk.OptionMenu):
    def __init__(self, parent):
        self._layer_detail_lookup = {}
        self._layer_names = [""]

        self._selection = tk.StringVar(parent)
        self._selection.set("Layers")
        self._selection.trace("w", self._selection_change)

        tk.OptionMenu.__init__(self, parent, self._selection, *self._layer_names)

        self.configure(state="disabled")

    def _selection_change(self, *args):
        if self['state'] == "normal":
            self.master.update_fieldmenu(self._layer_detail_lookup.get(self._selection.get()))

    def update_contents(self, selected_layer_group):
        if self['state'] == "disabled":
            self.configure(state="normal")
        else:
            # Reset header default value without triggering selection trace event
            self.configure(state="disabled")
            self._selection.set("Layers")
            self.configure(state="normal")

        # Retrieve new set of scapy layers
        self._layer_detail_lookup = {x.__name__: x for x in sc.conf.layers.ldict[selected_layer_group]}
        self._layer_names = self._layer_detail_lookup.keys()

        # Clean and recreate menu elements
        self.children['menu'].delete(0, 'end')
        for layer in self._layer_names:
            # noinspection PyProtectedMember
            self.children['menu'].add_command(label=layer,
                                              command=tk._setit(self._selection, layer))


class _FieldMenu(tk.OptionMenu):
    def __init__(self, parent):
        self._field_names = [""]

        self._selection = tk.StringVar(parent)
        self._selection.set("Fields")
        self._selection.trace("w", self._selection_change)

        tk.OptionMenu.__init__(self, parent, self._selection, *self._field_names)

        self.configure(state="disabled")

    def _selection_change(self, *args):
        if self['state'] == "normal":
            print(self._selection.get())

    def disable(self):
        self.configure(state="disabled")
        self._selection.set("Fields")

    def update_contents(self, selected_layer):
        if self['state'] == "disabled":
            self.configure(state="normal")
        else:
            # Reset header default value without triggering selection trace event
            self.configure(state="disabled")
            self._selection.set("Fields")
            self.configure(state="normal")

        # Retrieve new set of scapy layer fields
        field_lookup = selected_layer.__module__ + '.' + selected_layer.__name__ + '.fields_desc'

        # This is the unholy first-attempt solution to executing and assigning a constructed scapy module reference
        exec(compile("self._field_names = " + field_lookup, '', 'single'))

        # Clean and recreate menu elements
        self.children['menu'].delete(0, 'end')
        for field in self._field_names:
            # noinspection PyProtectedMember
            self.children['menu'].add_command(label=field,
                                              command=tk._setit(self._selection, field))
