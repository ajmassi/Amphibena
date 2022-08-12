import collections
import json
import logging
import os
import tkinter as tk
from tkinter import filedialog as fd, messagebox as mb, simpledialog as sd, ttk

from amphivena import playbook_utils

log = logging.getLogger(__name__)


"""
Layout:
-master
 |--wrapper
 |  |--header_wrapper
 |  |  |--title
 |  |  |--expand_all
 |  |  |--new_json_btn
 |  |  |--new_json_file_btn
 |  |  |--load_json_file_btn
 |  |--body_wrapper
 |  |  |--tree

"""


class ValueTypes:
    DICT = 1
    LIST = 2
    STR = 3
    FILEPATH = 4


class Tags:
    DICT = "dict"
    LIST = "list"
    ROOT = "root"
    LEAF = "leaf"


class EditorWindow(tk.Toplevel):
    def __init__(self, filepath):
        tk.Toplevel.__init__(self)
        self.title(f"Playbook Editor - {os.path.basename(filepath.get())}")
        self.geometry("600x400")
        self.resizable(True, True)

        JsonEditor(self, filepath)

    def update_filepath(self, filepath):
        self.title(f"Playbook Editor - {os.path.basename(filepath)}")
        self.master.playbook_file_path.set(filepath)


class JsonEditor:
    def __init__(self, parent, filepath, **options):
        self.parent = parent
        self.filepath = filepath.get()

        self.popup_menu_actions = collections.OrderedDict()

        if not options.get("readonly"):

            self.popup_menu_actions["add_child_dict"] = {
                "text": "Add Dict",
                "action": lambda: self.add_item_from_input(ValueTypes.DICT),
            }

            self.popup_menu_actions["add_child_list"] = {
                "text": "Add List",
                "action": lambda: self.add_item_from_input(ValueTypes.LIST),
            }

            self.popup_menu_actions["add_child_value"] = {
                "text": "Add Value",
                "action": lambda: self.add_item_from_input(ValueTypes.STR),
            }

            self.popup_menu_actions["add_child_filepath"] = {
                "text": "Add Filepath",
                "action": lambda: self.add_item_from_input(ValueTypes.FILEPATH),
            }

            self.popup_menu_actions["edit_child"] = {
                "text": "Edit",
                "action": lambda: self.edit_item_from_input(),
            }

            self.popup_menu_actions["remove_child"] = {
                "text": "Remove",
                "action": lambda: self.remove_item_from_input(
                    self.get_selected_index()
                ),
            }

        wrapper = ttk.Frame(parent)
        wrapper.pack(fill=tk.BOTH, expand=True)

        header_wrapper = ttk.Frame(wrapper)
        header_wrapper.pack(fill=tk.X)

        self.title = tk.StringVar()
        ttk.Label(header_wrapper, textvariable=self.title).pack(
            side=tk.LEFT, anchor=tk.N
        )

        # 'Save As' Button
        ttk.Button(
            header_wrapper,
            text="Save As",
            command=lambda: self.save_json_file(fd.asksaveasfilename()),
        ).pack(side=tk.RIGHT)

        # Save Button
        ttk.Button(
            header_wrapper,
            text="Save",
            command=lambda: self.save_json_file(self.filepath),
        ).pack(side=tk.RIGHT)

        # Expand All Button
        self.are_all_expanded = tk.BooleanVar()
        self.are_all_expanded.set(False)
        ttk.Checkbutton(
            header_wrapper,
            text="Expand All",
            variable=self.are_all_expanded,
            command=self.expand_toggle,
        ).pack(side=tk.LEFT)

        body_wrapper = ttk.Frame(wrapper)
        body_wrapper.pack(fill=tk.BOTH, expand=True)
        body_wrapper.columnconfigure(0, weight=1)
        body_wrapper.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(body_wrapper, selectmode="browse")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tree.bind("<Button-3>", lambda event: self.show_popup_menu(event))

        self.tree.item("", tags=[Tags.DICT])
        self.tree.tag_configure(Tags.ROOT, background="yellow")

        yscroll = ttk.Scrollbar(self.tree, orient=tk.VERTICAL, command=self.tree.yview)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.configure(yscrollcommand=yscroll.set)

        self.set_columns()

        self.popup_menu = tk.Menu(self.tree, tearoff=0)
        self.update_popup_menu()

        try:
            self.load_json_from_file(self.filepath)
        except playbook_utils.PlaybookValidationError as e:
            log.error(e)
            self.parent.destroy()

    def expand_toggle(self):
        """
        This function toggles between expanding the tree and closing it.
        """
        children = self.tree.get_children()

        if self.are_all_expanded.get():
            for child in children:
                self.expand_tree(child)
        else:
            for child in children:
                self.collapse_tree(child)

    def expand_tree(self, node):
        """
        Expands the node and its children.
        :param node: Its a <tk.Treeview> node object.
        """
        self.tree.item(node, open=True)
        children = self.tree.get_children([node])
        if len(children) > 0:
            for child in children:
                self.expand_tree(child)

    def collapse_tree(self, node):
        """
        Closes the node and its children.
        :param node: Its a <tk.Treeview> node object.
        """
        children = self.tree.get_children([node])
        if len(children) > 0:
            for child in children:
                self.collapse_tree(child)

        self.tree.item(node, open=False)

    def set_columns(self, columns=("Key", "Value")):
        """
        Sets the column headings with the given column tuple.
        :param columns: A <tuple> containing <str> objects.
        """
        col_ids = ["#" + str(i) for i in range(len(columns) - 1)]
        self.tree.configure(column=col_ids)
        for i in range(len(columns)):
            self.tree.heading("#" + str(i), text=columns[i])

    def set_action_item_selected(self, action):
        """
        :param action: Its a function, the format must be action(selected_item).
        """
        self.tree.bind(
            "<<TreeviewSelect>>", lambda event: action(self.get_selected_index())
        )

    def set_action_item_opened(self, action):
        """
        :param action: Its a function, the format must be action(selected_item).
        """
        self.tree.bind(
            "<<TreeviewOpen>>", lambda event: action(self.get_selected_index())
        )

    def set_action_item_closed(self, action):
        """
        :param action: Its a function, the format must be action(selected_item).
        """
        self.tree.bind(
            "<<TreeviewClose>>", lambda event: action(self.get_selected_index())
        )

    def add_popup_menu_action(self, menu_id, action, text=None):
        """
        This function allows the controller to add custom popup menu actions.
        :param menu_id: Unigue id for the menu.
        :param action: The function execute for this menu event.
        :param text: Display text for menu, default is menu_id.
        """
        self.popup_menu_actions[menu_id] = {"text": text or menu_id, "action": action}
        self.update_popup_menu()

    def add_node(self, key, value, node="", tags=[]):
        """
        Performs a recursive traversal to populate the item tree starting from given node.
        Each item is a key-value pair. Root node is defined by node=''.
        :param key: A <str> key, can be <int> in absence of a key, for example list items.
        :param value: It can be any of the primitive data type.
        :param node: Initially '', otherwise a <tk.Treeview> node object.
        """
        if node == "":
            tags = tags + [Tags.ROOT]

        if type(value) is dict:
            node = self.tree.insert(
                node, tk.END, text=str(key), tags=tags + [Tags.DICT]
            )
            for k in value:
                self.add_node(k, value[k], node)
        elif type(value) is list:
            node = self.tree.insert(
                node, tk.END, text=str(key), tags=tags + [Tags.LIST]
            )
            for k in range(len(value)):
                self.add_node(k, value[k], node)
        else:
            self.tree.insert(
                node, tk.END, text=str(key), tags=tags + [Tags.LEAF], values=[value]
            )

    def add_item_from_input(self, vtype=ValueTypes.STR):
        """
        :param vtype: A <int> value from ValueTypes. Determines what input to take.
        """
        parent = self.get_selected_index()

        if self.verify_selection(Tags.DICT):

            key = sd.askstring("Input", "key = ").strip()

            if not key:
                return

            value = None

            if vtype == ValueTypes.STR:
                value = sd.askstring("Input String Value", "value = ").strip()
            elif vtype == ValueTypes.DICT:
                value = {}
            elif vtype == ValueTypes.LIST:
                value = []
            elif vtype == ValueTypes.FILEPATH:
                value = fd.askopenfilename()

            if key and value is not None:
                self.add_node(key, value, parent)

        elif self.verify_selection(Tags.LIST):

            value = None

            if vtype == ValueTypes.STR:
                value = sd.askstring("Input String Value", "value = ")
            elif vtype == ValueTypes.DICT:
                value = {}
            elif vtype == ValueTypes.LIST:
                value = []
            elif vtype == ValueTypes.FILEPATH:
                value = fd.askopenfilename()

            if value is not None:
                self.add_node(len(self.tree.get_children(parent)), value, parent)

        else:
            # Leaf node in selection, change selection and call method again
            self.tree.selection_set(
                self.tree.parent(parent)
            )  # Changing selection to parent
            self.add_item_from_input(type)

    def edit_item(self, index, key=None, value=None):
        """
        Updates the existing item with the new key and value at index.
        :param index: Existing item index.
        :param key: A <str>, the new key.
        :param value: A <str>, the new value.
        :return: In case of absolute root this function does not do anything and returns empty.
        """
        if key:
            self.tree.item(index, text=key)

        if value:
            self.tree.item(index, values=[value])

    def edit_item_from_input(self):
        """
        Allows editing of key and value in case of a <dict> item and only value in case of <list> item.
        """
        selection = self.get_selected_index()

        is_parent_dict = self.tree.tag_has(Tags.DICT, self.tree.parent(selection))
        is_leaf = self.tree.tag_has(Tags.LEAF, selection)

        if is_parent_dict and mb.askyesno("Confirm?", "Edit key?"):
            key = sd.askstring("Key Input", "new key = ")

            self.edit_item(selection, key=key)

        if is_leaf and mb.askyesno("Confirm?", "Edit Value?"):
            value = sd.askstring("Value Input", "new value = ")
            if self.verify_value(value):
                self.edit_item(selection, value=value)

    def remove_item(self, index):
        """
        :param index: Removes the item at index and its children from the list.
        """
        self.tree.delete([index])

    def remove_item_from_input(self, index):
        """
        :param index: Removes the item at index and its children from the list.
        Does not remove a json root item, instead removes all its children.
        """

        json_root = self.get_json_root(index)

        if index == json_root:
            for item in self.tree.get_children(index):
                self.remove_item(item)
        else:
            self.remove_item(index)

    def remove_all_item(self):
        """
        :return: Removes all item from the tree.
        """
        # self.tree.delete([''])  # '' is the absolute root node # This is buggy in the treeview
        for child in self.tree.get_children():
            self.remove_item(child)

    def load_json_from_file(self, filepath):
        """
        :param filepath: An absolute filepath to the json file.
        :return: The <dict> object parsed from the json file.
        """
        try:
            data = playbook_utils.load(filepath)
            for key in data:
                self.add_node(key, data[key])
        except playbook_utils.PlaybookValidationError as e:
            raise e

        return data

    def save_json_file(self, filepath):
        """
        Gather steps and save to json file.
        :param filepath: path to save json to.
        """
        self.filepath = filepath

        data = {}
        for child in self.tree.get_children():
            data[self.get_key(child)] = self.tree_to_dict(child)

        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)

        print(f"Saved json to '{filepath}' successfully.")
        self.parent.update_filepath(filepath)

    def tree_to_dict(self, node):
        """
        Convert Treeview to python dict.
        :param node: a <tk.Treeview> node object.
        :return: The value object.
        """
        item = self.tree.item(node)
        d = None
        if self.tree.tag_has(Tags.DICT, node):
            d = {}
            child_nodes = self.tree.get_children(node)
            for child in child_nodes:
                d[self.get_key(child)] = self.tree_to_dict(child)
        elif self.tree.tag_has(Tags.LIST, node):
            d = []
            child_nodes = self.tree.get_children(node)
            for child in child_nodes:
                d.append(self.tree_to_dict(child))
        else:
            d = item["values"][0]
        return d

    def get_selected_index(self):
        """
        :return: Returns the currently selected/focused item from the list.
        """
        return self.tree.selection()

    def get_json_root(self, index):
        """
        This function traverses up until finding an item with Tags.ROOT and returns.
        :param index: An item index in the tree.
        :return: The corresponding json root index.
        """
        if index == "":
            return None
        if self.tree.tag_has(Tags.ROOT, index):
            return index
        return self.get_json_root(self.tree.parent(index))

    def get_key(self, index):
        """
        Extracts the tree from the node text.
        :param index: Node index.
        :return: The key <str> object.
        """
        return self.tree.item(index)["text"]

    def show_popup_menu(self, event):
        """
        Pops up menu for controller defined actions.
        :param event: The event where <Button-3> was clicked.
        """
        self.tree.selection_set(
            self.tree.identify_row(event.y)
        )  # Before popping up selecting the clicked item
        if self.get_selected_index():
            self.popup_menu.post(event.x_root, event.y_root)

    def update_popup_menu(self):
        """
        Updating the self.popup_menu object with actions defined in self.popup_menu_actions.
        """
        self.popup_menu.delete(0, tk.END)  # Delete old entries
        for key in self.popup_menu_actions:
            self.popup_menu.add_command(
                label=self.popup_menu_actions[key]["text"],
                command=self.popup_menu_actions[key]["action"],
            )

    def verify_selection(self, expected=Tags.LEAF):
        """
        Checks whether currently selected item has the expected tag.
        :param expected: The expected tag, default is Tags.LEAF
        :return: Boolean
        """
        selection = self.get_selected_index()
        if self.tree.tag_has(expected, selection):
            return True
        return False

    def verify_key(self, key):
        if len(key.encode("utf-8")):
            return True
        return False

    def verify_value(self, value):
        if len(value.encode("utf-8")):
            return True
        return False
