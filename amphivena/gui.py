import tkinter as tk
from functools import partial


class MainApplication(tk.Tk):
    """ Main Container """

    def __init__(self, menu_contents):
        tk.Tk.__init__(self)

        self.geometry("400x200")
        self.option_add('*tearOff', False)

        self.config(menu=MenuBar(self, menu_contents))


class MenuBar(tk.Menu):
    """ Top navigation menu, dynamically created from menu_contents dictionary """
    def __init__(self, parent, menu_contents):
        tk.Menu.__init__(self, parent)
        self.build_menu(self, menu_contents)

    def build_menu(self, menu_parent, menu_contents):
        """
        Constructs tkinter menu from menu_contents
        Lowest layer should be a list(able) object, [0] element will be presented as menu option

        :param menu_parent: menu element for menu_contents to be attached under
        :param menu_contents: nested dictionary structure
        :return: None
        """
        if type(menu_contents) == dict:
            for key in menu_contents.keys():
                sub_menu = tk.Menu()
                menu_parent.add_cascade(label=str(key), menu=sub_menu)
                self.build_menu(sub_menu, menu_contents[key])

        elif type(menu_contents) == list:
            for item in menu_contents:
                if type(item) == str:
                    menu_parent.add_command(label=item, command=partial(self.select_element(item)))
                elif type(item) == tuple:
                    menu_parent.add_command(label=item[0], command=partial(self.select_element(item)))

    # noinspection PyMethodMayBeStatic
    def select_element(self, element):
        """ Partial method for returning menu full element details

        :param element: a list, first element is the presented name
        :return: element
        """

        def layer_details():
            #TODO process element/tie in with rest of application
            print(element)

        return layer_details


if __name__ == "__main__":
    MainApplication().mainloop()
