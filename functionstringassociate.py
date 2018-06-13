from idc import *
from idautils import *
from idaapi import *

print "\nStringsFunctionAssociate v0.02 by partoftheworlD!\n"

class StringException(Exception):
    pass

class Strings_fc:
    def __init__(self):
        self.string_counter = 0
        pass

    string_types = ["C",
                    "Pascal",
                    "LEN2",
                    "Unicode",
                    "LEN4",
                    "ULEN2",
                    "ULEN4"]

    def get_string_type(self, addr):
        type_s = GetStringType(addr)
        if type_s >= len(self.string_types) or type_s < 0:
            raise StringException()
        return str(GetString(addr, -1, type_s))

    def set_comments(self, xref, comment):
        try:
            set_func_cmt(xref, "", 0)
            set_func_cmt(xref, "", 1)
            set_func_cmt(xref, comment, 1)
        except TypeError:
            print "[EA Error EA = %s ] Please reload plugin via File/Script File", xref

    def get_strings_per_function(self, start_func):
        strings = []
        end_func = FindFuncEnd(start_func)
        func_name = get_func_name(start_func)
        for inst_list in Heads(start_func, end_func):
            xrefs = DataRefsFrom(inst_list)
            for xref in xrefs:
                try:
                    strings.append(self.get_string_type(xref))
                    self.string_counter += 1
                except StringException:
                    continue
        yield func_name, strings

    def main(self):
        try:
            print "[+]Launching..."
            for i in Functions():
                for info_gen in self.get_strings_per_function(i):
                    if info_gen[1]:
                        self.set_comments(get_func(i), '"' + '", "'.join(string for string in info_gen[1]) + '"')
            print "[+]Well done! Added {} strings in {} functions".format(self.string_counter, get_func_qty())
        except KeyboardInterrupt:
            print "[+]Ended by user"

class StringsHandler(action_handler_t):
    def __init__(self):
        action_handler_t.__init__(self)

    def activate(self, ctx):
        sfc = Strings_fc()
        sfc.main()

    def update(self, ctx):
        return AST_ENABLE_ALWAYS

class Strings_window(plugin_t):
    flags = PLUGIN_FIX
    comment = 'Associate functions'
    help = 'https://github.com/partoftheworlD/IDA7py_FunctionStringAssociate/'
    wanted_name = 'StringsFunctionAssociate'
    wanted_hotkey = ""

    def init(self):
        try:
            self._install_plugin()
        except Exception as e:
            form = get_current_tform()
            pass
        return PLUGIN_KEEP

    def _install_plugin(self):
        self.init()

    def term(self):
        pass

    def run(self, arg = 0):
        a = StringsHandler()
        a.activate(self)

def PLUGIN_ENTRY():
    return Strings_window()
