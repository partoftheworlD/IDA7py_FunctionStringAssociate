import idc
import idautils
import idaapi

print "\nStringsFunctionAssociate v0.04 by partoftheworlD! Last Changes <2018-06-14 20:22:12.551000>\n"

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
        type_s = idc.GetStringType(addr)
        if type_s >= len(self.string_types) or type_s < 0:
            raise StringException()
        return str(idc.GetString(addr, -1, type_s))          

    def get_strings_per_function(self, start_func):
        strings = []
        fs = ''

        func_obj = idaapi.get_func(start_func)    
        idaapi.set_func_cmt(func_obj, None, 1)
        idaapi.set_func_cmt(func_obj, None, 0)  

        end_func = idc.FindFuncEnd(start_func)
        for inst_list in idautils.Heads(start_func, end_func):
            xrefs = idautils.DataRefsFrom(inst_list)
            for xref_addr in xrefs:
                try:
                    string = self.get_string_type(xref_addr)
                    if len(string) > 2:
                        strings.append(string)
                        self.string_counter += 1
                    else:
                        pass
                except StringException:
                    continue

        for c in strings:
            fs += '"' + c + '" '
            idaapi.set_func_cmt(func_obj, 'STR# {}'.format(fs), 1)

    def main(self):
        try:
            print "\n[+]Launching..."
            for i in idautils.Functions():
                self.get_strings_per_function(i)
            print "\n[+]Well done! Added {} strings in {} functions".format(self.string_counter, idaapi.get_func_qty())
        except KeyboardInterrupt:
            print "\n[+]Ended by user"


class StringsHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        sfc = Strings_fc()
        sfc.main()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class Strings_window(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = 'Associate functions'
    help = 'https://github.com/partoftheworlD/IDA7py_FunctionStringAssociate/'
    wanted_name = 'Strings Function Associate'
    wanted_hotkey = ""

    def init(self):
        try:
            self._install_plugin()
        except Exception as e:
            form = idaapi.get_current_tform()
            pass
        return idaapi.PLUGIN_KEEP

    def _install_plugin(self):
        self.init()

    def term(self):
        pass

    def run(self, arg=0):
        a = StringsHandler()
        a.activate(self)


def PLUGIN_ENTRY():
    return Strings_window()
