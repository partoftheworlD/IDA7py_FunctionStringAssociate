import idc
import idautils
import idaapi

print "\nStringsFunctionAssociate v0.06 by partoftheworlD! Last Changes <2018-08-06 02:45:56.132000>\n"

class StringException(Exception):
    pass


class Strings_fc:
    def __init__(self):
        self.string_counter = 0

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
    
    def clear_comments(self, start_func, func_obj):
        idaapi.set_func_cmt(func_obj, '', 1)
        idaapi.set_func_cmt(func_obj, '', 0)
        

    def get_strings_per_function(self, start_func):
        strings = []
        fs = ''
        func_obj = idaapi.get_func(start_func)  
        if func_obj:
            self.clear_comments(start_func, func_obj)
            for inst_list in idautils.Heads(start_func, idc.FindFuncEnd(start_func)):
                try:
                    for string in [self.get_string_type(xref_addr) for xref_addr in idautils.DataRefsFrom(inst_list)]:
                        if len(string) > 2:
                            strings.append(string)
                            self.string_counter += 1
                        else:
                            pass
                except StringException:
                    continue
    
            if strings:
                for c in strings:
                    if '\n' in c:
                        c = c.replace('\n', '')
                    fs += '"' + c + '" '
                idaapi.set_func_cmt(func_obj, 'STR {}# {}'.format(len(strings), fs), 1)
            
        else:
            print("func_obj return 0")
            pass
            

    def main(self):
        print "\n[+]Launching..."
        try:            
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
        str_Handle = StringsHandler()
        str_Handle.activate(self)


def PLUGIN_ENTRY():
    return Strings_window()
