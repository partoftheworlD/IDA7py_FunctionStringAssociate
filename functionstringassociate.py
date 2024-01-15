import idc
import idautils
import idaapi
import ida_bytes

print("\nStringsFunctionAssociate v0.09 by partoftheworlD! Last Changes <2024-01-15 19:50:02.814613>\n")

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
        try:
            type_s = idc.get_str_type(addr)
            return str(ida_bytes.get_strlit_contents(addr, -1, type_s))
        except TypeError:
            raise StringException()        
    
    def clear_comments(self, func_obj):
        idaapi.set_func_cmt(func_obj, '', 1)
        idaapi.set_func_cmt(func_obj, '', 0)

    def save_existing_comments(self, start_func):
        bc = []
        comment = idaapi.get_func_cmt(start_func, 1)
        if comment:
            bc.append(comment)
        comment = idaapi.get_func_cmt(start_func, 0)
        if comment:
            bc.append(comment)
        if len(bc) > 1:
            return bc
        else:
            return None

    def get_strings_per_function(self, start_func):
        strings = []
        fs = ''
        func_obj = idaapi.get_func(start_func)  
        if func_obj:
            bc = self.save_existing_comments(start_func)
            if bc is not None:
                for string in [saved_comment for saved_comment in bc]:
                    strings.append(string)
            self.clear_comments(func_obj)
            for inst_list in idautils.Heads(start_func, idc.find_func_end(start_func)):
                try:
                    for string in [self.get_string_type(xref_addr) for xref_addr in idautils.DataRefsFrom(inst_list)]:
                        if len(string) > 2:
                            strings.append(string[2:-1])
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
            

    def main(self):
        print("\n[+]Launching...")
        try:            
            for i in idautils.Functions():
                self.get_strings_per_function(i)
            print("\n[+]Well done! Added {} strings in {} functions".format(self.string_counter, idaapi.get_func_qty()))
        except KeyboardInterrupt:
            print("\n[+]Ended by user")


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
        except Exception:
            form = idaapi.get_current_widget()
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
