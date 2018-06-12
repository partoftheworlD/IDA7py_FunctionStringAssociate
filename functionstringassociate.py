from idc import *
from idautils import *
from ida_funcs import *


class StringException(Exception):
    pass

class Strings:
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

    @staticmethod
    def set_comments(xref, comment):
        set_func_cmt(xref, "", 0)
        set_func_cmt(xref, "", 1)
        set_func_cmt(xref, comment, 1)

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


if __name__ == '__main__':
    const_var = 60
    try:
        print "=" * const_var
        print "Launching..."
        print "=" * const_var
        strings = Strings()
        for functions in Functions():
            for info_gen in strings.get_strings_per_function(functions):
                if info_gen[1]:
                    #print j[0], ' , '.join(strz for strz in j[1]) Debug
                    strings.set_comments(get_func(functions), '"' + '", "'.join(string for string in info_gen[1]) + '"')
        print "="*const_var
        print "Well done! Added {} strings in {} functions".format(strings.string_counter, get_func_qty())
        print "="*const_var
    except KeyboardInterrupt:
        print "="*const_var
        print "Ended by user"
        print "="*const_var
