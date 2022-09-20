########################################################################################
## 
## IDA plugin for annotating your IDB with imported strings
##
## To install:
##      Copy script into plugins directory, i.e: C:\Program Files\<ida version>\plugins
##
## Strings File:
##      The plugin requires a JSON file that contains a list of strings and their
##      respective offests using the following format.
##
##      "strings":[{"offset":<string_offset>,"value":<ascii_string>},...]
##
##
## To run:
##      Edit->Plugins->StrAnnotate
##      Use the dialogue box to select your strings JSON file and start annotating!
##
########################################################################################

import idaapi
import idautils
import ida_bytes
import idc
import ida_kernwin
import json
import string
import ida_loader

__AUTHOR__ = '@herrcore'

PLUGIN_NAME = "StrAnnotate"
PLUGIN_HOTKEY = ""
VERSION = '1.0.0'

p_initialized = False


def set_hexrays_comment(address, text):
    '''
    set comment in decompiled code
    '''
    try:
        cfunc = idaapi.decompile(address)
        tl = idaapi.treeloc_t()
        tl.ea = address
        tl.itp = idaapi.ITP_SEMI
        if cfunc is not None:
            cfunc.set_user_cmt(tl, text)
            cfunc.save_user_cmts() 
    except:
        print(f"Unable to comment pseudocode at {hex(address)}")


def set_comment(address, text):
    ## Set in dissassembly
    idc.set_cmt(address, text,0)
    ## Set in decompiled data
    set_hexrays_comment(address, text)


#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class StrAnnotate_Plugin_t(idaapi.plugin_t):
    comment = "StrAnnotate plugin for IDA"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    flags = idaapi.PLUGIN_KEEP


    def init(self):
        global p_initialized

        # register popup menu handlers
        try:
            Searcher.register(self, "StrAnnotate")
        except:
            pass

        if p_initialized is False:
            p_initialized = True
            idaapi.register_action(idaapi.action_desc_t(
                "StrAnnotate",
                "Import strings!",
                self.annotate,
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Edit/StrAnnotate", "StrAnnotate", idaapi.SETMENU_APP)
            ## Print a nice header
            print("=" * 80)
            print("\nStrAnnotate v{0}".format(VERSION))
            print("\n")
            print("* Use this plugin to annotate your IDB with an externally generated strings table *")
            print("\n")
            print("=" * 80)

        return idaapi.PLUGIN_KEEP


    def term(self):
        pass


    def annotate(serlf, strings_file):
        # Opening JSON file
        file_data = None
        with open(strings_file,'r') as fp:
            file_data = fp.read()
        if file_data is None:
            print(f"Error reading file {strings_file}")
            return

        # Parse JSON
        try:
            json_data = json.loads(file_data)
        except:
            print(f"Error parsing file {strings_file}, invalid json format.")
            return

        # Get strings list
        strings_list = json_data.get("strings",None)
        if strings_list is None:
            print(f"Error parsing file {strings_file}, json has no key 'strings'.")
            return

        # Iterate through strings list 
        for string_entry in strings_list:
            # Validate entry
            string_offset = string_entry.get("offset",None)
            if string_offset is None:
                print(f"Invalid string entry {string_entry}, expected format \{'offset':<string_offset>,'value':<ascii_string>\}")
                return
            string_value = string_entry.get("value",None)
            if string_value is None:
                print(f"Invalid string entry {string_entry}, expected format \{'offset':<string_offset>,'value':<ascii_string>\}")
                return
            # Convert offset into ea
            string_address = ida_loader.get_fileregion_ea(string_offset)

            # Lol how to tell if x64 or x32
            if string_address == 0xffffffff or string_address == 0xffffffffffffffff:
                print(f"Invalid string offset {string_entry}, not in range of binary.")
                return

            # If the string is misaligned get the nearest head
            string_address_head = idaapi.get_item_head(string_address)

            # Print the string
            print(f"{hex(string_address_head)} : {string_value}")

            # Add string comment
            set_comment(string_address_head, string_value)


    def run(self, arg):
        strings_file = ida_kernwin.ask_file(0, "*.json", 'Choose string file (json format)...')
        if strings_file == None:
            print("ERROR: You must choose a strings file to annotate with")
        else:
            self.annotate(strings_file)


# register IDA plugin
def PLUGIN_ENTRY():
    return StrAnnotate_Plugin_t()
