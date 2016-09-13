import string
import os
import time
import httplib
import gzip
from StringIO import StringIO
# if this fail, install libopenssl0.9.8:i386 (on ubuntu x64)
try:
    import _hashlib
except:
    import hashlib as _hashlib
import idaapi
import idautils
import idc
import atexit
import json
from string import lower
import threading

import logging

g_logger = logging.getLogger()
for h in g_logger.handlers:
    g_logger.removeHandler(h)

g_logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(threadName)s]: %(message)s',
        datefmt='%d/%m/%Y %I:%M')
handler.setFormatter(formatter)
g_logger.addHandler(handler)



settings_filename = "skelsettings.json"
skel_settings = None
skel_db = None
skel_conn = None

last_timestamp = 0
uihook = None
poli_id = 0
sample_id = 0
crit_backup_file = None
last_saved = 0
backup_file = None


class SkelConfig(object):
    """
        Config management
    """

    def __init__(self, settings_file):
        filename = os.path.dirname(__file__) + "/" + settings_file
        self.username = "Anonymous"
        self.edit_flag = False

        # Network config
        self.poli_server = ""
        self.poli_port = 80
        self.poli_remote_path = ""
        self.poli_apikey = ""
        self.debug_http = False
        self.online_at_startup = None
        self.poli_timeout = 5

        # Skelenox general config
        self.display_subs_info = False
        self.int_func_lines_count = 9
        self.save_timeout = 10 * 60

        # White background, edit to your color scheme preference
        self.auto_highlight = 1
        self.backgnd_highlight_color = 0xA0A0FF
        self.backgnd_std_color = 0xFFFFFF

        # dark background
        # self.backgnd_highlight_color = 0x333333
        # self.backgnd_std_color = 0x0

        if os.path.isfile(filename):
            g_logger.info("Loading settings file")
            self._do_init(filename)
        else:
            g_logger.warning("Config file not edited, populating default")
            self.populate_default(filename)
            self.not_edited(filename)

    def not_edited(self, filename):
        """
            The user have not edited the settings
        """
        idc.Warning("Please edit the %s file with your settings!" % (filename))
        raise EnvironmentError

    def _do_init(self, filename):
        """
            Loads the settings in JSON file
        """
        with open(filename, 'r') as inputfile:
            raw_data = inputfile.read()
            data = json.loads(raw_data, encoding='ascii')
            if data["edit_flag"] is False:
                self.not_edited(filename)
            else:
                for key in data.keys():
                    setattr(self, key, data[key])

    def populate_default(self, filename):
        """
            Dumps the default value in JSON in the given filename
        """
        data = json.dumps(vars(self), sort_keys=True, indent=4)
        with open(filename, 'w') as outfile:
            outfile.write(data)

    def dump_config(self):
        """
            Simply print the config on screen
        """
        values = {}
        for elem in vars(self).keys():
            values[elem] = vars(self)[elem]
        print json.dumps(values, sort_keys=True, indent=4)


class SkelConnection(object):
    """
        HTTP(S) API management
    """

    def __init__(self, poli_server="", poli_port=5000,
                 remote_path="", poli_apikey="", http_debug=False):
        self.http_debug = http_debug
        self.remote_path = remote_path
        self.api_key = poli_apikey
        self.poli_server = poli_server
        self.poli_port = poli_port

        self.h_conn = None
        self.is_online = False
        self.ctx = None

    def get_online(self):
        """
            Connect to the server
        """
        try:
            self.__do_init()
        except Exception as e:
            g_logger.exception("The polichombr server seems down")
            return False
        return True

    def __do_init(self):
        """
            Initiate connection handle
        """
        if self.http_debug is True:
            self.h_conn = httplib.HTTPConnection(
                self.poli_server, self.poli_port)
        else:
            self.ctx = ssl._create_unverified_context()
            self.h_conn = httplib.HTTPSConnection(
                self.poli_server, context=self.ctx)
        self.h_conn.connect()
        self.is_online = True

    def get_offline(self):
        """
            Wrapper to close connection
        """
        self.close_connection()

    def close_connection(self):
        """
            Cleanup the connection
        """
        g_logger.debug("Closing connection")
        if self.h_conn is not None:
            self.h_conn.close()
        self.is_online = False

    def poli_post(self, endpoint="/", data=None):
        """
            @arg : endpoint The API target endpoint
            @arg : data dictionary
            @return : dict issued from JSON
        """
        headers = {"Accept-encoding": "gzip, deflate",
                   "Content-type": "application/json",
                   "Connection": "keep-alive",
                   "Accept": "*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5",
                   "Connection": "Keep-Alive",
                   "X-API-Key": self.api_key
                   }
        method = "POST"
        json_data = json.dumps(data)
        self.h_conn.request(method, endpoint, json_data, headers)
        res = self.h_conn.getresponse()

        if res.status != 200:
            g_logger.error("The POST request didn't go as expected")
        contentType = res.getheader("Content-Encoding")
        if contentType == "gzip":
            buf = StringIO(res.read())
            res = gzip.GzipFile(fileobj=buf)
        data = res.read()
        try:
            result = json.loads(data)
        except:
            raise IOError
        return result

    def poli_get(self, endpoint="/", data=None):
        """
            @arg : endpoint The API target endpoint
            @arg : data dictionary
            @return : dict issued from JSON
        """
        headers = {"Accept-encoding": "gzip, deflate",
                   "Content-type": "application/json",
                   "Connection": "keep-alive",
                   "Accept": "*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.5",
                   "Connection": "Keep-Alive",
                   "X-API-Key": self.api_key
                   }
        method = "GET"
        json_data = json.dumps(data)
        self.h_conn.request(method, endpoint, json_data, headers)
        res = self.h_conn.getresponse()

        if res.status != 200:
            g_logger.error("The GET request didn't go as expected")
        contentType = res.getheader("Content-Encoding")
        if contentType == "gzip":
            buf = StringIO(res.read())
            res = gzip.GzipFile(fileobj=buf)
        data = res.read()
        try:
            result = json.loads(data)
        except:
            g_logger.exception("Coulnt parse the JSON data")
            print data
            raise IOError
        return result

    def push_comment(self, address=0, comment=None):
        if comment is None:
            return False
        global sample_id
        data = {"address": address,
                "comment": comment}
        endpoint = self.prepare_endpoint('comments')
        res = self.poli_post(endpoint, data)
        if res["result"]:
            g_logger.debug(("Comment %s sent for address 0x%x" % (comment, address)))
        else:
            g_logger.error("Cannot send comment %s ( 0x%x )" % (comment, address))
        return res["result"]

    def get_comments(self):
        endpoint = self.prepare_endpoint('comments')
        res = self.poli_get(endpoint)
        return res["comments"]

    def get_names(self):
        endpoint = self.prepare_endpoint('names')
        res = self.poli_get(endpoint)
        return res["names"]

    def push_name(self, address=0, name=None):
        if name is None:
            return False
        global sample_id
        data = {"address": address,
                "name": name}
        endpoint = self.prepare_endpoint('names')
        res = self.poli_post(endpoint, data)
        if res["result"]:
            g_logger.debug("sent name %s" % (name))
        else:
            g_logger.error("failed to send name %s" % (name))

    @staticmethod
    def prepare_endpoint(action):
        global sample_id
        return "/api/1.0/samples/" + str(sample_id) + "/" + action + "/"


def checkupdates():
    global skel_conn
    if skel_conn.is_online is False:
        return False
    if sync_names() == -1:
        return False
    return 0


def push_change(cmd, param1, param2):
    """
        XXX : todo
    """
    global skel_conn, sample_id
    g_logger.debug("[+] " + cmd + " => " + param1 + " :: " + param2 + " -- SENT")
    return True


def push_functions_names():
    """
        update les noms de fonctions depuis l'idb actuel
    """
    global sample_id

    for addr in idautils.Functions(idc.MinEA(), idc.MaxEA()):
        fname = GetFunctionName(addr)
        if fname != "" and not hasSubNoppedPrefix(fname):
            if skel_conn.push_name(addr, fname) == -1:
                return False
    return True


def startup():
    """
        Ask for initial synchro
    """
    overwrite = idaapi.askbuttons_c("YES", "NO", "NO",
                                    0,
                                    "Names synchro: do you want to keep your actual subs names?\nYES: keep your actual names (and push them to the server)\nNO: overwrite the actual names with the server's ones")
    if overwrite == 1:
        if not push_functions_names():
            return False
    else:
        return sync_names(True)


def execute_comment(comment):
    """
        XXX : switch on the comment type
    """
    idc.MakeRptCmt(
        comment["address"],
        comment["data"].encode(
            'ascii',
            'replace'))
    g_logger.debug("[x] Added comment %s @0x%x " % (comment["data"], comment["address"]))


def execute_rename(name):
        if "sub_" in idc.GetTrueName(name["address"]):
            g_logger.debug("[x] renaming %s @ 0x%x as %s" % (idc.GetTrueName(name["address"]), name["address"], name["data"]))
            idc.MakeName(
                name["address"],
                name["data"].encode(
                    'ascii',
                    'ignore'))


def sync_names(full_synchro=False):
    global sample_id, skel_conn, last_timestamp

    if not skel_conn.is_online:
        g_logger.error("[!] Error, cannot sync while offline")
        return False

    comments = skel_conn.get_comments()
    for comment in comments:
        execute_comment(comment)

    names = skel_conn.get_names()
    for name in names:
        execute_rename(name)

    g_logger.info("[+] IDB synchronized")
    return True


def get_online(*args):
    global backup_file, sample_id, skel_conn

    if skel_conn.is_online:
        return False

    skel_conn.get_online()

    SaveBase(backup_file, idaapi.DBFL_TEMP)

    # test si le sample courant existe sur poli et si non, on le cree :]
    if poli_id == 0:
        data = skel_conn.poli_get(
            "/api/1.0/samples/" +
            lower(
                GetInputMD5()) +
            "/")
        if data["sample_id"] is not None:
            sample_id = data["sample_id"]
        else:
            g_logger.error("Cannot find remote sample")
            # XXX upload sample!
            skel_conn.get_offline()
            return True
    g_logger.info("[+] First synchronization finished")
    return True


def end_skelenox():
    """
        cleanup
    """
    global sample_id, skel_conn
    skel_conn.close_connection()
    cleanup_hooks()
    g_logger.info("Skelenox terminated")
    sample_id = 0
    return

def end_notify_callback(nw_arg):
    g_logger.debug("Being notified of exiting DB")
    end_skelenox()

idaapi.notify_when(idaapi.NW_CLOSEIDB|idaapi.NW_TERMIDA,
                   end_notify_callback)


def init_skelenox():
    global crit_backup_file, backup_file, last_saved
    global last_timestamp
    global sample_id
    global uihook
    global is_updating
    global skel_conn
    global skel_settings, settings_filename

    is_updating = 0

    last_timestamp = -1
    sample_id = 0
    last_saved = 0

    g_logger.info("[+] Init Skelenox")

    # Load settings
    skel_settings = SkelConfig(settings_filename)

    skel_conn = SkelConnection(skel_settings.poli_server,
                               skel_settings.poli_port,
                               skel_settings.poli_remote_path,
                               skel_settings.poli_apikey,
                               skel_settings.debug_http)

    cleanup_hooks()

    # If having 3 idbs in your current path bother you, change this
    crit_backup_file = GetIdbPath()[:-4] + "_backup_preskel_.idb"
    backup_file = GetIdbPath()[:-4] + "_backup_.idb"

    atexit.register(end_skelenox)
    g_logger.info("Backuping IDB before any intervention (_backup_preskel_)")
    SaveBase(crit_backup_file, idaapi.DBFL_TEMP)
    g_logger.info("Creating regular backup file IDB (_backup_)")
    SaveBase(backup_file, idaapi.DBFL_TEMP)
    last_saved = time.time()

    skel_settings.online_at_startup = True

    if not get_online():
            g_logger.error("Cannot get online =(")
            return False

    # Synchronize the sample
    if not startup():
        return

    # setup hooks

    uihook = MyUiHook()
    uihook.hook()

    g_logger.info("Skelenox init finished")
    _help()
    return


def shex(a):
    """
        custom, pour supprimer les L finaux, au cas ou
    """
    return hex(a).rstrip("L")


def CheckDefaultValue(name):
    default_values = ['sub_', "dword_", "unk_", "byte_", "word_", "loc_"]
    for value in default_values:
        if value in name[:6]:
            return True
    return False


def hasSubNoppedPrefix(name):
    if name is not None:
        # IDA prefix
        default_values = ['sub_', '?', 'nullsub', 'unknown']
        for val in default_values:
            if val in name[:7]:
                return True
        if name[:1] != "?" and name[0] != "_" and name[0] != "@":
                return False
    return True


def push_comms():
    global skel_conn
    commBL = [
        "size_t", "int", "LPSTR", "char", "char *", "lpString", "unsigned int", "void *",
        "indirect table for switch statement", "this", "jump table for switch statement", "switch jump"]
    for i in range(idc.MinEA(), idc.MaxEA()):
        if idc.GetCommentEx(
                i, 0) is not None and not idc.GetCommentEx(i, 0) in commBL:
            if not skel_conn.push_comment(i, idc.GetCommentEx(i, 0)):
                return -1
        elif idc.GetCommentEx(i, 1) is not None and not idc.GetCommentEx(i, 1) in commBL:
            if not skel_conn.push_comment(i, idc.GetCommentEx(i, 1)):
                return -1
    for function_ea in idautils.Functions(idc.MinEA(), idc.MaxEA()):
        fName = idc.GetFunctionName(function_ea)
        if hasSubNoppedPrefix(fName) is False:
            if not skel_conn.push_name(function_ea, fName):
                g_logger.error("Error sending function name %s" % (fName) )
        # if idc.GetFunctionCmt(function_ea,0) != "":
        #    push_change("idc.SetFunctionCmt",shex(function_ea),idc.GetFunctionCmt(i,0))
        # elif idc.GetFunctionCmt(function_ea,1) != "":
        #    push_change("idc.SetFunctionCmt",shex(function_ea),idc.GetFunctionCmt(function_ea,1))
    return


class MyUiHook(idaapi.UI_Hooks):
    """
        Catch IDA actions and send them
    """
    cmdname = ""
    addr = 0

    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def preprocess(self, name):
        #checkupdates()  # XXX : enable it after correct timestamp management
        self.cmdname = name
        self.addr = idc.here()
        return 0

    def term(self):
        end_skelenox()

    def postprocess(self):
        global skel_conn
        try:
            if self.cmdname == "MakeComment":
                if idc.GetCommentEx(self.addr, 0) is not None:
                    skel_conn.push_comment(
                        self.addr, idc.GetCommentEx(
                            (self.addr), 0))
                elif idc.GetCommentEx(self.addr, 1) is not None:
                    skel_conn.push_comment(
                        self.addr, idc.GetCommentEx(
                            (self.addr), 1))
                elif idc.GetFunctionCmt(self.addr, 0) != "":
                    skel_conn.push_comment(
                        self.addr, idc.GetCommentEx(
                            (self.addr), 0))
                elif idc.GetFunctionCmt(self.addr, 1) != "":
                    skel_conn.push_comment(self.addr, idc.GetFunctionCmt(
                        self.addr, 1).replace("\n", "\\n").replace("\"", "\\\""))
            if self.cmdname == "MakeRptCmt":
                if idc.GetCommentEx(self.addr, 0) is not None:
                    skel_conn.push_comment(self.addr, idc.GetCommentEx(
                        self.addr, 0).replace("\n", "\\n").replace("\"", "\\\""))
                elif idc.GetCommentEx(self.addr, 1) is not None:
                    skel_conn.push_comment(self.addr, idc.GetCommentEx(
                        self.addr, 1).replace("\n", "\\n").replace("\"", "\\\""))
                elif idc.GetFunctionCmt(self.addr, 0) != "":
                    skel_conn.push_comment(self.addr, idc.GetFunctionCmt(
                        self.addr, 0).replace("\n", "\\n").replace("\"", "\\\""))
                elif idc.GetFunctionCmt(self.addr, 1) != "":
                    skel_conn.push_comment(self.addr, idc.GetFunctionCmt(
                        self.addr, 1).replace("\n", "\\n").replace("\"", "\\\""))
            elif self.cmdname == "MakeName":
                # idc.Jump(self.addr)
                if (idc.GetFunctionAttr(self.addr, 0) == self.addr):
                    fname = GetFunctionName(self.addr)
                    if fname != "":
                        if not CheckDefaultValue(fname):
                            skel_conn.push_name(self.addr, fname)
                else:
                    fname = idc.GetTrueName(self.addr)
                    if fname != "" and not CheckDefaultValue(fname):
                        skel_conn.push_name(self.addr, fname.replace(
                            "\n", "\\n").replace("\"", "\\\""))
                    else:
                        # ok, on regarde ce qui est pointe
                        if GetOpType(self.addr, 0) in [o_near, o_imm, o_mem]:
                            if GetOpType(self.addr, 1) in [
                                    o_near, o_imm, o_mem]:
                                print "[P] You must be on the top of function or at the global address to set the name in log file"
                            else:
                                add = idc.GetOperandValue(self.addr, 0)
                                fname = idc.GetTrueName(add)
                                if fname != "" and not CheckDefaultValue(
                                        fname):
                                    skel_conn.push_name(add, fname.replace(
                                        "\n", "\\n").replace("\"", "\\\""))
                                else:
                                    print "[P] You must be on the top of function or at the global address to set the name in log file"
                        elif GetOpType(self.addr, 1) in [o_near, o_imm, o_mem]:
                            add = idc.GetOperandValue(self.addr, 1)
                            fname = idc.GetTrueName(add)
                            if fname != "" and not CheckDefaultValue(fname):
                                skel_conn.push_name(add, fname.replace(
                                    "\n", "\\n").replace("\"", "\\\""))
                            else:
                                print "[P] You must be on the top of function or at the global address to set the name in log file"

            elif self.cmdname == "MakeFunction":
                if idc.GetFunctionAttr(self.addr, 0) is not None:
                    pass
                    #push_change("idc.MakeFunction", shex(idc.GetFunctionAttr(
                    #    self.addr, 0)), shex(idc.GetFunctionAttr(self.addr, 4)))
            elif self.cmdname == "DeclareStructVar":
                print "Fixme : declare Struct variable"
            elif self.cmdname == "AddStruct":
                print "Fixme : adding structure"
            elif self.cmdname == "SetType":
                newtype = idc.GetType(self.addr)
                if newtype is None:
                    newtype = ""
                else:
                    newtype = prepare_parse_type(newtype, self.addr)
                push_change("idc.SetType", shex(self.addr), newtype)
            elif self.cmdname == "OpStructOffset":
                print "Fixme, used when typing a struct member/stack var/data pointer to a struct offset "
        except KeyError:
            pass
        return 0


def prepare_parse_type(typestr, ea):
    """
        idc.ParseType doesnt accept types without func / local name
        as exported by default GetType
        this is an ugly hack to fix it
        FIXME : parsing usercall (@<XXX>)
    """
    lname = idc.GetTrueName(ea)
    if lname is None:
        lname = "Default"

    # func pointers
    fpconventions = ["__cdecl *",
                     "__stdcall *",
                     "__fastcall *",
                     #"__usercall *",
                     #"__userpurge *",
                     "__thiscall *"]

    cconventions = ["__cdecl",
                    "__stdcall",
                    "__fastcall",
                    #"__usercall",
                    #"__userpurge",
                    "__thiscall"]

    flag = False
    for conv in fpconventions:
        if conv in typestr:
            mtype = typestr.replace(conv, conv + lname)
            flag = True

    if not flag:
        # replace prototype
        for conv in cconventions:
            if conv in typestr:
                mtype = typestr.replace(conv, conv + " " + lname)
                flag = True
    return mtype


class SkelIDPHooks(idaapi.IDP_Hooks):
    """
        Hook IDP that saves the database regularly
    """
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def custom_out(self):
        global last_saved, backup_file, skel_settings
        if last_saved < (time.time() - skel_settings.save_timeout):
            print "[+] Saving IDB"
            SaveBase(backup_file, idaapi.DBFL_TEMP)
            last_saved = time.time()
        return idaapi.IDP_Hooks.custom_out(self)

    def rename(self, *args):
        return super(self, IDP_Hook).rename()


def cleanup_hooks():
    """Clean IDA hooks on exit"""
    global uihook
    if "uihook" in globals() and uihook is not None:
        uihook.unhook()
        uihook = None
    return


def _help():
    """
        help!
    """
    print "-------------------------------------------------------------------"
    print "  SKELENOX "
    print "-------------------------------------------------------------------"
    print "Help:"
    print "see online ;-)"
    print "-------------------------------------------------------------------"
    print "\tfile %IDB%_backup_preskel_ contains pre-critical ops IDB backup"
    print "\tfile %IDB%_backup_ contains periodic IDB backups"
    return

if __name__ == '__main__':
    # RUN !
    init_skelenox()
