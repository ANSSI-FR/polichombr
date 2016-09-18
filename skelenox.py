"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2016
"""

import os
import time
import httplib
import gzip
import atexit
import json
import threading
import logging

from StringIO import StringIO
from string import lower

import idaapi
import idautils
import idc

g_logger = logging.getLogger()
for h in g_logger.handlers:
    g_logger.removeHandler(h)

g_logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
format_str = '[%(asctime)s] [%(levelname)s] [%(threadName)s]: %(message)s'
formatter = logging.Formatter(format_str, datefmt='%d/%m/%Y %I:%M')
handler.setFormatter(formatter)
g_logger.addHandler(handler)

try:
    import ssl
except:
    g_logger.exception("Cannot load ssl lib, please install libopenssl-0.9.8:i386")


settings_filename = "skelsettings.json"
skel_settings = None
skel_db = None
skel_conn = None
skel_hooks = None

last_timestamp = 0
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
        self.save_timeout = 10 * 60

        # White background, edit to your color scheme preference
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

    @staticmethod
    def not_edited(filename):
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
        except Exception:
            g_logger.exception("The polichombr server seems down")
            return False
        return True

    def __do_init(self):
        """
            Initiate connection handle
        """
        if self.http_debug is True:
            g_logger.info("Connecting using simple HTTP")
        else:
            g_logger.error("HTTPS is not managed at the moment...")

        self.h_conn = httplib.HTTPConnection(self.poli_server, self.poli_port)
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
        data = {"address": address,
                "name": name}
        endpoint = self.prepare_endpoint('names')
        res = self.poli_post(endpoint, data)
        if res["result"]:
            g_logger.debug("sent name %s at 0x%x" % (name, address))
        else:
            g_logger.error("failed to send name %s" % (name))
        return True

    @staticmethod
    def prepare_endpoint(action):
        global sample_id
        return "/api/1.0/samples/" + str(sample_id) + "/" + action + "/"


def checkupdates():
    global skel_conn
    if skel_conn.is_online is False:
        return False
    if sync_names() is False:
        return False
    return 0


class SkelUpdateAgent(threading.Thread):
    """
        This thread agent wait for messages on a queue.
        On each message, it polls the server for getting
        new updates. If new updates are detected, they are passed
        to the execution agent wich will handle them
    """
    last_timestamp = 0

    def __init__(self, args=(), kwargs=None):
        threading.Thread.__init__(self, name="SkelUpdateAgent",
                                  target=self.worker,
                                  args=args, kwargs=kwargs)

    def worker(self):
        try:
            sync_queue = kwargs["hUpdateSyncQueue"]

        except Exception as e:
            g_logger.error("Could'nt get the sync queues")
            g_logger.exception(e)
        while True:
            ret = sync_queue.get(timeout=0.5) # block 0.5 secs if nothing available
            if 'quit' in ret:
                break
            #names = SkelConn.get_names(XXX)
            #comments = SkelConn.get_comments()
            #structs = SkelConn.get_structs()
            #schedule_names_updates(names)

def push_change(cmd, param1, param2):
    """
        XXX : todo
    """
    global sample_id
    g_logger.warning("Push change is unimplemented...")
    #g_logger.debug("[+] " + cmd + " => " + param1 + " :: " + param2 + " -- SENT")
    return True


def push_functions_names():
    """
        We push all the function names from the current IDB
    """
    global skel_conn

    for addr in idautils.Functions(idc.MinEA(), idc.MaxEA()):
        fname = GetFunctionName(addr)
        if fname != "" and not hasSubNoppedPrefix(fname):
            if not skel_conn.push_name(addr, fname):
                return False
    return True


def startup():
    """
        Push the defined names,
        and pull the remote ones
    """
    push_functions_names()
    return sync_names()


def execute_comment(comment):
    """
        XXX : switch on the comment type
    """
    idc.MakeRptCmt(
        comment["address"],
        comment["data"].encode(
            'ascii',
            'replace'))
    g_logger.debug("[x] Added comment %s @ 0x%x " % (comment["data"], comment["address"]))


def execute_rename(name):
    """
        Wrapper for renaming only default names
    """
    if "sub_" in idc.GetTrueName(name["address"])[:4]:
        g_logger.debug("[x] renaming %s @ 0x%x as %s" % (idc.GetTrueName(name["address"]), name["address"], name["data"]))
        idc.MakeName(name["address"], name["data"].encode('ascii', 'ignore'))


def sync_names():
    """
        Get the remote comments and names
    """
    global skel_conn

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
    global sample_id, skel_conn, skel_hooks
    skel_conn.close_connection()
    skel_hooks.cleanup_hooks()
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
    global is_updating
    global skel_conn
    global skel_settings, settings_filename
    global skel_hooks

    is_updating = 0

    last_timestamp = -1
    sample_id = 0
    last_saved = 0

    SkelUtils.header()

    g_logger.info("[+] Init Skelenox")

    # Load settings
    skel_settings = SkelConfig(settings_filename)

    skel_conn = SkelConnection(skel_settings.poli_server,
                               skel_settings.poli_port,
                               skel_settings.poli_remote_path,
                               skel_settings.poli_apikey,
                               skel_settings.debug_http)

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
    skel_hooks = SkelHooks()
    skel_hooks.hook()

    g_logger.info("Skelenox init finished")
    return


def push_comms():
    global skel_conn
    commBL = [
        "size_t", "int", "LPSTR", "char", "char *", "lpString", "unsigned int", "void *",
        "indirect table for switch statement", "this", "jump table for switch statement", "switch jump"]
    for i in range(idc.MinEA(), idc.MaxEA()):
        if idc.GetCommentEx(
                i, 0) is not None and not idc.GetCommentEx(i, 0) in commBL:
            if not skel_conn.push_comment(i, idc.GetCommentEx(i, 0)):
                return False
        elif idc.GetCommentEx(i, 1) is not None and not idc.GetCommentEx(i, 1) in commBL:
            if not skel_conn.push_comment(i, idc.GetCommentEx(i, 1)):
                return False
    for function_ea in idautils.Functions(idc.MinEA(), idc.MaxEA()):
        fName = idc.GetFunctionName(function_ea)
        if hasSubNoppedPrefix(fName) is False:
            if not skel_conn.push_name(function_ea, fName):
                g_logger.error("Error sending function name %s" % (fName) )
        # if idc.GetFunctionCmt(function_ea,0) != "":
        #    push_change("idc.SetFunctionCmt",shex(function_ea),idc.GetFunctionCmt(i,0))
        # elif idc.GetFunctionCmt(function_ea,1) != "":
        #    push_change("idc.SetFunctionCmt",shex(function_ea),idc.GetFunctionCmt(function_ea,1))
    return True
class SkelHooks(object):
    """
        Class containing the three different hooks for skelenox

        SkelUIHook :
            * Original UI hook, catch cmds.
            Drawbacks : doesn't catch the actions made by scripts

        SkelIDBHook:
            * Catches the main actions
            Drawbacks:
                - type info management
                - doesn't catch naming actions
        SkelIDPHook:
            * IDPHook used for the actions not implemented in IDBHooks

    """
    ui_hook = None
    idb_hook = None
    idp_hook = None

    class SkelUIHook(idaapi.UI_Hooks):
        """
            Catch IDA UI actions and send them
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
                if "MakeComment" in self.cmdname:
                    if idc.Comment(self.addr) is not None:
                        skel_conn.push_comment(
                            self.addr, idc.Comment(self.addr))
                    if idc.GetFunctionCmt(self.addr, 0) != "":
                        skel_conn.push_comment(
                            self.addr, idc.GetFunctionCmt(
                                (self.addr), 0))
                elif "MakeRptCmt" in self.cmdname:
                    if idc.GetCommentEx(self.addr, 1) != "":
                        skel_conn.push_comment(self.addr, idc.GetCommentEx(self.addr, 1))
                    if idc.GetFunctionCmt(self.addr, 1) != "":
                        skel_conn.push_comment(self.addr,
                                idc.GetFunctionCmt(self.addr, 1))
#                 elif "MakeName" in self.cmdname:
                    # if (idc.GetFunctionAttr(self.addr, 0) == self.addr):
                        # fname = GetFunctionName(self.addr)
                        # if fname != "":
                            # if not CheckDefaultValue(fname):
                                # skel_conn.push_name(self.addr, fname)
                    # else:
                        # fname = idc.GetTrueName(self.addr)
                        # if fname != "" and not CheckDefaultValue(fname):
                            # skel_conn.push_name(self.addr, fname)
                        # else:
                            # # ok, on regarde ce qui est pointe
                            # if GetOpType(self.addr, 0) in [o_near, o_imm, o_mem]:
                                # if GetOpType(self.addr, 1) in [
                                        # o_near, o_imm, o_mem]:
                                    # g_logger.warning("You must be on the top of function or at the global address to set the name in log file")
                                # else:
                                    # add = idc.GetOperandValue(self.addr, 0)
                                    # fname = idc.GetTrueName(add)
                                    # if fname != "" and not CheckDefaultValue(fname):
                                        # skel_conn.push_name(add, fname)
                                    # else:
                                        # print "[P] You must be on the top of function or at the global address to set the name in log file"
                            # elif GetOpType(self.addr, 1) in [o_near, o_imm, o_mem]:
                                # add = idc.GetOperandValue(self.addr, 1)
                                # fname = idc.GetTrueName(add)
                                # if fname != "" and not CheckDefaultValue(fname):
                                    # skel_conn.push_name(add, fname)
                                # else:
                                    # print "[P] You must be on the top of function or at the global address to set the name in log file"

                elif self.cmdname == "MakeFunction":
                    if idc.GetFunctionAttr(self.addr, 0) is not None:
                        pass
                        #push_change("idc.MakeFunction", shex(idc.GetFunctionAttr(
                        #    self.addr, 0)), shex(idc.GetFunctionAttr(self.addr, 4)))
                elif self.cmdname == "DeclareStructVar":
                    print "Fixme : declare Struct variable"
                elif self.cmdname == "SetType":
                    newtype = idc.GetType(self.addr)
                    if newtype is None:
                        newtype = ""
                    else:
                        newtype = SkelUtils.prepare_parse_type(newtype, self.addr)
                    push_change("idc.SetType", shex(self.addr), newtype)
                elif self.cmdname == "OpStructOffset":
                    print "Fixme, used when typing a struct member/stack var/data pointer to a struct offset "
            except KeyError:
                pass
            return 0

    class SkelIDBHook(idaapi.IDB_Hooks):
        def __init__(self):
            idaapi.IDB_Hooks.__init__(self)

        def cmt_changed(self, *args):
            print "IDB: comment changed"
            print args
            return idaapi.IDB_Hooks.cmt_changed(self, *args)

        def struc_created(self, *args):
            """
                args -> id
            """
            print "New structure %s created" % idaapi.get_struc_name(args[0])
            return idaapi.IDB_Hooks.struc_created(self, *args)

        def deleting_struc(self, *args):
            """
            deleting_struc(self, sptr) -> int
            """
            print "DELETING STRUCT"
            print args
            return idaapi.IDB_Hooks.deleting_struc(self, *args)

        def renaming_struc(self, *args):
            """
            renaming_struc(self, id, oldname, newname) -> int
            """
            print "RENAMING STRUCT"
            print args
            return idaapi.IDB_Hooks.renaming_struc(self, *args)

        def expanding_struc(self, *args):
            """
            expanding_struc(self, sptr, offset, delta) -> int
            """
            return idaapi.IDB_Hooks.expanding_struc(self, *args)

        def changing_struc_cmt(self, *args):
            """
            changing_struc_cmt(self, struc_id, repeatable, newcmt) -> int
            """
            return idaapi.IDB_Hooks.changing_struc_cmt(self, *args)

        def deleting_struc_member(self, *args):
            """
            deleting_struc_member(self, sptr, mptr) -> int
            """
            return idaapi.IDB_Hooks.deleting_struc_member(self, *args)

        def renaming_struc_member(self, *args):
            """
            renaming_struc_member(self, sptr, mptr, newname) -> int
            """
            print "RENAMING STRUCT MEMBER"
            print args
            mystruct, mymember, newname = args
            print mymember
            print dir(mymember)

            return idaapi.IDB_Hooks.renaming_struc_member(self, *args)

        def changing_struc_member(self, *args):
            """
            changing_struc_member(self, sptr, mptr, flag, ti, nbytes) -> int
            """
            print "CHANGING STRUCT MEMBER"
            print args
            mystruct, mymember, flag, ti, nbytes = args
            print ti
            print dir(ti)
            print ti.cd
            print ti.ec
            print ti.ri
            print ti.tid
            return idaapi.IDB_Hooks.changing_struc_member(self, *args)

    class SkelIDPHook(idaapi.IDP_Hooks):
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
            print "Going to rename something"
            ea, name = args
            print ea, name
            return idaapi.IDP_Hooks.rename(self, *args)

        def renamed(self, *args):
            g_logger.debug("[IDB Hook] Something is renamed")
            ea, new_name, is_local_name = args
            if ea > idc.MinEA() and ea < idc.MaxEA():
                if is_local_name:
                    # XXX push_new_local_name(ea, new_name)
                    pass
                else:
                    # XXX push_new_name(ea, new_name)
                    pass
            else:
                print "ea outside program..."

            return idaapi.IDP_Hooks.renamed(self, *args)


    def __init__(self):
        self.ui_hook = SkelHooks.SkelUIHook()
        self.idb_hook = SkelHooks.SkelIDBHook()
        self.idp_hook = SkelHooks.SkelIDPHook()


    def hook(self):
        self.ui_hook.hook()
        self.idb_hook.hook()
        self.idp_hook.hook()

    def cleanup_hooks(self):
        """
            Clean IDA hooks on exit
        """
        if self.ui_hook is not None:
            self.ui_hook.unhook()
            self.ui_hook = None

        if self.idb_hook is not None:
            self.idb_hook.unhook()
            self.idb_hook = None

        if self.idp_hook is not None:
            self.idp_hook.unhook()
            self.idp_hook = None
        return

class SkelUtils(object):
    """
        Utils functions
    """
    @staticmethod
    def shex(a):
        """
            custom, pour supprimer les L finaux, au cas ou
        """
        return hex(a).rstrip("L")

    @staticmethod
    def CheckDefaultValue(name):
        default_values = ['sub_', "dword_", "unk_", "byte_", "word_", "loc_"]
        for value in default_values:
            if value in name[:6]:
                return True
        return False

    @staticmethod
    def hasSubNoppedPrefix(name):
        if name is not None:
            # IDA prefix
            default_values = ['sub_', '?', 'nullsub', 'unknown', 'SEH_']
            for val in default_values:
                if val in name[:7]:
                    return True
            if name[0] != "_" and name[0] != "@":
                    return False
        return True



    @staticmethod
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


    @staticmethod
    def header():
        """
            help!
        """
        print "-------------------------------------------------------------------"
        print "                 SKELENOX "
        print "        This plugin is part of Polichombr"
        print "             (c) ANSSI-FR 2016"
        print "-------------------------------------------------------------------"
        print "\t Collaborative reverse engineering framework"
        print "Help:"
        print "see   https://www.github.com/anssi-fr/polichombr/docs/"
        print "-------------------------------------------------------------------"
        print "\tfile %IDB%_backup_preskel_ contains pre-critical ops IDB backup"
        print "\tfile %IDB%_backup_ contains periodic IDB backups"
        return

def PLUGIN_ENTRY():
    return SkelenoxPlugin()

class SkelenoxPlugin(idaapi.plugin_t):
    """

    """
    flags = idaapi.PLUGIN_UNL
    comment = "Skelenox"
    help = "Polichombr synchronization agent"
    wanted_name = "Skelenox"
    wanted_hotkey = "Ctrl-F4"

    def init(self):
        # Some initialization
        self.icon_id = 0
        init_skelenox()
        return idaapi.PLUGIN_OK

    def run(self, arg=0):
        return

    def term(self):
        end_skelenox()

if __name__ == '__main__':
    # RUN !
    init_skelenox()
