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

# TODO:
# [ ] Fix upload of sample if it is new
# [ ] Fix note pad destruction when calling exit_skelenox
# [ ] Proper logging
# [ ] Local names (prefix) are not pushed.
# [ ] Make difference for comments
# [ ] Hook for segments / structs / enums etc

settings_filename = "skelsettings.json"
skel_settings = None
skel_db = None
skel_conn = None

last_timestamp = 0
skelhook = None
skelhook_set = None
uihook = None
polihook = None
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

        # Fond noir
        # self.backgnd_highlight_color = 0x333333
        # self.backgnd_std_color = 0x0

        if os.path.isfile(filename):
            print "[+] Loading settings file"
            self._do_init(filename)
        else:
            print "[!] Config file not edited, populating default"
            self.populate_default(filename)
            self.not_edited(filename)

    def not_edited(self, filename):
        """
            Error file not edited ;-)
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
            print "[!] Polichombr server seems down"
            print e

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
                   "Authorization": self.api_key
                   }
        method = "POST"
        json_data = json.dumps(data)
        self.h_conn.request(method, endpoint, json_data, headers)
        res = self.h_conn.getresponse()

        if res.status != 200:
            print "[!] Error during request"
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
            print "[!] Error during request"
        contentType = res.getheader("Content-Encoding")
        if contentType == "gzip":
            buf = StringIO(res.read())
            res = gzip.GzipFile(fileobj=buf)
        data = res.read()
        try:
            result = json.loads(data)
        except:
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
            print "[x] Comment %s sent for address 0x%x" % (comment, address)
        else:
            print "[!] Cannot send comment %s ( 0x%x )" % (comment, address)
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
            print "[x] sent name %s" % (name)
        else:
            print "[!] failed to send name %s" % (name)

    @staticmethod
    def prepare_endpoint(action):
        global sample_id
        return "/api/1.0/samples/" + str(sample_id) + "/" + action + "/"


def checkupdates():
    global skel_conn
    if skel_conn.is_online is False:
        return False
    # on synchro avec le server l'idb courant
    if sync_names() == -1:
        return False
    # on pousse le cache pour le sample actuel (et au passage on overwrite
    # ceux renamed lors de la synchro)
    return 0


def push_change(cmd, param1, param2):
    global skel_conn, sample_id
    print "[+] " + cmd + " => " + param1 + " :: " + param2 + " -- SENT"
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
    global skel_conn

    overwrite = idaapi.askbuttons_c("YES", "NO", "NO",
                                    0,
                                    "Names synchro: do you want to keep your actual subs names?\nYES: keep your actual names (and push them to the server)\nNO: overwrite the actual names with the server's ones")
    if overwrite == 1:
        if push_functions_names() is False:
            return False
    else:
        return sync_names(True)


def execute_comment(comment):
    """
        XXX : switch on the comment type
    """
    print comment["address"]
    idc.MakeRptCmt(
        comment["address"],
        comment["data"].encode(
            'ascii',
            'replace'))
    print "[x] Added comment %s @0x%x " % (comment["data"], comment["address"])


def execute_rename(name):
        if "sub_" in idc.GetTrueName(name["address"]):
            print "[x] renaming %s @0x%x as %s" % (idc.GetTrueName(name["address"]), name["address"], name["data"])
            idc.MakeName(
                name["address"],
                name["data"].encode(
                    'ascii',
                    'ignore'))


def sync_names(full_synchro=False):
    global sample_id, skel_conn, last_timestamp

    if not skel_conn.is_online:
        print "[!] Error, cannot sync while offline"
        return False

    comments = skel_conn.get_comments()
    for comment in comments:
        execute_comment(comment)

    names = skel_conn.get_names()
    for name in names:
        execute_rename(name)

    print "[+] IDB synchronized"
    return True


def calc_hash(funcAddr):
    """
        # calculer un hash de fonction poli-style
        #   pas de MD5 pour l'instant, voir plus tard si besoin
    """
    global ample_id
    func = idaapi.get_func(funcAddr)
    if func is None:
        return ""
    flow = idaapi.FlowChart(f=func)
    cur_hash_rev = ""
    addrIds = []
    cur_id = 1
    bb_addr = []
    for c in range(0, flow.size):
        bb_addr.append(flow.__getitem__(c).startEA)

    for c in range(0, flow.size):
        cur_basic = flow.__getitem__(c)
        cur_hash_rev += shex(cur_basic.startEA) + ":"
        addrIds.append((shex(cur_basic.startEA), str(cur_id)))
        cur_id += 1

        # on regarde si on voit des calls
        addr = cur_basic.startEA
        blockEnd = cur_basic.endEA
        mnem = GetMnem(addr)
        while mnem != "":
            if mnem == "call":
                cur_hash_rev += "c,"
                addr = NextHead(addr, blockEnd)
                mnem = GetMnem(addr)
                if addr != BADADDR:
                    cur_hash_rev += shex(addr) + ";" + shex(addr) + ":"
                    addrIds.append((shex(addr), str(cur_id)))
                    cur_id += 1
            else:
                addr = NextHead(addr, blockEnd)
                mnem = GetMnem(addr)
        refs = []
        for suc in cur_basic.succs():
            refs.append(suc.startEA)
        refs.sort()
        refsrev = ""
        for ref in refs:
            refsrev += shex(ref) + ","
        if refsrev != "":
            refsrev = refsrev[:-1]
        cur_hash_rev += refsrev + ";"

    # a ce stade, on a des strings de la forme:
    # 00000000:00000010,000000020;00000010:c,00000012;00000012:00000020;00000020:;
    # on rewalk dessus pour transformer les adresses en IDs
    for aid in addrIds:
        cur_hash_rev = string.replace(cur_hash_rev, aid[0], aid[1])

    # return cur_hash
    # print "hash:"
    # print cur_hash_rev
    m2 = _hashlib.new("md5")
    m2.update(cur_hash_rev)
    iHash = m2.hexdigest()[-8:]
    return iHash


def get_online(*args):
    global backup_file, sample_id, skel_conn

    if skel_conn.is_online:
        return 0

    print ""
    print "<!------- POLICHOMBR UPDATE -------!>"

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
            print "[!] Cannot find remote sample"
            # XXX upload sample!
            skel_conn.get_offline()
            return 0

    # maintenant on peut update (et pousser nos modifs au passage)
    if update_poli_db() == -1:
        return -1

    # remove les liens vu qu'on en a plus besoin
    if "m7" in globals() and m7 is not None:
        idaapi.del_menu_item(m7)
        m7 = None
    # if "m8" in globals() and m8 != None:
        # idaapi.del_menu_item(m8)
        #m8 = None

    print "[+] Update finished"
    print "<!---------------------------------!>"
    return 0


def update_poli_db():
    pass


def end_skelenox():
    """
        cleanup
    """
    global sample_id, skel_conn
    # cut connection
    skel_conn.close_connection()
    # on enleve les hooks
    cleanup_hooks()
    print "[!] Skelenox terminated"
    # et on reset les globales importantes
    sample_id = 0
    return


def init_skelenox():
    global crit_backup_file, backup_file, last_saved
    global last_timestamp
    global sample_id
    global m7, polihook, skellhook, skelhook_set
    global skelV
    global is_updating
    global skel_conn
    global skel_settings, settings_filename

    is_updating = 0

    skelhook_set = False
    last_timestamp = -1
    sample_id = 0
    last_saved = 0

    print "[+] Init Skelenox"
    # Load settings
    skel_settings = SkelConfig(settings_filename)

    skel_conn = SkelConnection(skel_settings.poli_server,
                               skel_settings.poli_port,
                               skel_settings.poli_remote_path,
                               skel_settings.poli_apikey,
                               skel_settings.debug_http)

    cleanup_hooks()

    # GetIdbPath() c'est un peu violent comme filename, changer si besoin
    crit_backup_file = GetIdbPath()[:-4] + "_backup_preskel_.idb"
    backup_file = GetIdbPath()[:-4] + "_backup_.idb"

    atexit.register(end_skelenox)
    print "[+] Backuping IDB (_backup_preskel_)"
    SaveBase(crit_backup_file, idaapi.DBFL_TEMP)
    print "[+] Backuping IDB (_backup_)"
    SaveBase(backup_file, idaapi.DBFL_TEMP)
    last_saved = time.time()

    # online, avec overwrite
    #   => si on load au startup, tout est deja commit donc pas de diff
    #   => sinon on ajoute les 2 boutons qui vont bien
    if skel_settings.online_at_startup is None:
        choice = idaapi.askbuttons_c("Yes",
                                     "No",
                                     "Cancel",
                                     0,
                                     "Do you want to start Polichombr synchro?")
        if choice == 1:
            skel_settings.online_at_startup = True
        else:
            skel_settings.online_at_startup = False

    if get_online() == -1:
            return
    # synchro du sample
    if startup() == -1:
        return

        # setup hooks

    polihook = MyUiHook()
    polihook.hook()

    print "[+] Skelenox init finished"
    _help()
    return


def shex(a):
    """
        custom, pour supprimer les L finaux, au cas ou
    """
    return hex(a).rstrip("L")


def shexst(a):
    return hex(a).rstrip("L").lstrip("0x") or 0


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
                print "[!] Error sending function name %s" % (fName)
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


class hookEr(idaapi.IDP_Hooks):
    """
        # hook IDP
        #   analyse de fonction des changement du ptr
        #   save l'IDB / update la poliDB toutes les 10 minutes
    """
    curfuncstart = 0
    curfuncend = 0

    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def custom_out(self):
        global last_saved, backup_file, skel_settings
        if last_saved < (time.time() - skel_settings.save_timeout):
            print "[+] Saving IDB"
            SaveBase(backup_file, idaapi.DBFL_TEMP)
            print "[+] Updating database"
            update_poli_db()
            last_saved = time.time()
        addr = idc.here()
        if addr < self.curfuncstart or addr > self.curfuncend:
            ea = ScreenEA()
            if idaapi.get_func(ea) is not None:
                cfs = idaapi.get_func(ea).startEA
                cfe = idaapi.get_func(ea).endEA
                if cfe == BADADDR:
                    cfe = idaapi.get_func(self.curfuncS).endEA
                if cfe != BADADDR and cfs != BADADDR:
                    self.curfuncstart = cfs
                    self.curfuncend = cfe
                    print analyzeFunction(addr)[0]
        return idaapi.IDP_Hooks.custom_out(self)

    def rename(self, *args):
        print "RENAMING"
        return super(self, IDP_Hook).rename()


def cleanup_hooks():
    """Clean IDA hooks on exit"""
    global uihook, polihook
    if "polihook" in globals() and polihook is not None:
        polihook.unhook()
        polihook = None
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


def tracker(*args):
    """
        Init le tracker
    """
    global skelhook, skelhook_set
    if skelhook_set:
        print "[+] UI hook uninstall"
        skelhook.unhook()
        del skelhook
        skelhook = None
        skelhook_set = False
    else:
        print "[+] UI hook install"
        skelhook = hookEr()
        skelhook.hook()
        skelhook_set = True
    return

if __name__ == '__main__':
    # RUN !
    init_skelenox()
