"""
    Sample managements and disassembly (SVG) management.
"""

import os
import random
import re
import datetime
import yara
import magic
import time
import json

from flask import abort
from hashlib import md5, sha1, sha256
from collections import Counter
from subprocess import Popen
from graphviz import Source

from app import app
from app import db
from app import login_manager
from app.models.sample import SampleSchema, SampleMetadata, FunctionInfo
from app.models.sample import SampleMetadataType, StringsItem, StringsType
from app.models.sample import FileName, Sample, AnalysisStatus, CheckList
from app.models.sample import SampleMatch
from app.models.user import User
from app.models.analysis import AnalysisResult
from app.models.models import TLPLevel
from app.models.yara_rule import YaraRule
from app.models.idaactions import IDAAction


class SampleController(object):
    """
        Wrapper to the Sample model. It is in charge of managing the creation,
        extraction and modification of samples, and all of directly related
        information, such as function information, ida actions, etc.
    """

    def __init__(self):
        pass

    def create_sample_from_file(self, file_data, orig_filename="", user=None,
                                tlp_level=TLPLevel.TLPWHITE):
        """
            Creates a sample from file data. Updates metadata, etc.
        """
        if TLPLevel.tostring(tlp_level) == "":
            return None
        sha_256 = sha256(file_data).hexdigest()
        sample = None
        # check if we already had the file or not. If not, we will just update some
        # information
        if Sample.query.filter_by(sha256=sha_256).count() != 0:
            sample = Sample.query.filter_by(sha256=sha_256).first()
            if sample.storage_file is not None and sample.storage_file != "" and os.path.exists(
                    sample.storage_file):
                return sample

        # Create if needed
        if sample is None:
            sample = Sample()
            db.session.add(sample)
            sample.TLP_sensibility = tlp_level
            sample.family_id = None
            sample.file_date = datetime.datetime.now()
        elif sample.file_date is None:
            sample.file_date = datetime.datetime.now()

        # Drop file to disk
        filename = sha_256 + ".bin"
        file_path = os.path.join(app.config['STORAGE_PATH'], filename)
        with open(file_path, 'wb') as myfile:
            myfile.write(file_data)

        # Generic data
        sample.analysis_status = AnalysisStatus.TOSTART
        sample.storage_file = file_path
        mime_type = self.do_sample_type_detect(file_path)
        sample.mime_type = mime_type[0]
        sample.full_mime_type = mime_type[1]
        sample.md5 = md5(file_data).hexdigest()
        sample.sha1 = sha1(file_data).hexdigest()
        sample.sha256 = sha_256
        sample.size = len(file_data)
        # Specific metadata, resulting from Tasks
        sample.import_hash = ""
        sample.machoc_hash = ""

        db.session.commit()

        if orig_filename != "":
            self.add_filename(sample, orig_filename)
        if user is not None:
            self.add_user(user, sample)
        return sample

    @staticmethod
    def add_filename(sample, name):
        """
            Adds a sample file name.
        """
        filename = FileName()
        filename.name = name
        sample.filenames.append(filename)
        db.session.add(filename)
        db.session.commit()
        return True

    @staticmethod
    def do_sample_type_detect(datafile):
        """
            Checks the datafile type's.
        """
        mtype = magic.from_file(datafile, mime=True)
        stype = magic.from_file(datafile)
        return (mtype, stype)

    @classmethod
    def delete(cls, sample):
        """
            Delete sample.
        """
        if os.path.exists(sample.storage_file):
            os.remove(sample.storage_file)
        for act in sample.filenames:
            db.session.delete(act)
        for act in sample.functions:
            db.session.delete(act)
        for act in sample.actions:
            db.session.delete(act)
        for an in sample.analysis_data:
            db.session.delete(an)
        cls.flush_matches(sample)
        db.session.delete(sample)
        db.session.commit()
        return True

    @staticmethod
    def remove_user(user, sample):
        """
            Delete user from sample.
        """
        if user in sample.users:
            sample.users.remove(user)
            db.session.commit()
        return True

    @staticmethod
    def add_user(user, sample):
        """
            Add user in sample.
        """
        if user in sample.users:
            return True
        sample.users.append(user)
        db.session.commit()
        return True

    @staticmethod
    def set_file_date(sample, timestamp):
        """
            Change file's internal date.
        """
        sample.file_date = timestamp
        db.session.commit()
        return True

    def set_import_hash(self, sample, import_hash):
        """
            Sets the sample's import hash. Also performs the IAT match.
        """
        sample.import_hash = import_hash
        db.session.commit()
        self.match_by_importhash(sample)
        return True

    @staticmethod
    def set_tlp_level(sample, tlp_level):
        """
            Change file's TLP level.
        """
        if TLPLevel.tostring(tlp_level) == "":
            return None
        for family in sample.families:
            if family.TLP_sensibility > tlp_level:
                return False
        sample.TLP_sensibility = tlp_level
        db.session.commit()
        return True

    @staticmethod
    def schema_export_all():
        """
            Schema export.
        """
        # TODO : any sample, not only PE ones.
        sample_schema = SampleSchema(many=True)
        data = Sample.query.all()
        return sample_schema.dump(data).data

    @staticmethod
    def schema_export(sample):
        """
            Schema export.
        """
        sample_schema = SampleSchema()
        return sample_schema.dump(sample).data

    @staticmethod
    def get_all_samples():
        """
            Schema export.
        """
        sample_schema = SampleSchema()
        data = Sample.query.all()
        return sample_schema.dump(data).data

    @staticmethod
    def set_abstract(sample, abstract):
        """
            Abstract update.
        """
        sample.abstract = abstract
        db.session.add(sample)
        db.session.commit()
        return True

    @staticmethod
    def get_checklist_by_id(checklist_id):
        """
            Get checklist by id.
        """
        return CheckList.query.get(checklist_id)

    @staticmethod
    def toggle_sample_checklist(sample, checklist):
        """
            Toggle checklist item for the sample.
        """
        if checklist not in sample.check_list:
            sample.check_list.append(checklist)
        else:
            sample.check_list.remove(checklist)
        db.session.commit()
        return True

    @staticmethod
    def create_checklist(title, description):
        """
            Creates checklist.
        """
        checklist = CheckList()
        checklist.title = title
        checklist.description = description
        db.session.add(checklist)
        db.session.commit()
        return True

    @staticmethod
    def delete_checklist(checklist):
        """
            Deletes checklist.
        """
        db.session.delete(checklist)
        db.session.commit()
        return True

    @staticmethod
    def get_all_checklists():
        """
            Get all checklist.
        """
        return CheckList.query.all()

    @staticmethod
    def create_analysis(sample, data, title, overwrite=True):
        """
            Create an analysis result. Analyses results are unique (by their titles)
            if overwrite is set to False, the existing one will be overwitten.
            Otherwise, not.
        """
        analysis = AnalysisResult.query.filter_by(
            title=title, sample=sample).first()
        analysis_exists = True
        if analysis is None:
            analysis = AnalysisResult()
            analysis_exists = False
        elif not overwrite:
            return True
        analysis.title = title
        analysis.data = data
        analysis.analysis_data = datetime.datetime.now()
        analysis.analysis_status = True
        if not analysis_exists:
            sample.analysis_data.append(analysis)
        db.session.add(analysis)
        db.session.commit()
        return True

    @staticmethod
    def search_machoc_single_hash(needle):
        """
            Search needle machoc hash.
        """
        if isinstance(needle, str):
            needle = int(needle, 16)
        return FunctionInfo.query.filter(
            FunctionInfo.machoc_hash == needle).all()

    @classmethod
    def search_hash(cls, needle):
        """
            Search a hash. If len() == 8, will also search in functions hashes.

            Returns (samples, functions)
        """
        results = []
        needle = needle.lower()
        if not re.match("[0-9a-f]{5,}", needle):
            return []
        needleq = "%" + needle + "%"
        a = Sample.query.filter(Sample.sha256.like(needleq)).all()
        b = Sample.query.filter(Sample.sha1.like(needleq)).all()
        c = Sample.query.filter(Sample.md5.like(needleq)).all()
        results = list(set(a + b + c))
        function_results = None
        if re.match("[0-9a-f]{8}", needle):
            function_results = cls.search_machoc_single_hash(needle)
        return results, function_results

    @classmethod
    def search_fulltext(cls, needle, max_results=50):
        """
            Search a text in lot of items and return associated samples.
            Searchs in filenames, strings, functions names and anlysis
            abstracts. Oh, and also in samples abstracts.
        """
        results = []
        if len(needle) < 5:
            return results

        needle = "%" + needle + "%"
        results = Sample.query.filter(Sample.abstract.like(needle)).all()

        tmpres = FileName.query.filter(FileName.name.like(needle)).all()
        for filename in tmpres:
            if filename.sample not in results:
                results.append(filename.sample)

        tmpres = StringsItem.query.filter(
            StringsItem.string_value.like(needle)).all()
        for stringitem in tmpres:
            if stringitem.sample not in results:
                results.append(stringitem.sample)
        if len(results) > max_results:
            return results

        tmpres = FunctionInfo.query.filter(
            FunctionInfo.name.like(needle)).all()
        for function in tmpres:
            if function.sample not in results:
                results.append(function.sample)
        if len(results) > max_results:
            return results

        for analysis in AnalysisResult.query.filter(
                AnalysisResult.data.like(needle)).all():
            if analysis.sample not in results:
                results.append(s.sample)

        return results

    def search_machoc_full_hash(self, machoc_hash, limit=0.8):
        """
            Search a full machoc hash. In one word, diffs with other
            samples in database.
        """
        machoc_hash = machoc_hash.lower()
        if not re.match("^([0-9a-f]{8})+$", machoc_hash):
            return []
        hits = []
        s1_hashes = []
        for i in re.findall("[0-9a-f]{8}", machoc_hash):
            s1_hashes.append(int(i, 16))

        for s in Sample.query.all():
            s2_hashes = []
            for f in s.functions:
                if f.machoc_hash is not None and f.machoc_hash != -1:
                    s2_hashes.append(f.machoc_hash)
            if len(s2_hashes) > 0:
                hitlvl = self.machoc_diff_hashes(s1_hashes, s2_hashes)
                if hitlvl >= limit:
                    hits.append((s, hitlvl))
        return hits

    @staticmethod
    def flush_matches(sample):
        """
            Deletes matches.
        """
        for match in sample.linked_samples:
            db.session.delete(match)
        for match in sample.linked_samples_2:
            db.session.delete(match)
        matches = SampleMatch.query.filter_by(sid_2=sample.id).all()
        for match in matches:
            db.session.delete(match)
        db.session.commit()
        return False

    @staticmethod
    def match_by_importhash(sample):
        """
            Match samples by import hash.
        """
        if sample.import_hash is None or sample.import_hash == "":
            return True
        for sample_2 in Sample.query.filter_by(
                import_hash=sample.import_hash).all():
            if sample_2.id != sample.id:
                if SampleMatch.query.filter(SampleMatch.sid_1.in_([sample.id, sample_2.id]), SampleMatch.sid_2.in_(
                        [sample.id, sample_2.id]), SampleMatch.match_type == "iat_hash").count() == 0:
                    match = SampleMatch()
                    match.match_type = "iat_hash"
                    match.sid_2 = sample_2.id
                    sample.linked_samples.append(match)
                    sample_2.linked_samples_2.append(match)
                    db.session.add(match)
                    db.session.commit()

                    # add the corresponding match to the other sample
                    match = SampleMatch()
                    match.match_type = "iat_hash"
                    match.sid_2 = sample.id
                    sample_2.linked_samples.append(match)
                    db.session.add(match)
                    db.session.commit()

                continue
        return True

    def match_by_machoc80(self, sample):
        """
            Match samples by machoc hash.
        """
        if len(sample.functions) == 0:
            return True
        for sample_2 in Sample.query.all():
            if len(sample_2.functions) == 0:
                continue
            if SampleMatch.query.filter(SampleMatch.sid_1.in_([sample.id, sample_2.id]), SampleMatch.sid_2.in_(
                    [sample.id, sample_2.id]), SampleMatch.match_type == "machoc80").count() != 0:
                continue
            if self.machoc_diff_samples(sample, sample_2) >= 0.8:
                match = SampleMatch()
                match.match_type = "machoc80"
                match.sid_2 = sample_2.id
                sample.linked_samples.append(match)
                sample_2.linked_samples_2.append(match)
                db.session.add(match)
                db.session.commit()

                match = SampleMatch()
                match.match_type = "machoc80"
                match.sid_2 = sample.id
                sample_2.linked_samples.append(match)
                db.session.add(match)
                db.session.commit()
        return True

    @classmethod
    def machoc_diff_with_all_samples(cls, sample, level=0.8):
        """
            Diff a sample with all other samples. Class method.
        """
        if len(sample.functions) == 0:
            return []
        hits = []
        for sample_2 in Sample.query.all():
            if len(sample_2.functions) == 0 or sample_2 == sample:
                continue
            hit_rate = cls.machoc_diff_samples(sample, sample_2)
            if hit_rate >= level:
                hits.append((sample_2, hit_rate))
        return hits

    @classmethod
    def machoc_diff_samples(cls, sample1, sample2):
        """
            Diff two samples using machoc.
            XXX : le memory leak arrive entre deux appels de cette methode
        """
        app.logger.error("Mem: %i" % (cls.memory_usage_resource()))
        if sample1 == sample2:
            return 0
        sample1_hashes = []
        sample2_hashes = []
        for f in sample1.functions:
            if f.machoc_hash is not None and f.machoc_hash != -1:
                sample1_hashes.append(f.machoc_hash)
        for f in sample2.functions:
            if f.machoc_hash is not None and f.machoc_hash != -1:
                sample2_hashes.append(f.machoc_hash)
        app.logger.error("Mem: %i" % (cls.memory_usage_resource()))
        return cls.machoc_diff_hashes(sample1_hashes, sample2_hashes)

    @staticmethod
    def memory_usage_resource():
        import resource
        rusage_denom = 1024.
        mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / rusage_denom
        return mem

    @staticmethod
    def machoc_diff_hashes(sample1_hashes, sample2_hashes):
        """
            Diff two sample hashes. Thanks DLE :].
        """
        if len(sample1_hashes) == 0 or len(sample2_hashes) == 0:
            return 0
        maxlen = max(len(sample1_hashes), len(sample2_hashes))
        c1, c2 = map(Counter, (sample1_hashes, sample2_hashes))
        ch = set(sample1_hashes).intersection(set(sample2_hashes))
        return float(sum(map(lambda h: max(c1[h], c2[h]), ch))) / maxlen

    def machoc_get_similar_functions(self, sample_dst, sample_src):
        """
            Diff two sample in order to identify similar functions. This is performed by:
            - getting unique machoc hashes;
            - getting unique 5-grams machoc hashes.

            We actually build the 5-grams, compare the hashes and then compare the
            5-grams. The code is provided as-is and MUST BE IMPROVED. We also have to add
            other functionalities:
            - 3-grams comparison between single & 5-grams comparisons;
            - 7-grams comparison with non-standard middle function.
        """
        src_addresses_identified = []
        dst_addresses_identified = []
        src_hashes = []
        src_ngrams_hashes = []
        dst_hashes = []
        dst_ngrams_hashes = []
        dst_sorted_fcts = []
        ngrams_length = 5
        ngram_mid = 2
        retv = []
        start = time.time()
        src_sorted_fcts = []
        for i in sample_src.functions:
            if i.machoc_hash == -1:
                continue
            src_hashes.append(i.machoc_hash)
            src_sorted_fcts.append((i.address, i.machoc_hash, i))
        src_sorted_fcts.sort()
        tmp2 = []
        for i in src_sorted_fcts:
            tmp2.append(i[1])
            if len(tmp2) == ngrams_length:
                src_ngrams_hashes.append(tmp2)
                tmp2 = tmp2[1:]
        for i in sample_dst.functions:
            if i.machoc_hash == -1:
                continue
            dst_hashes.append(i.machoc_hash)
            dst_sorted_fcts.append((i.address, i.machoc_hash, i))
        dst_sorted_fcts.sort()
        tmp2 = []
        for i in dst_sorted_fcts:
            tmp2.append(i[1])
            if len(tmp2) == ngrams_length:
                dst_ngrams_hashes.append(tmp2)
                tmp2 = tmp2[1:]
        # 1 - 1 hits
        for i in sample_src.functions:
            if i.machoc_hash == -1:
                continue
            if dst_hashes.count(i.machoc_hash) == 1 and src_hashes.count(
                    i.machoc_hash) == 1:
                for j in sample_dst.functions:
                    if j.machoc_hash == i.machoc_hash:
                        retv.append({"src": i, "dst": j})
                        src_addresses_identified.append(i.address)
                        dst_addresses_identified.append(j.address)
                        break
        cc = 0
        # n-grams hits
        for i in src_ngrams_hashes:
            if src_hashes.count(i[ngram_mid]) == 1 and dst_hashes.count(
                    i[ngram_mid]) == 1:
                continue
            if i in dst_ngrams_hashes:
                if src_ngrams_hashes.count(
                        i) == 1 and dst_ngrams_hashes.count(i) == 1:
                    src_ngram_found = []
                    dst_ngram_found = []
                    src_function = None
                    dst_function = None
                    tmp1 = []
                    tmp2 = []
                    for x in src_sorted_fcts:
                        tmp1.append(x[2])
                        tmp2.append(x[1])
                        if tmp2 == i:
                            src_function = tmp1[ngram_mid]
                            break
                        if len(tmp2) == len(i):
                            tmp1 = tmp1[1:]
                            tmp2 = tmp2[1:]
                    tmp1 = []
                    tmp2 = []
                    for x in dst_sorted_fcts:
                        tmp1.append(x[2])
                        tmp2.append(x[1])
                        if tmp2 == i:
                            dst_function = tmp1[ngram_mid]
                            break
                        if len(tmp2) == len(i):
                            tmp1 = tmp1[1:]
                            tmp2 = tmp2[1:]
                    if src_function and dst_function:
                        retv.append({"src": src_function, "dst": dst_function})
                        src_addresses_identified.append(src_function.address)
                        dst_addresses_identified.append(dst_function.address)
                    else:
                        app.logger.error("NGram diff error")
        src_cpt = 0
        dst_cpt = 0
        for i in sample_src.functions:
            if i.machoc_hash == -1:
                continue
            if i.address not in src_addresses_identified:
                retv.append({"src": i, "dst": None})
                src_cpt += 1
        for i in sample_dst.functions:
            if i.machoc_hash == -1:
                continue
            if i.address not in dst_addresses_identified:
                retv.append({"src": None, "dst": i})
                dst_cpt += 1
        app.logger.debug("USING " + str(ngrams_length) + "-GRAMS")
        app.logger.debug("SRC sample not found count : " + str(src_cpt))
        app.logger.debug("DST sample not found count : " + str(dst_cpt))
        app.logger.debug("TOOK " + str(time.time() - start) + " seconds")
        return retv

    @staticmethod
    def add_metadata(sample, metadata_type,
                     metadata_value, do_commit=True):
        """
            Add a sample's metadata.
        """
        if SampleMetadataType.tostring(metadata_type) == "":
            app.logger.error("Invalid metadata type supplied")
            return False
        if isinstance(metadata_value, int):
            metadata_value = hex(metadata_value)
        else:
            try:
                metadata_value = str(metadata_value)
            except Exception as e:
                app.logger.error("Invalid metadata supplied")
                return False
        for s_metadata in sample.s_metadata:
            if s_metadata.type_id == metadata_type and s_metadata.value == metadata_value:
                return True
        s_metadata = SampleMetadata()
        s_metadata.value = metadata_value
        s_metadata.type_id = metadata_type
        db.session.add(s_metadata)
        sample.s_metadata.append(s_metadata)
        if do_commit:
            db.session.commit()
        return True

    def add_multiple_metadata(self, sample, metas):
        """
            Add multiple sample metadata. Avoid too many commits.
        """
        for metadata_type, metadata_value in metas:
            self.add_metadata(
                sample,
                metadata_type,
                metadata_value,
                do_commit=False)
        db.session.commit()
        return True

    @staticmethod
    def add_string(sample, string_type, string_value, do_commit=True):
        """
            Add a string.
        """
        for string_item in sample.strings:
            if string_item.string_type == string_type and string_item.string_value == string_value:
                return True
        string_item = StringsItem()
        string_item.string_value = string_value
        string_item.string_type = string_type
        db.session.add(string_item)
        sample.strings.append(string_item)
        if do_commit:
            db.session.commit()
        return True

    def add_multiple_strings(self, sample, strings):
        """
            Add multiple sample strings. Avoid too many commits.
        """
        for string_type, string_value in strings:
            self.add_string(sample, string_type, string_value, do_commit=False)
        db.session.commit()
        return True

    @staticmethod
    def add_function(sample, address, machoc_hash,
                     name="", overwrite=False, do_commit=True):
        """
            Add a function. Updates if exists.
        """
        if isinstance(address, str):
            address = int(address, 16)
        if name == "":
            name = "sub_" + hex(address)[2:]
        functions_exists = False
        obj = FunctionInfo.query.filter_by(sample=sample, address=address)
        if obj.count() != 0:
            function_info = obj.first()
            functions_exists = True
            if not overwrite:
                return True
        if not functions_exists:
            function_info = FunctionInfo()
            db.session.add(function_info)
            function_info.address = address
        function_info.name = name
        if isinstance(machoc_hash, str):
            machoc_hash = int(machoc_hash, 16)
        function_info.machoc_hash = machoc_hash
        sample.functions.append(function_info)
        if do_commit:
            db.session.commit()
        return True

    def add_multiple_functions(self, sample, funcs, overwrite=False):
        """
            Add multiple.
        """
        for address, machoc_hash, name in funcs:
            self.add_function(
                sample,
                address,
                machoc_hash,
                name,
                overwrite,
                do_commit=False)
        db.session.commit()
        return True

    @classmethod
    def sample_rename_from_diff(cls, items, sample_dst, sample_src):
        """
            Rename a sample's functions with other ones functions.
        """
        for fid_dst, fid_src in items:
            fsrc = FunctionInfo.query.get(fid_src)
            fdst = FunctionInfo.query.get(fid_dst)
            if fsrc is None or fdst is None:
                return False
            if fsrc not in sample_src.functions:
                return False
            if fdst not in sample_dst.functions:
                return False
            if fsrc.name.startswith("sub_"):
                continue
            if not fdst.name.startswith("sub_"):
                continue
            fdst.name = fsrc.name
        db.session.commit()
        return True

    @staticmethod
    def get_function_by_address(samp, address):
        for i in samp.functions:
            if i.address == address:
                return i

    @staticmethod
    def get_functions_hashes(sample):
        """
            Get sample machoc hashes.
        """
        machoc_hashes = []
        for functioninfo in sample.functions:
            machoc_hashes.append(functioninfo.machoc_hash)
        return machoc_hashes

    @staticmethod
    def get_sample_function_by_address(sample, address):
        if isinstance(address, str):
            adress = int(address, 16)
        for functioninfo in sample.functions:
            # TODO : there is a bug in here.
            if int(functioninfo.address) == address:
                return functioninfo
        return None

    @staticmethod
    def update_function_hash(function, machoc_hash):
        """
            Update a function's machoc hash.
        """
        function.machoc_hash = machoc_hash
        db.session.commit()
        return True

    @staticmethod
    def rename_function(function, name):
        """
            Update a function's name.
        """
        function.name = name
        db.session.commit()
        return True

    @staticmethod
    def get_function_by_machoc_hash(sample, needle):
        """
            Get by hash.
        """
        for function in sample.functions:
            if function.machoc_hash == needle:
                return function
        return None

    @classmethod
    def rename_func_from_action(cls, sid, address, name):
        sample = cls.get_by_id(sid)
        func = cls.get_sample_function_by_address(sample, address)
        if func is not None:
            app.logger.debug("Renaming func 0x%X as %s" % (address, name))
            cls.rename_function(func, name)
            return True
        else:
            return False

    @staticmethod
    def get_by_id(sid):
        """
            By ID.
        """
        return Sample.query.get(sid)

    @staticmethod
    def get_samples_by_machoc_hash(needle):
        """
            By machoc hash.
        """
        if isinstance(needle, str):
            needle = int(needle, 16)
        function_infos = FunctionInfo.query.filter_by(machoc_hash=needle)
        samples = []
        if function_infos is None:
            return []
        for function in function_infos:
            if function.sample not in samples:
                samples.append(function.sample)
        return samples

    @staticmethod
    def get_user_uncategorized_samples(user, limit=15):
        """
            By user with no family.
        """
        samples = []
        for sample in user.samples:
            if sample.families.count() == 0:
                samples.append(sample)
                limit = limit - 1
                if limit == 0:
                    break
        return samples

    def create_sample_from_json_machex(self, machex_json, level):
        """
            Creation from machex string data.
        """
        try:
            jdata = json.loads(machex_json)
            mhash_sha256 = jdata["sha256"]
            mhash_sha1 = jdata["sha1"]
            mhash_md5 = jdata["md5"]
            mtype = jdata["type"]
        except Exception as e:
            app.logger.error("Machex import failed : %s" % (e))
            return None

        qresult = Sample.query.filter_by(sha256=mhash_sha256)
        exists = False
        if qresult.count() != 0:
            sample = qresult.first()
            return None
        sample = Sample()
        sample.md5 = mhash_md5
        sample.sha1 = mhash_sha1
        sample.sha256 = mhash_sha256
        sample.mime_type = mtype
        sample.TLP_sensibility = level
        sample.analysis_status = AnalysisStatus.TOSTART
        if "full_mime_type" in jdata:
            sample.full_mime_type = jdata["full_mime_type"]
        if "size" in jdata:
            sample.size = jdata["size"]
        if "file_date" in jdata:
            sample.file_date = jdata["file_date"]
        db.session.add(sample)
        if "file_metadata" in jdata:
            for i in jdata["file_metadata"]:
                self.add_metadata(
                    sample, SampleMetadataType.fromstring(
                        i['type']), i['value'])
        if "filenames" in jdata:
            for i in jdata["filenames"]:
                self.add_filename(sample, i)
        if "functions" in jdata:
            for i in jdata["functions"]:
                address = i["address"]
                if isinstance(address, str):
                    address = int(address, 16)
                name = ""
                machoc_hash = -1
                if "machoc" in i:
                    machoc_hash = i["machoc"]
                    if isinstance(machoc_hash, str):
                        machoc_hash = int(machoc_hash, 16)
                if "name" in i:
                    name = i["name"]
                self.add_function(sample, address, machoc_hash, name)
        if "strings" in jdata and len(jdata["strings"]) > 0:
            for i in jdata["strings"]:
                typ = i["type"]
                val = i["value"]
                if not exists:
                    self.add_string(sample, typ, val)
        if "abstract" in jdata:
            sample.abstract = jdata["abstract"]
        if "analyses" in jdata:
            for i in jdata["analyses"]:
                self.create_analysis(sample, i["data"], i["title"])
        db.session.commit()
        return sample

    @staticmethod
    def machexport(sample, machocfull, strings, metadata,
                   fmachoc, fname, sabstract, aabstracts):
        """
            Creation of machex string data.
        """
        retv = {}
        retv["md5"] = sample.md5
        retv["sha1"] = sample.sha1
        retv["sha256"] = sample.sha256
        retv["type"] = sample.mime_type
        if machocfull:
            retv["machoc"] = ""
        if sabstract:
            retv["abstract"] = sample.abstract
        if aabstracts:
            retv["analyses"] = []
            for i in sample.analysis_data:
                retv["analyses"].append({"title": i.title, "data": i.data})
        if metadata:
            retv["file_date"] = str(sample.file_date)
            retv["size"] = sample.size
            retv["full_mime_type"] = sample.full_mime_type
            retv["file_metadata"] = []
            retv["filenames"] = []
            for i in sample.s_metadata:
                retv["file_metadata"].append(
                    {"type": SampleMetadataType.tostring(i.type_id), "value": i.value})
            for i in sample.filenames:
                retv['filenames'].append(i.name)
        if fmachoc or fname or machocfull:
            if fmachoc or fname:
                retv["functions"] = []
            for f in sample.functions:
                if fmachoc or fname:
                    tmp = {"address": f.address}
                    if fname:
                        tmp["name"] = f.name
                    if fmachoc:
                        tmp["machoc"] = f.machoc_hash
                    retv["functions"].append(tmp)
                if machocfull:
                    retv["machoc"] += hex(f.machoc_hash)[2:].zfill(8)
        if strings:
            retv["strings"] = []
            for i in sample.strings:
                retv["strings"].append(
                    {"type": i.string_type, "value": i.string_value})
        return retv

    @staticmethod
    def add_idaaction(sid, action_id):
        """
            Add to sample.
            TODO: use objects, not ids (cf. task_analyzeitrb).
        """
        sample = Sample.query.get(sid)
        if sample is None:
            return False
        action = IDAAction.query.get(action_id)
        if action is None:
            return False
        # TODO: apply_action()
        # TODO: propagate to FUNCTIONINFO names
        sample.actions.append(action)
        db.session.commit()
        return True


def disassemble_sample(sample_id, address):
    """
        Gets SVG file data.
    """
    filename = Sample.query.get(sample_id).storage_file
    if not filename:
        return False
    out_file = disassemble_it(filename, address)
    if out_file is False:
        return False
    data = open(out_file, "rb").read()
    return data


def disassemble_sample_get_svg(sample_id, address):
    """
        Gets SVG file data, with functions names.
    """
    graph = disassemble_sample(sample_id, address)
    filename = Sample.query.get(sample_id).storage_file
    data = Source(graph, format='svg')
    out_file = filename + "_disass_"
    if address is not None:
        out_file += hex(address)
    out_file = data.render(out_file)
    beautify_svg(out_file)
    svg_data = open(out_file, 'rb').read()
    elements = re.findall("func_<!-- -->[0-9a-f]{3,}h", svg_data)
    for e in elements:
        et = e[13:-1]
        for i in Sample.query.get(sample_id).functions:
            if i.address == et:
                svg_data = svg_data.replace(e, i.name)
    elements = re.findall("loc_[0-9a-f]{3,}h", svg_data)
    for e in elements:
        et = e[4:-1]
        for i in Sample.query.get(sample_id).functions:
            if i.address == et:
                svg_data = svg_data.replace(e, i.name)
    return svg_data


def disassemble_it(filename, address=None):
    """
        Wrapper for the ruby disassembler script.
    """
    FNULL = open(os.devnull, 'w')

    if address is not None:
        outfile = filename + "_disass_" + hex(address)
    else:
        outfile = filename + "_disass_None"
    args = ['ruby', 'analysis_tools/disassfunc.rb',
            "-graph", "-svg", "-o", outfile, filename]
    if address is not None:
        args.append(hex(address))
    proc = Popen(args, stdin=FNULL, stdout=FNULL, stderr=FNULL)
    proc.wait()
    FNULL.close()
    app.logger.debug("Disassembly just finished!")
    return outfile


def beautify_svg(filename):
    """
        Runs the SVG beautifier.
        TODO: move the beautifier code here, there is no reason to leave
        it in a ruby script file.
    """
    FNULL = open(os.devnull, 'w')
    args = ['ruby', 'analysis_tools/beautysvg.rb', filename]
    proc = Popen(args, stdin=FNULL, stdout=FNULL, stderr=FNULL)
    proc.wait()
    FNULL.close()
    app.logger.debug("Parsing SVG: Done.")
