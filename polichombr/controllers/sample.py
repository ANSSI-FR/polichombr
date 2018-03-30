"""
    This file is part of Polichombr.

    (c) 2017 ANSSI-FR


    Description:
        Sample managements and disassembly (SVG) management.
"""

import os
import re
import time
import datetime
from collections import Counter
from subprocess import Popen
from hashlib import md5, sha1, sha256

import sqlalchemy
import magic

from sqlalchemy import func
from graphviz import Source

from polichombr import app
from polichombr import db
from polichombr.models.sample import SampleSchema, SampleMetadata, FunctionInfo
from polichombr.models.sample import SampleMetadataType, StringsItem
from polichombr.models.sample import FileName, Sample, AnalysisStatus
from polichombr.models.sample import SampleMatch, CheckList
from polichombr.models.analysis import AnalysisResult
from polichombr.models.models import TLPLevel
from polichombr.models.idaactions import IDAAction


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
        sha_256 = sha256(file_data).hexdigest()
        sample = None
        # check if we already had the file or not
        # If not, we will just update some information
        if Sample.query.filter_by(sha256=sha_256).count() != 0:
            sample = Sample.query.filter_by(sha256=sha_256).first()
            if sample.storage_file is not None and os.path.exists(
                    sample.storage_file):
                return sample

        # Create if needed
        if sample is None:
            sample = Sample()
            db.session.add(sample)
            sample.TLP_sensibility = tlp_level
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

        strings = StringsItem.query.filter_by(sample_id=sample.id).all()

        attributes = [sample.filenames,
                      sample.functions,
                      sample.actions,
                      sample.analysis_data,
                      strings]

        for attribute in attributes:
            for item in attribute:
                db.session.delete(item)

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
            return False
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
    def schema_export_many(samples):
        """
            Export a list of samples
        """
        sample_schema = SampleSchema(many=True)
        return sample_schema.dump(samples).data

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
            Create an analysis result.
            Analyses results are unique (by their titles)
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

        sha2_search = Sample.query.filter_by(sha256=needle).all()
        sha1_search = Sample.query.filter_by(sha1=needle).all()
        md5_search = Sample.query.filter_by(md5=needle).all()
        results = list(set(sha2_search + sha1_search + md5_search))
        function_results = None
        # XXX fix this
        # if re.match("[0-9a-f]{8}", needle):
        # function_results = cls.get_functions_by_machoc_hash(needle)
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
                results.append(analysis.sample)
        return results

    def search_machoc_full_hash(self, machoc_hash, limit=0.8):
        """
            Search a full machoc hash.
            In one word, diffs with other samples in database.
        """
        hits = []
        s1_hashes = []
        machoc_hash = machoc_hash.lower()

        if not re.match("^([0-9a-f]{8})+$", machoc_hash):
            return hits
        for i in re.findall("[0-9a-f]{8}", machoc_hash):
            s1_hashes.append(int(i, 16))

        for s in Sample.query.all():
            s2_hashes = self.get_functions_hashes(s)
            if s2_hashes:
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
    def add_sample_match(sample_1, sample_2, match_type):
        """
            Create and commit a sample match between two samples,
            with the associated type.
            Used types are "iat_hash" or "machoc80"
        """
        match = SampleMatch()
        match.match_type = match_type
        match.sid_2 = sample_2.id
        sample_1.linked_samples.append(match)
        sample_2.linked_samples_2.append(match)
        db.session.add(match)
        db.session.commit()

    @staticmethod
    def query_matches(sample_1, sample_2, match_type):
        """
            Return true if there is an existing match of type "match_type"
            between the two samples.
        """
        query = SampleMatch.query.filter(SampleMatch.sid_1.in_([sample_1.id,
                                                                sample_2.id]),
                                         SampleMatch.sid_2.in_([sample_1.id,
                                                                sample_2.id]),
                                         SampleMatch.match_type == match_type)
        if query.count() != 0:
            return True
        return False

    @classmethod
    def match_by_importhash(cls, sample):
        """
            Match samples by import hash.
        """
        if sample.import_hash is None or sample.import_hash == "":
            return True
        for sample_2 in Sample.query.filter_by(
                import_hash=sample.import_hash).all():
            if sample_2.id != sample.id:
                if not cls.query_matches(sample, sample_2, "iat_hash"):
                    cls.add_sample_match(sample, sample_2, "iat_hash")
                    # add the corresponding match to the other sample
                    cls.add_sample_match(sample_2, sample, "iat_hash")
        return True

    @classmethod
    def match_by_machoc80(cls, sample):
        """
            Match samples by machoc hash.
        """
        if sample.functions.count() == 0:
            return True
        for sample_2 in Sample.query.filter(Sample.id != sample.id).all():
            if cls.query_matches(sample, sample_2, "machoc80"):
                continue
            elif cls.machoc_diff_samples(sample, sample_2) >= 0.8:
                app.logger.debug("Add machoc match %d %d",
                                 sample.id, sample_2.id)
                cls.add_sample_match(sample, sample_2, "machoc80")
                cls.add_sample_match(sample_2, sample, "machoc80")
        return True

    @classmethod
    def machoc_diff_with_all_samples(cls, sample, level=0.8):
        """
            Diff a sample with all other samples. Class method.
        """
        if sample.functions.count() == 0:
            return []
        hits = []
        for sample_2 in Sample.query.all():
            if sample_2.functions.count() == 0 or sample_2.id == sample.id:
                continue
            hit_rate = cls.machoc_diff_samples(sample, sample_2)
            if hit_rate >= level:
                hits.append((sample_2, hit_rate))
        return hits

    @classmethod
    def machoc_diff_samples(cls, sample1, sample2):
        """
            Diff two samples using machoc.
        """

        sample1_hashes = [f.machoc_hash for f in
                          cls.get_functions_filtered(sample1.id)]

        sample2_hashes = [f.machoc_hash for f in
                          cls.get_functions_filtered(sample2.id)]

        rate = cls.machoc_diff_hashes(sample1_hashes, sample2_hashes)
        return rate

    @staticmethod
    def machoc_diff_hashes(sample1_hashes, sample2_hashes):
        """
            Diff two sample hashes. Thanks DLE :].
        """
        if sample1_hashes or sample2_hashes:
            return 0
        maxlen = max(len(sample1_hashes), len(sample2_hashes))
        c1, c2 = list(map(Counter, (sample1_hashes, sample2_hashes)))
        ch = set(sample1_hashes).intersection(set(sample2_hashes))
        rate = float(sum([max(c1[h], c2[h]) for h in ch])) / maxlen
        return rate

    @staticmethod
    def extract_ngrams_from_machoc(func_infos, ngrams_length=5):
        """
        Returns a list of n-grams from a list of function infos
        """
        tmp2 = []
        hashes = []
        for f in func_infos:
            tmp2.append(f.machoc_hash)
            if len(tmp2) == ngrams_length:
                hashes.append(tmp2)
                tmp2 = tmp2[1:]
        return hashes

    @classmethod
    def machoc_get_unique_match(cls, sample_src, sample_dst):
        """
            Get machoc similar functions

            @arg: two samples
            @return: A list of functions in sample `sample_dst`
            that have the same machoc hash as a least one on `sample_src`
        """
        src_funcs = cls.get_functions_filtered(sample_src.id)

        matches = []

        funcs = FunctionInfo.query.filter_by(sample_id=sample_dst.id)
        funcs = funcs.group_by(FunctionInfo.id, FunctionInfo.machoc_hash)
        funcs = funcs.having(func.count(FunctionInfo.machoc_hash) == 1)

        for funcx in src_funcs:
            match = funcs.filter_by(machoc_hash=funcx.machoc_hash)
            try:
                match = match.scalar()
                if match is not None:
                    matches.append(match)
            except sqlalchemy.orm.exc.MultipleResultsFound:
                pass
        app.logger.debug("Got %d direct machoc matches", len(matches))
        return matches

    @classmethod
    def machoc_get_similar_functions(cls, sample_dst, sample_src):
        """
            Diff two sample in order to identify similar functions.
            This is performed by:
                - getting unique machoc hashes;
                - getting unique 5-grams machoc hashes.


            n-grams are n-length tuples of machoc hashes.

            We actually build the 5-grams, compare the hashes and then compare
            the 5-grams. The code is provided as-is and MUST BE IMPROVED.
            We also have to add other functionalities:
                - 3-grams comparison between single & 5-grams comparisons;
                - 7-grams comparison with non-standard middle function.
        """

        ngrams_length = 5
        ngram_mid = 2
        retv = []
        start = time.time()

        # Get all the functions ordered by address, for both samples
        src_funcs = FunctionInfo.query
        src_funcs = src_funcs.filter_by(sample_id=sample_src.id)
        src_funcs = src_funcs.order_by(FunctionInfo.address).all()

        dst_funcs = FunctionInfo.query
        dst_funcs = dst_funcs.filter_by(sample_id=sample_dst.id)
        dst_funcs = dst_funcs.order_by(FunctionInfo.address).all()

        # Extract machoc hashes and ngrams from these functions
        src_hashes = [f.machoc_hash for f in src_funcs]
        dst_hashes = [f.machoc_hash for f in dst_funcs]
        src_ngrams_hashes = cls.extract_ngrams_from_machoc(src_funcs)
        dst_ngrams_hashes = cls.extract_ngrams_from_machoc(dst_funcs)

        # Calculate 1 - 1 hits
        unique_matches = cls.machoc_get_unique_match(sample_dst, sample_src)

        for match in unique_matches:
            src_func = cls.get_functions_machoc_filtered(
                sample_dst.id, match.machoc_hash)
            retv.append({"src": match, "dst": src_func})

        # n-grams hits
        for index, src_ngram in enumerate(src_ngrams_hashes):
            # Avoid unique matches wich are already calculated
            if src_hashes.count(
                    src_ngram[ngram_mid]) == 1 and dst_hashes.count(
                        src_ngram[ngram_mid]) == 1:
                continue
            # Is the ngram unique in the other sample
            if dst_ngrams_hashes.count(src_ngram) == 1:
                if src_ngrams_hashes.count(src_ngram) == 1:
                    # If the ngram is a match, then the function is
                    # shifted from the index in the array
                    src_function = src_funcs[index + ngram_mid]
                    dst_function = dst_funcs[dst_ngrams_hashes.index(
                        src_ngram) + 2]

                    retv.append({"src": src_function, "dst": dst_function})

        src_cpt = len(src_funcs) - len(retv)
        dst_cpt = len(dst_funcs) - len(retv)

        app.logger.debug("USING %d-GRAMS", ngrams_length)
        app.logger.debug("%d functions not found in source sample", src_cpt)
        app.logger.debug("%d functions not found in dest sample", dst_cpt)
        app.logger.debug("TOOK %d seconds", time.time() - start)
        return retv

    @staticmethod
    def add_metadata(sample, metadata_type, metadata_value):
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
                metadata_value = str(metadata_value).replace("\x00", "")
            except Exception as e:
                app.logger.exception(e)
                return False
        for meta in sample.s_metadata:
            if meta.type_id == metadata_type and meta.value == metadata_value:
                return True
        s_metadata = SampleMetadata()
        s_metadata.value = metadata_value
        s_metadata.type_id = metadata_type
        db.session.add(s_metadata)
        sample.s_metadata.append(s_metadata)
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
                metadata_value)
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
    def query_function_info(sample, address):
        obj = FunctionInfo.query.filter_by(
            sample_id=sample.id, address=address)
        if obj.count() != 0:
            return obj.first()
        return None

    @classmethod
    def add_function(cls, sample, address, machoc_hash,
                     name="", overwrite=False):
        """
            Add a function. Updates if exists.
        """
        if isinstance(address, str):
            address = int(address, 16)
        if name == "":
            name = "sub_" + hex(address)[2:]
        functions_exists = False
        function_info = cls.query_function_info(sample, address)
        if function_info is not None:
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
        db.session.commit()
        return True

    def add_multiple_functions(self, sid, funcs, overwrite=False):
        """
            Add multiple functions to the sample
            Each func is a dict with the address as key,
            and is a dict (machoc_hash, name)
        """
        sample = self.get_by_id(sid)
        for addr in list(funcs.keys()):
            self.add_function(
                sample,
                addr,
                funcs[addr]["machoc"],
                funcs[addr]["name"],
                overwrite)
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
            if fsrc not in sample_src.functions or fdst not in sample_dst.functions:
                return False
            if fsrc.name.startswith("sub_"):
                continue
            if not fdst.name.startswith("sub_"):
                continue
            fdst.name = fsrc.name
        db.session.commit()
        return True

    @staticmethod
    def get_functions(sample_id):
        """
            Return all the functions for a sample
        """
        functions = FunctionInfo.query.filter_by(sample_id=sample_id).all()
        return functions

    @staticmethod
    def get_functions_filtered(sample_id):
        """
            Get all functions from a sample
            with a valid machoc
        """
        funcs = FunctionInfo.query.filter_by(sample_id=sample_id)
        funcs = funcs.filter(FunctionInfo.machoc_hash != -1)
        return funcs.all()

    @staticmethod
    def get_functions_machoc_filtered(sample_id, machoc):
        """
            Get the first function from a sample
            with a given machoc
        """
        funcs = FunctionInfo.query.filter_by(sample_id=sample_id)
        funcs = funcs.filter_by(machoc_hash=machoc)
        return funcs.first()

    @staticmethod
    def get_function_by_address(samp, address):
        """
            Get the first function at a given address for a sample
        """
        functions = FunctionInfo.query.filter_by(sample_id=samp.id)
        functions = functions.filter_by(address=address)

        function = functions.first()
        return function

    @staticmethod
    def get_functions_hashes(sample):
        """
            Get sample machoc hashes.
        """
        functions = FunctionInfo.query.filter_by(sample_id=sample.id).all()
        machoc_hashes = [funcinfo.machoc_hash for funcinfo in functions]
        return machoc_hashes

    @staticmethod
    def get_functions_by_machoc_hash(needle):
        """
            Return a list of functions matching a given machoc hash
        """
        funcs = FunctionInfo.query.filter_by(machoc_hash=needle).all()
        return funcs

    @classmethod
    def get_proposed_funcnames(cls, sample):
        """
            Get a list of names for similar function hashes
            return a dict of {"address" : [list of names]}
        """
        funcs = [{"address": f.address,
                  "machoc_hash": f.machoc_hash,
                  "proposed_names": list()}
                 for f in cls.get_functions_filtered(sample.id)]
        app.logger.debug("Got %d funcs to compare for sample %d",
                         len(funcs),
                         sample.id)
        for function in funcs:
            matches = FunctionInfo.query.with_entities(FunctionInfo.name)
            matches = matches.filter_by(machoc_hash=function["machoc_hash"])
            matches = matches.filter(FunctionInfo.name.notlike("sub_%")).all()
            function["proposed_names"] = [match[0] for match in matches]
        return funcs

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

    @classmethod
    def rename_func_from_action(cls, sid, address, name):
        sample = cls.get_by_id(sid)
        function = cls.get_function_by_address(sample, address)
        if function is not None:
            app.logger.debug("Renaming func 0x%X as %s", address, name)
            cls.rename_function(func, name)
            return True
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
        function_infos = FunctionInfo.query.filter_by(machoc_hash=needle).all()
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
    with open(out_file, "rb") as mfile:
        data = mfile.read().decode("utf-8")
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
    with open(out_file, 'rb') as mfile:
        svg_data = mfile.read().decode("utf-8")
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
    args = ['ruby', 'polichombr/analysis_tools/disassfunc.rb',
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
    args = ['ruby', 'polichombr/analysis_tools/beautysvg.rb', filename]
    proc = Popen(args, stdin=FNULL, stdout=FNULL, stderr=FNULL)
    proc.wait()
    FNULL.close()
    app.logger.debug("Parsing SVG: Done.")
