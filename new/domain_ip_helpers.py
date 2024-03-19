import logging
from pathlib import Path

from capa.helpers import get_auto_format  # , is_runtime_ida, is_runtime_ghidra, load_json_from_path

# from capa.exceptions import UnsupportedFormatError
from capa.features.common import FORMAT_CAPE  # , FORMAT_PE, FORMAT_ELF, Feature

# from capa.features.address import Address
# from capa.features.extractors import ida, viv, cape, binja, dnfile, ghidra, pefile, elffile, dotnetfile
from capa.render.result_document import ResultDocument

# from capa.features.extractors.cape.models import CapeReport
from capa.features.extractors.base_extractor import FeatureExtractor

# from capa.features.extractors.cape.extractor import CapeExtractor

logger = logging.getLogger(__name__)

# these constants are also defined in capa.main
# defined here to avoid a circular import
BACKEND_VIV = "vivisect"
BACKEND_DOTNET = "dotnet"
BACKEND_BINJA = "binja"
BACKEND_PEFILE = "pefile"


# def get_file_strings(doc: ResultDocument) -> Tuple[Feature, Address]:
#     """extract strings from a given file"""
#     extractor = get_extractor_from_doc(doc)
#     if is_runtime_ida():
#         strings, addr = fix_up(ida.file.extract_file_strings())
#     elif is_runtime_ghidra():
#         strings, addr = fix_up(ghidra.file.extract_file_strings())
#     else:
#         file = get_file_path(doc)
#         format_ = get_auto_format(file)
#         buf = file.read_bytes()
#         if format_ == FORMAT_ELF:
#             strings, addr = fix_up(elffile.extract_file_strings(buf))
#         elif format_ == BACKEND_VIV:
#             strings, addr = fix_up(viv.file.extract_file_strings(buf))
#         elif format_ == BACKEND_PEFILE or format_ == FORMAT_PE:
#             strings, addr = fix_up(pefile.extract_file_strings(buf))
#         elif format_ == BACKEND_BINJA:
#             binja_extractor = binja.extractor.BinjaFeatureExtractor(extractor, BinaryView)
#             strings, addr = fix_up(binja.file.extract_file_strings(binja_extractor.bv))
#         elif format_ == BACKEND_DOTNET:
#             dnfile_extractor = dotnetfile.extractor.DotnetFileFeatureExtractor(extractor.path)
#             strings, addr = fix_up(dnfile.file.extract_file_strings(dnfile_extractor.pe))
#         # elif format_ == FORMAT_CAPE:
#         #     report = load_json_from_path(extractor.path)
#         #     cape_extractor = cape.extractor.CapeExtractor(extractor, report)
#         #     strings, addr = fix_up(cape.file.extract_file_strings(cape_extractor.report))
#         else:
#             raise UnsupportedFormatError(f"Unknown file format! Format: {format_}")

#     print(f"attrs of feature extractor == {dir(extractor)}")

#     return strings, addr


# def get_file_strings(doc: ResultDocument) -> Generator[Tuple[Feature, Address], None, None]:
#     """
#     matches file format and extracts features and addresses from a file

#     args:
#       doc (ResultDocument): 'None' if runtime is IDA or Ghidra

#     yields:
#       Tuple[Feature, Address] at each step of iteration
#     """
#     extractor = get_extractor_from_doc(doc)
#     if is_runtime_ida():
#         yield from ida.file.extract_file_strings()
#     elif is_runtime_ghidra():
#         yield from ghidra.file.extract_file_strings()
#     else:
#         file_path = get_file_path(doc)
#         format_ = get_auto_format(file_path)
#         buf = file_path.read_bytes()
#         if format_ == FORMAT_ELF:
#             yield from elffile.extract_file_strings(buf)
#         elif format_ == BACKEND_VIV:
#             yield from viv.file.extract_file_strings(buf)
#         elif format_ == BACKEND_PEFILE or format_ == FORMAT_PE:
#             yield from pefile.extract_file_strings(buf)
#         elif format_ == BACKEND_BINJA:
#             binja_extractor = binja.extractor.BinjaFeatureExtractor(extractor)
#             yield from binja.file.extract_file_strings(binja_extractor.bv)
#         elif format_ == BACKEND_DOTNET:
#             dnfile_extractor = dotnetfile.DotnetFileFeatureExtractor(file_path)
#             yield from dnfile.file.extract_file_strings(dnfile_extractor.pe)
#         # elif format_ == FORMAT_CAPE:
#         #     report = load_json_from_path(file_path)
#         #     yield from cape.file.extract_file_strings(report)
#         else:
#             raise UnsupportedFormatError(f"Unknown file format! Format: {format_}")


def get_file_path(doc: ResultDocument) -> Path:
    return Path(doc.meta.sample.path)


def get_sigpaths_from_doc(doc: ResultDocument):
    import capa.loader

    if doc.meta.argv:
        try:
            if "-s" in list(doc.meta.argv):
                idx = doc.meta.argv.index("-s")
                sigpath = Path(doc.meta.argv[idx + 1])
                if "./" in str(sigpath):
                    fixed_str = str(sigpath).split("./")[1]
                    sigpath = Path(fixed_str)

            elif "--signatures" in list(doc.meta.argv):
                idx = doc.meta.argv.index("--signatures")
                sigpath = Path(doc.meta.argv[idx + 1])
                if "./" in str(sigpath):
                    fixed_str = str(sigpath).split("./")[1]
                    sigpath = Path(fixed_str)

            else:
                sigpath = "(embedded)"  # type: ignore

            return capa.loader.get_signatures(sigpath)

        except AttributeError:
            raise NotImplementedError("Confirm that argv is an attribute of doc.meta")

    else:
        print("in 'get_sigpaths_from_doc', run in debug (-d) mode")
        logger.debug("'doc.meta' has not attribute 'argv', this is probably a bad sign...")


def get_extractor_from_doc(doc: ResultDocument) -> FeatureExtractor:
    import capa.loader

    path = get_file_path(doc)
    format = doc.meta.analysis.format
    os = doc.meta.analysis.os

    _ = get_auto_format(get_file_path(doc))
    if format == FORMAT_CAPE:
        pass
        # report = capa.helpers.load_json_from_path(path)
        # return CapeExtractor.from_report(report)
    elif _ == BACKEND_VIV:
        backend = BACKEND_VIV
    elif _ == BACKEND_PEFILE:
        backend = BACKEND_PEFILE
    elif _ == BACKEND_BINJA:
        backend = BACKEND_BINJA
    elif _ == BACKEND_DOTNET:
        backend = BACKEND_DOTNET
    else:
        backend = BACKEND_VIV  # according to capa.main this is the default

    sigpath = get_sigpaths_from_doc(doc)

    return capa.loader.get_extractor(
        input_path=path,
        input_format=format,
        os_=os,
        backend=backend,
        sigpaths=sigpath,
    )
