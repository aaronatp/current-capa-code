from typing import List, Tuple, Iterator, Union
from pathlib import Path

from capa.helpers import is_runtime_ida, get_auto_format, is_runtime_ghidra
from capa.exceptions import UnsupportedFormatError
from capa.features.common import FORMAT_PE, FORMAT_ELF, FORMAT_CAPE, String
from capa.features.address import Address
from capa.features.extractors import ida, viv, cape, binja, dnfile, ghidra, pefile, elffile
from capa.render.result_document import ResultDocument
from capa.features.extractors.base_extractor import FeatureExtractor
from capa.features.extractors.cape.models import CapeReport
from capa.features.extractors.cape.extractor import CapeExtractor

# these constants are also defined in capa.main
# defined here to avoid a circular import
BACKEND_VIV = "vivisect"
BACKEND_DOTNET = "dotnet"
BACKEND_BINJA = "binja"
BACKEND_PEFILE = "pefile"


def get_file_strings(doc: ResultDocument) -> Tuple[String, Address]:
    """extract strings from a given file"""
    extractor = get_extractor_from_doc(doc)
    if is_runtime_ida():
        strings, addr = fix_up(ida.helpers.extract_file_strings())
    elif is_runtime_ghidra():
        strings, addr = fix_up(ghidra.helpers.extract_file_strings())
    else:
        file = get_file_path(doc)
        format_ = get_auto_format(file)
        buf = file.read_bytes()
        if format_ == FORMAT_ELF:
            strings, addr = fix_up(elffile.extract_file_strings(buf))
        elif format_ == BACKEND_VIV:
            strings, addr = fix_up(viv.file.extract_file_strings(buf))
        elif format_ == BACKEND_PEFILE or format_ == FORMAT_PE:
            strings, addr = fix_up(pefile.extract_file_strings(buf))
        elif format_ == BACKEND_BINJA:
            strings, addr = fix_up(binja.file.extract_file_strings(extractor.bv))
        elif format_ == BACKEND_DOTNET:
            strings, addr = fix_up(dnfile.file.extract_file_strings(extractor.pe))
        elif format_ == FORMAT_CAPE:
            strings, addr = fix_up(cape.file.extract_file_strings(extractor.report))
        else:
            raise UnsupportedFormatError(f"Unknown file format! Format: {format_}")

    return strings, addr


def fix_up(obj: Iterator[Tuple[String, Address]]) -> Tuple[List[str], List[Address]]:
    """
    basically a wrapper for 'extract_file_strings' calls
    to actually get list of strings
    """
    strings, addrs = [], []
    for tuple in obj:
        strings.append(tuple[0])
        addrs.append(tuple[1])

    return strings, addrs


def get_file_path(doc: ResultDocument) -> Path:
    return Path(doc.meta.sample.path)


def get_extractor_from_doc(doc: ResultDocument) -> FeatureExtractor:
    import capa.loader
    path = get_file_path(doc)
    format = doc.meta.analysis.format
    os = doc.meta.analysis.os

    _ = get_auto_format(get_file_path(doc))
    if format == FORMAT_CAPE:
        report = CapeReport.from_buf(path.read_bytes())
        return CapeExtractor.from_report(report)
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
                sigpath = "(embedded)"  # default sigpath value from main.py

            return capa.loader.get_signatures(sigpath)

        except AttributeError:
            raise NotImplementedError("Uh oh! argv is not an attribute of meta")
    
    else:
        raise SigpathError("Could not get signatures!")


class SigpathError(BaseException):
    pass
