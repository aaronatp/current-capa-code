import re
import socket
import ipaddress
from typing import List, Iterator, Generator, Tuple

from capa.exceptions import UnsupportedFormatError
from capa.capabilities import domain_ip_helpers
from capa.features.insn import API  # make the "ok we get some api calls" statement can see this why cant it rn?
from capa.features.common import FORMAT_PE, FORMAT_ELF, FORMAT_DOTNET, Feature
from capa.features.address import Address
from capa.features.extractors import viv, binja, pefile, elffile, dotnetfile
from capa.render.result_document import ResultDocument
from capa.features.extractors.base_extractor import FunctionHandle, StaticFeatureExtractor, DynamicFeatureExtractor

import viv_utils

# these constants are also defined in capa.main
# defined here to avoid a circular import
BACKEND_VIV = "vivisect"
BACKEND_DOTNET = "dotnet"
BACKEND_BINJA = "binja"
BACKEND_PEFILE = "pefile"


def valid_domain(string: str) -> bool:
    """
    supports the domain extractor functions '*_extract_domain_names'

    causes the extractor function to ignore domain-like strings
    that have invalid top-level domains (e.g., ".exe", ".dll", etc.)
    """
    ##############
    # ideally we probably should move the 'DOMAIN_PATTERN' out of this function's scope but
    # then we would have to pass it as a variable to this function and that would make
    # rendering in the main function a lot more messy

    # See this Stackoverflow post that discusses the parts of this regex (http://stackoverflow.com/a/7933253/433790)
    DOMAIN_PATTERN = r"^(?!.{256})(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}|xn--[a-z0-9]{1,59})$"
    ##############
    if re.search(DOMAIN_PATTERN, string):
        invalid_list = ["win", "exe", "dll", "med", "inf", "ini", "dat", "db", "log", "bak", "lnk", "bin", "scr", "exf"]  # add more to this list
        top_level_domain = string.split('.')[-1]
        for invalid in invalid_list:
            # the caller has already lopped off any URL subfolders
            # this ensures that the last segment of the string separated
            # at periods equals the top level domain
            if top_level_domain == invalid:
                return False

        return True


def default_extract_domain_names(doc: ResultDocument) -> Iterator[str]:
    """yield web domain regex matches from list of strings"""
    ##############
    # ideally we probably should move the 'DOMAIN_PATTERN' out of this function's scope but
    # then we would have to pass it as a variable to this function and that would make
    # rendering in the main function a lot more messy

    # See this Stackoverflow post that discusses the parts of this regex (http://stackoverflow.com/a/7933253/433790)
    DOMAIN_PATTERN = r"^(?!.{256})(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}|xn--[a-z0-9]{1,59})$"
    ##############
    from capa.capabilities.domain_ip_helpers import fix_up, get_file_strings
    
    print(f"part of zip(get_file_strings(doc)[0], get_file_strings[1]): {zip(get_file_strings(doc)[0], get_file_strings(doc)[1])}")

    for string, _ in zip(get_file_strings(doc)[0], get_file_strings(doc)[1]):
        # re.search only accepts 'str' on byte-like objects so
        # we convert the type of 'string'
        string = string.value
        print(f"string.value == {string}")
        print(f"type of string value == {type(string)}")
        if valid_domain(string):
            print("it's a valid domain == {string}")
            print(f"this is a match: {string}")
            yield string

        elif is_ip_addr(string):
            print(f"it's an ip address == {string}")
            print(f"this is a match: {string}")
            yield string


def verbose_extract_domain_and_ip(doc: ResultDocument) -> Generator[str, None, None]:
    """yield web domain and ip address regex matches from list of strings"""
    # this is not very clean fix this
    for string, info_list in get_domain_ip_dict(doc).items():
        total_occurrances = info_list[1]
        if is_ip_addr(string):
            yield formatted_ip_verbose(doc, string, total_occurrances, info_list[0])
        else:
            yield formatted_domain_verbose(doc, string, total_occurrances, info_list[0])


def get_domain_ip_dict(doc: ResultDocument):
    """
    essentially gets dict of domains/IPs in a file and number of times each occur

    returns the concatenation of the domain and IP dicts

    {'70.103.102.12': ['/next/asxp.jpg', 12]} yes do this and loop through this dict like 'for domain_or_ip, info[0] in dict'
    """
    domain_counts = {}
    ip_counts = {}

    for string, _ in zip(*domain_ip_helpers.get_file_strings(doc)):
        for cleaned_string, extra in initial_domain_ip_cleaning(string.value):
        # cleaned_string, extra = initial_domain_ip_cleaning(string.value)
            if valid_domain(cleaned_string):
                try:
                    domain_counts[cleaned_string].value()[1] += 1
                    print("do we increment domain total occurrances?")
                except KeyError:
                    domain_counts[cleaned_string] = [extra, 1]

            elif is_ip_addr(cleaned_string):
                try:
                    ip_counts[cleaned_string].value()[1] += 1
                    print("do we increment ip total occurrances?")
                except KeyError:
                    ip_counts[cleaned_string] = [extra, 1]


    print(f"domain_ip_dict == {dict(list(domain_counts.items()) + list(ip_counts.items()))}")

    return dict(list(domain_counts.items()) + list(ip_counts.items()))


def initial_domain_ip_cleaning(dirty_string):
    """
    some strings could have spaces in them (for example, in one version of Gandcrab ransomware,
    "%X ahnlab hXXp://memesmix.net/media/created/dd0doq.jpg" [I replaced "http" with "hXXP"])
    
    """
    # ok move the following filtering etc to the above (i.e., above the regex is_ip_addr functions)
    print(f"ok basic string == {dirty_string}")
    list_of_strings = dirty_string.split(" ")
    for string in list_of_strings:
        if "http://" in string:
            print(f"we split http:// from {string}")
            string = string.split("http://")[-1]
            print(f"string now == {string}")
            
        if "https://" in string:
            print(f"we split https:// from {string}")
            string = string.split("https://")[-1]
            print(f"string now == {string}")

        if "/" in string:
            print(f"there were extra '/' so we split them in {string}")
            string, extra = string.split("/")[0], string.split("/")[1:]
            print(f"we set extra == {string.split('/')[1:]}")
            print(f"after setting extra string now == {string}")

        else:
            print("we set extra == ''")
            extra = ['']

        print(f"string and extra == {string} and {extra}")

        yield string, extra


# wrap is_ip_addr to potentially split http:// and https and trailing "/" - build this into regex or at least that part if possible
def is_ip_addr(string: str) -> bool:
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False


def formatted_ip_verbose(doc: ResultDocument, string: str, total_occurrances: int, extra: List[str]) -> str:
    """same as 'formatted_domain_verbose' but without 'ip_address_statement'"""
    return (
        f"{string}\n"
        + f"    |---- {networking_functions_statement(doc, string, extra)}\n"
        + f"    |---- {total_occurrances} occurrances\n"
    )


def formatted_domain_verbose(doc: ResultDocument, string: str, total_occurrances: int, extra: List[str]) -> str:
    """
    example output:

    capa -v suspicious.exe
    -----------------------
    google.com
        |---- IP address:
        |        |----192.0.0.1
        |----Functions used to communicate with google.com:
        |        |----InternetConnectA
        |        |----HttpOpenRequestA
        |        |----FtpGetFileA
        |----3 occurrances
    """
    return (
        f"{string}\n"
        + f"    |---- {ip_address_statement(string)}\n"
        + f"end of ip addr statement\n"
        + f"    |---- {networking_functions_statement(doc, string, extra)}\n"
        + f"    |---- {total_occurrances} occurrances\n"
    )


def ip_address_statement(string: str) -> str:
    try:
        print(f"string that is passed to socket.gethostbyname == {string}")
        ip_address = socket.gethostbyname(string)
        print(f"ok ip_address == {ip_address}")
            # if is_messy(ip_address):
            #     ip_address = clean(ip_address)
        print("\nokok")
        print(f"len of ip_address == {len(ip_address)}")
        print(f"type of ip_address == {type(ip_address)}")
        assert(type(ip_address) == str)
        return "IP address:\n" + f"|        |----{ip_address}"
    except socket.gaierror:
        return f"Could not get IP address from {string}"


class InvalidHostnameError(BaseException):
    pass


def networking_functions_statement(doc: ResultDocument, string: str, extra: List[str]) -> str:
    """prints the functions used to communicate with domain/ip"""
    api_functions = get_domain_or_ip_caller_functions(doc, string)

    if len(api_functions) == 0:
        statement = f"""
        {string} occurs but no functions found that use it.
        Perhaps it's a decoy domain/IP address? If you think this is a mistake,
        please open an issue on the capa GitHub page (https://github.com/mandian/capa)
        """
        return statement
    
    elif len(api_functions) == 1:
        statement = f"Function used to communicate with {string}"
        # this first for loop adds any 'extra' features to statement
        for page in extra:
                if page != '':
                    statement += '/' + page

        for func in api_functions:
            return statement + f"\n|    |----{func}"
    
    elif len(api_functions) > 1:
        statement = f"Functions used to communicate with {string}\n"
        # this first for loop adds any 'extra' features to statement
        for page in extra:
                if page != '':
                    statement += '/' + page

        for function in api_functions:
            statement += f"\n|    |----{function}\n"

        return statement
    
    else:
        raise LengthError("'api_functions' contains unexpected data!")
    

class LengthError(BaseException):
    pass


def get_domain_or_ip_caller_functions(doc: ResultDocument, domain_or_ip: str) -> List[str]:
    """
    for every occurrance of 'domain' in the extractor, we see which function (e.g., Windows API)
    uses it

    returns:
      List[str]: list of functions that are used in communication with a domain
    """
    api_functions = []

    if isinstance(domain_ip_helpers.get_extractor_from_doc(doc), StaticFeatureExtractor):
        print(f"domain_or_ip we are passing to yielded_caller_func_static == {domain_or_ip}")
        for caller_func in yielded_caller_func_static(doc, domain_or_ip):
            print(f"caller_func is {caller_func} asdfg")
            if caller_func is None:
                continue
            api_functions.append(caller_func)

    # if isinstance(domain_ip_helpers.get_extractor_from_doc(doc), DynamicFeatureExtractor):
    #     for caller_func in yielded_caller_func_dynamic(doc, domain_or_ip):
    #         if caller_func is None:
    #             continue
    #         api_functions.append(caller_func)

    return api_functions


def generate_insns_from_doc(doc):
    extractor = domain_ip_helpers.get_extractor_from_doc(doc)
    for func in extractor.get_functions():
        for block in extractor.get_basic_blocks(func):
            for insn in extractor.get_instructions(func, block):
                for insn_feature, insn_addr in extractor.extract_insn_features(func, block, insn):
                    yield insn_feature, insn_addr
                    

def yielded_caller_func_static(doc: ResultDocument, target_string: str) -> Generator[str, None, None]:
    """
    analogous to 'yielded_caller_func_dynamic' but tailored to StaticFeatureExtractor
    """
    signal = 0
    for feature, _ in generate_insns_from_doc(doc):
        if feature.value == target_string:
            signal = 1

        if signal == 1:
            if type(feature) == API and potential_winapi_function(feature.value):
                if '.' in feature.value:
                    signal = 0
                    print(f"feature.value.split('.')[-1] yield == {feature.value.split('.')[-1]}")
                    yield feature.value.split('.')[-1]

                signal = 0
                print(f"feature.value yield == {feature.value}")
                yield feature.value


def quick_true():
    return ['inet', 'addr', 'send', 'recv', 'sock',\
            'select', 'shutdown', 'ntoh', 'listen',\
                'serv', 'getpeer']


def potential_winapi_function(string):
    """
    some simple heuristics for checking whether a string is NOT a WinAPI function
    
    returns:
      True if string is not a WinAPI function
      False if string could be a WinAPI function    
    """
    if '.' in string:
        print(f"potential winapi function == {string}")
        string = string.split('.')[-1]

    if string in excluded_functions():
        return False

    for smell in quick_true():
        if smell in string:
            return True

    if "_" in string:
        if all(sub_string.isupper() for sub_string in string.split("_")):
            print("running all() etc")
            print(f"{string} fails all() etc")
            return True

    if string.isupper() or string.islower():  # WinAPI functions are usually mixed upper and lower case
        print("running is upper or lower")
        print(f"{string} fails upper or lower")
        return False

    if not string.isalpha():  # if contains non-letters
        print("running isalpha")
        print(f"{string} fails isalpha")
        return False

    if too_many_consecutive_uppercase_letters(string, 7):  # maximum of 7 consecutive uppercase letters
        print("are we running connsecuritive uppercase")
        print(f"{string} fails consecutive uppercase")
        return False

    print(f"{string} doesn't fail any of the winapi weed out conditions")
    return True


def excluded_functions():
    """
    add excluded functions here, e.g., those that can't accept an IP address/web domain as an argument
    """
    return ['Sleep']


def too_many_consecutive_uppercase_letters(string, limit):
    """
    'HOSTENT' (probably) has the  most consecutive uppercase letters

    returns:
      True: too many consecutive uppercase letters, caller function disregards
      False: not too many consecutive uppercase, indicates this is a potential WinAPI function
    """
    counter = 0
    for i in string:
        if i.isupper():
            counter += 1
        else:  # basically reset counter if we reach a non-uppercase letter
            counter = 0

        if counter > limit:
            return True
    
    return False


def get_function_name(doc: ResultDocument, func: FunctionHandle) -> str:
    """
    helper function for 'yielded_caller_func_static,' not used in yielded_caller_func_dynamic

    returns:
      function_name (str): function's name (e.g., "HttpOpenRequestA")
    """
    extractor = domain_ip_helpers.get_extractor_from_doc(doc)
    file = domain_ip_helpers.get_file_path(doc)
    format_ = domain_ip_helpers.get_auto_format(file)
    if format_ == BACKEND_VIV:
        function_name = extractor.get_function_name(func.inner.va)

    elif format_ == BACKEND_BINJA:
        function_name = binja.file.extract_function_name(func)
    
    # PE/Dotnet/ELF extractors don't implement 'get_function_name'
    # the following is kind of a hacky way around that lol
    elif format_ in {FORMAT_PE, FORMAT_DOTNET, FORMAT_ELF}:
        from capa.main import get_workspace
        from capa.features.extractors.viv.insn import get_imports

        sigpaths = domain_ip_helpers.get_sigpaths_from_doc(doc)
        vw = get_workspace(file, format_, sigpaths)
        print(f"get_imports == {get_imports(vw)} asdfg")
        function_name = '0'
        # function_name = viv_utils.get_function_name(vw, func.inner.va)
        # print(f"vw imports: {vw.imports} asdfg")
        # print(f"vw exports: {vw.exports} asdfg")
        # print(f"vw name by va: {vw.name_by_va} asdfg")
        # function_name = viv_utils.get_function_name(vw, func.inner.va)  # va versus absolute address
    else:
        raise UnsupportedFormatError(
            "Unexpected format! Please open an issue on GitHub (https://github.com/mandiant/capa/issues)"
        )

    return function_name






# from vivisect import VivWorkspace
# def get_binary_location(vw: VivWorkspace, va: int):
#     print(f"binary function location == {vw.name_by_va[va]} asdfg")
#     return vw.name_by_va[va]


def yielded_caller_func_dynamic(
    doc: ResultDocument, target_string: str, start_position: Address
) -> Generator[str, None, None]:
    """
    we look into an extractor to see what APIs operate on a web domain

    examines calling context of web domains and yields any functions that
    operate on them. next, recursively examines calling contexts of yielded
    functions and yields additional network management functions
    (e.g., "HttpOpenRequestA", "FtpGetFileA", etc.).

    """
    extractor = domain_ip_helpers.get_extractor_from_doc(doc)
    for ph in extractor.get_processes():
        for th in extractor.get_threads(ph):
            for ch in extractor.get_calls(ph, th):
                for feature, addr in extractor.extract_call_features(ph, th, ch):
                    # if we are in the 'yield from' statement, this ignores
                    # appearances of api_name that occur before web domain
                    if addr < start_position:
                        continue

                    if feature.value == target_string:
                        api_name = extractor.extract_call_features(ph, th, ch)[0][0]
                        yield api_name  # yield the function operating on the web domain

                        if any(["HTTP", "HTTPS", "FTP", "UDP"]) in api_name.upper():
                            continue

                        # if the yielded function is not a network protocol function
                        # (e.g., "Https," "Ftp," etc.), we ask if the yielded function
                        # is passed to other functions that are network protocol functions
                        else:
                            try:
                                # when we do 'start_position = addr', we ignore 'function_name' when it occurs
                                # before 'feature' (i.e., before 'addr')
                                yield from yielded_caller_func_dynamic(doc, api_name, addr)

                            except StopIteration:
                                yield None
