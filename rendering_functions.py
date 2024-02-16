import tabulate

import capa.render.utils as rutils
import capa.render.result_document as rd
from capa.render.utils import StringIO
from capa.capabilities.extract_domain_and_ip import default_extract_domain_names, verbose_extract_domain_and_ip


### Default mode

def render_domain_and_ip(doc: rd.ResultDocument, ostream: StringIO):
    """
    example::
        +------------------------------+
        | IP addresses and web domains |
        |------------------------------+
        | google.com                   |
        | 192.123.232.08               |
        | my-w3bs1te.net               |
        | maliciooous.r4ndom-site.uhoh |
        | whoops.net                   |
        +------------------------------+
    """
    rows = []
    for domain_or_ip in default_extract_domain_names(doc):
        rows.append(domain_or_ip)

    if rows:
        ostream.write(
            tabulate.tabulate(
                {"IP addresses and web domains": rows},
                headers=["IP addresses and web domains"],
                tablefmt="mixed_outline",
            )
        )
        ostream.write("\n")
    else:
        ostream.writeln(rutils.bold("No web domains or IP addresses found"))


### Verbose mode

def render_domain_and_ip(ostream: rutils.StringIO, doc: rd.ResultDocument):
    """
    example::
        +-----------------------------------------------------------+
        | IP addresses and web domains                              |
        |-----------------------------------------------------------+
        | google.com                                                |
        |    |----IP address:                                       |
        |            |----192.0.0.1                                 |
        |    |----Functions used to communicate with google.com:    |
        |            |----InternetConnectA                          |
        |            |----HttpOpenRequestA                          |
        |            |----FtpGetFileA                               |
        |    |----3 occurrances                                     |
        |                                                           |                                                                          |
        | 192.123.232.08                                            |
        |    |----Functions used to communicate with 192.123.232.08:|
        |            |----...                                       |
        |                                                           |
        +-----------------------------------------------------------+
    """
    rows = []
    for domain_or_ip in verbose_extract_domain_and_ip(doc):
        rows.append(domain_or_ip)

    if rows:
        ostream.write(
            tabulate.tabulate(
                {"IP addresses and web domains": rows},
                headers=["IP addresses and web domains"],
                tablefmt="mixed_outline",
            )
        )
        ostream.write("\n")
    else:
        ostream.writeln(rutils.bold("No web domains or IP addresses found"))
