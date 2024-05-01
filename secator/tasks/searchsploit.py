import platform

from secator.decorators import task
from secator.definitions import (
    CVES,
    EXTRA_DATA,
    ID,
    MATCHED_AT,
    NAME,
    OPT_NOT_SUPPORTED,
    PROVIDER,
    REFERENCE,
    TAGS,
)
from secator.output_types import Exploit
from secator.runners import Command


@task()
class searchsploit(Command):
    """Exploit-DB command line search tool."""

    cmd = "searchsploit"
    input_flag = None
    json_flag = "--json"
    version_flag = OPT_NOT_SUPPORTED
    opts = {
        "strict": {
            "short": "s",
            "is_flag": True,
            "default": False,
            "help": "Strict match",
        }
    }
    opt_key_map = {}
    output_types = [Exploit]
    output_map = {
        Exploit: {
            NAME: lambda x: "-".join(x["Title"].split("-")[1:]).strip(),
            PROVIDER: lambda x: "EDB",
            ID: "EDB-ID",
            CVES: lambda x: [c for c in x["Codes"].split(";") if c.startswith("CVE-")],
            REFERENCE: lambda x: f'https://exploit-db.com/exploits/{x["EDB-ID"]}',
            EXTRA_DATA: lambda x: {"verified": x["Verified"]},
        }
    }
    if platform.system() == "Darwin":
        install_cmd = (
            "if command -v brew >/dev/null 2>&1; then "
            "if brew ls --versions exploitdb >/dev/null 2>&1; then "
            "brew update >/dev/null 2>&1 && brew upgrade exploitdb >/dev/null 2>&1 || true; "
            "else "
            "brew update >/dev/null 2>&1 && brew install exploitdb >/dev/null 2>&1 || true; "
            "fi; "
            "else "
            "if [ ! -d '/opt/exploit-database' ]; then "
            "sudo mkdir /opt/exploitdb && sudo chown $USER /opt/exploitdb || true; "
            "git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploit-database || true; "
            "else "
            "cd /opt/exploit-database && git pull || true; "
            "fi; "
            "if [ ! -L /usr/local/bin/searchsploit ]; then "
            "sudo mkdir -p /usr/local/bin && sudo chown $USER /usr/local/bin || true; "
            "ln -sf /opt/exploit-database/searchsploit /usr/local/bin/searchsploit || true; "
            "fi; "
            "if [ ! -f ~/.searchsploit_rc ]; then "
            "cp -n /opt/exploit-database/.searchsploit_rc ~/ || true; "
            "sed -i.bak 's|path_array=(.*)|path_array=(\"/opt/exploit-database\")|g' ~/.searchsploit_rc || true; "
            "fi; "
            "searchsploit -u || true; "
            "fi"
        )
    else:
        install_cmd = (
            "sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb || true && "
            "sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit"
        )
    proxychains = False
    proxy_socks5 = False
    proxy_http = False
    input_chunk_size = 1
    profile = "io"

    @staticmethod
    def before_init(self):
        _in = self.input
        self.matched_at = None
        if "~" in _in:
            split = _in.split("~")
            self.matched_at = split[0]
            self.input = split[1]
        if isinstance(self.input, str):
            self.input = self.input.replace("httpd", "").replace("/", " ")

    @staticmethod
    def on_item_pre_convert(self, item):
        if self.matched_at:
            item[MATCHED_AT] = self.matched_at
        item[TAGS] = [self.input.replace("'", "")]
        return item
