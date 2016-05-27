# Copyright (C) 2016 Nate Hausrath (hausrath@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class RansomwareBehavior(Signature):
    name = "ransomware_behavior"
    description = "Looks for generic ransomware behavior"
    weight = 3
    severity = 3
    categories = ["ransomware"]
    authors = ["Nate Hausrath"]
    minimum = "1.2"

    def run(self):
        executed_commands = [
            '"C:\\Windows\\system32\\vssadmin.exe" delete shadows /all /quiet',
            'C:\\Windows\\sysnative\\vssadmin.exe delete shadows /all /quiet',
            '"C:\\Windows\\system32\\wbem\\wmic.exe" shadowcopy delete',
            'C:\\Windows\\sysnative\\wbem\\WMIC.exe shadowcopy delete',
            '"C:\\Windows\\System32\\bcdedit.exe" /set {default} recoveryenabled no',
            'bcdedit.exe /set {default} recoveryenabled no',
            '"C:\\Windows\\System32\\bcdedit.exe" /set {default} bootstatuspolicy ignoreallfailures',
            'bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures ',
        ]
        
        found_commands = []
        for ioc in executed_commands:
            if self.check_executed_command(pattern=ioc):
                found_commands.append(ioc)
        if len(found_commands) > 1:
            self.description = ("Executes commands similar to ransomware.")
            for command in found_commands:
                self.data.append({"Command Executed" : command})
            return True

        return False
