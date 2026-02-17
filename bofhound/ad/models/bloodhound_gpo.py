from bloodhound.ad.utils import ADUtils

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundGPO(BloodHoundObject):

    GUI_PROPERTIES = [
        'distinguishedname', 'whencreated',
        'domain', 'domainsid', 'name', 'highvalue',
        'description', 'gpcpath', 'isaclprotected'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, _object):
        super().__init__(_object)

        self._entry_type = "GPO"
        self.ContainedBy = {}
        
        if 'distinguishedname' in _object.keys() and 'displayname' in _object.keys():
            self.Properties["domain"] = ADUtils.ldap2domain(_object.get('distinguishedname').upper())
            self.Properties["name"] = f"{_object.get('displayname').upper()}@{self.Properties['domain']}"
            logger.debug(f"Reading GPO object {ColorScheme.gpo}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectguid' in _object.keys():
            self.ObjectIdentifier = _object.get("objectguid").upper().upper()

        if 'ntsecuritydescriptor' in _object.keys():
            self.RawAces = _object['ntsecuritydescriptor']

        if 'description' in _object.keys():
            self.Properties["description"] = _object.get('description')

        if 'gpcfilesyspath' in _object.keys():
            self.Properties["gpcpath"] = _object.get('gpcfilesyspath')

        self.Properties["highvalue"] = False

        self.Aces = []

        self.IsDeleted = False
        self.IsACLProtected = False

    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        gpo = super().to_json(properties_level)

        gpo["ObjectIdentifier"] = self.ObjectIdentifier
        gpo["ContainedBy"] = self.ContainedBy
        # The below is all unsupported as of now.
        gpo["Aces"] = self.Aces
        gpo["IsDeleted"] = self.IsDeleted
        gpo["IsACLProtected"] = self.IsACLProtected

        return gpo
