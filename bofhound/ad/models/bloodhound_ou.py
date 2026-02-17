from bloodhound.ad.utils import ADUtils

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundOU(BloodHoundObject):

    GUI_PROPERTIES = [
        'distinguishedname', 'whencreated',
        'domain', 'domainsid', 'name', 'highvalue', 'description',
        'blocksinheritance', 'isaclprotected'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, _object):
        super().__init__(_object)

        self._entry_type = "OU"
        self.GPLinks = []
        self.ContainedBy = {}
        self.Properties["blocksinheritance"] = False

        if 'distinguishedname' in _object.keys() and 'ou' in _object.keys():
            self.Properties["domain"] = ADUtils.ldap2domain(_object.get('distinguishedname').upper())
            self.Properties["name"] = f"{_object.get('ou').upper()}@{self.Properties['domain']}"
            logger.debug(f"Reading OU object {ColorScheme.ou}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectguid' in _object.keys():
            self.ObjectIdentifier = _object.get("objectguid").upper().upper()

        if 'ntsecuritydescriptor' in _object.keys():
            self.RawAces = _object['ntsecuritydescriptor']

        if 'description' in _object.keys():
            self.Properties["description"] = _object.get('description')

        if 'gplink' in _object.keys():
            # [['DN1', 'GPLinkOptions1'], ['DN2', 'GPLinkOptions2'], ...]
            self.GPLinks = [link.upper()[:-1].split(';') for link in _object.get('gplink').split('[LDAP://')][1:]

        if 'gpoptions' in _object.keys():
            gpoptions = _object.get('gpoptions')
            if gpoptions == '1':
                self.Properties["blocksinheritance"] = True

        self.Properties["highvalue"] = False

        self.Aces = []
        self.Links = []
        self.ChildObjects = []
        self.GPOChanges = {
            "AffectedComputers": [],
            "AffectedUsers": [],
            "DcomUsers": [],
            "LocalAdmins": [],
            "PSRemoteUsers": [],
            "RemoteDesktopUsers": []
        }
        self.IsDeleted = False
        self.IsACLProtected = False


    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        ou = super().to_json(properties_level)

        ou["ObjectIdentifier"] = self.ObjectIdentifier
        ou["ContainedBy"] = self.ContainedBy
        # The below is all unsupported as of now.
        ou["Aces"] = self.Aces
        ou["Links"] = self.Links
        ou["ChildObjects"] = self.ChildObjects

        self.GPOChanges["AffectedComputers"] = self.AffectedComputers
        self.GPOChanges["AffectedUsers"] = self.AffectedUsers
        ou["GPOChanges"] = self.GPOChanges

        ou["IsDeleted"] = self.IsDeleted
        ou["IsACLProtected"] = self.IsACLProtected

        return ou
