from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject

from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundDomain(BloodHoundObject):

    GUI_PROPERTIES = [
        'distinguishedname', 'domainsid', 'description', 'whencreated',
        'functionallevel', 'domain', 'isaclprotected', 'collected',
        'name'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, _object):
        super().__init__(_object)

        self._entry_type = "Domain"
        self.GPLinks = []
        self.ContainedBy = {}
        level_id = _object.get('msds-behavior-version', 0)
        try:
            functional_level = ADUtils.FUNCTIONAL_LEVELS[int(level_id)]
        except KeyError:
            functional_level = 'Unknown'

        dc = None

        self.Properties['collected'] = True

        if 'distinguishedname' in _object.keys():
            self.Properties["name"] = ADUtils.ldap2domain(_object.get('distinguishedname').upper())
            self.Properties["domain"] = self.Properties["name"]
            dc = BloodHoundObject.get_domain_component(_object.get('distinguishedname').upper())
            logger.debug(f"Reading Domain object {ColorScheme.domain}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectsid' in _object.keys():
            self.Properties["domainsid"] = _object.get('objectsid')

        if 'distinguishedname' in _object.keys():
            self.Properties['distinguishedname'] = _object.get('distinguishedname').upper()

        if 'description' in _object.keys():
            self.Properties["description"] = _object.get('description')
        else:
            self.Properties["description"] = None

        if 'ntsecuritydescriptor' in _object.keys():
            self.RawAces = _object['ntsecuritydescriptor']

        if 'gplink' in _object.keys():
            # [['DN1', 'GPLinkOptions1'], ['DN2', 'GPLinkOptions2'], ...]
            self.GPLinks = [link.upper()[:-1].split(';') for link in _object.get('gplink').split('[LDAP://')][1:]

        self.Properties["highvalue"] = True

        self.Properties["functionallevel"] = functional_level

        self.Trusts = []
        self.Aces = []
        self.Links = []
        self.ChildObjects = []
        self.GPOChanges = {
            "AffectedComputers": [],
            "DcomUsers": [],
            "LocalAdmins": [],
            "PSRemoteUsers": [],
            "RemoteDesktopUsers": []
        }
        self.IsDeleted = False
        self.IsACLProtected = False


    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        domain = super().to_json(properties_level)

        domain["ObjectIdentifier"] = self.ObjectIdentifier
        domain["Trusts"] = self.Trusts
        domain["ContainedBy"] = None
        # The below is all unsupported as of now.
        domain["Aces"] = self.Aces
        domain["Links"] = self.Links
        domain["ChildObjects"] = self.ChildObjects

        self.GPOChanges["AffectedComputers"] = self.AffectedComputers
        self.GPOChanges["AffectedUsers"] = self.AffectedUsers
        domain["GPOChanges"] = self.GPOChanges

        domain["IsDeleted"] = self.IsDeleted
        domain["IsACLProtected"] = self.IsACLProtected

        return domain
