from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundAIACA(BloodHoundObject):

    GUI_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'isaclprotected',
        'description', 'whencreated', 'crosscertificatepair', 'hascrosscertificatepair',
        'certthumbprint', 'certname', 'certchain', 'hasbasicconstraints',
        'basicconstraintpathlength'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, _object):
        super().__init__(_object)

        self._entry_type = "AIACA"
        self.ContainedBy = {}
        self.IsACLProtected = False
        self.IsDeleted = False
        self.x509Certificate = None

        if 'objectguid' in _object.keys():
            self.ObjectIdentifier = _object.get("objectguid").upper()

        if 'distinguishedname' in _object.keys():
            domain = ADUtils.ldap2domain(_object.get('distinguishedname')).upper()
            self.Properties['domain'] = domain
            self.Properties['distinguishedname'] = _object.get('distinguishedname').upper()

        if 'description' in _object.keys():
            self.Properties['description'] = _object.get('description')
        else:
            self.Properties['description'] = None

        if 'name' in _object.keys():
            if 'domain' in self.Properties.keys():
                self.Properties['name'] = _object.get('name').upper() + "@" + self.Properties['domain'].upper()

        if 'crosscertificatepair' in _object.keys():
            self.Properties['crosscertificatepair'] = _object.get('crosscertificatepair')
            self.Properties['hascrosscertificatepair'] = True
        else:
            self.Properties['crosscertificatepair'] = []
            self.Properties['hascrosscertificatepair'] = False

        if 'cacertificate' in _object.keys():
            self.parse_cacertificate(_object)
        
        if 'ntsecuritydescriptor' in _object.keys():
            self.RawAces = _object['ntsecuritydescriptor']

        
    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        data = super().to_json(properties_level)

        data["Aces"] = self.Aces
        data["IsDeleted"] = self.IsDeleted
        data["IsACLProtected"] = self.IsACLProtected
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["ContainedBy"] = self.ContainedBy

        return data
