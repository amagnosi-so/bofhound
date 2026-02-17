from bloodhound.ad.utils import ADUtils

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme
from bofhound.ad.helpers.cert_utils import PkiCertificateAuthorityFlags


class BloodHoundEnterpriseCA(BloodHoundObject):

    GUI_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'isaclprotected',
        'description', 'whencreated', 'flags', 'caname', 'dnshostname', 'certthumbprint',
        'certname', 'certchain', 'hasbasicconstraints', 'basicconstraintpathlength',
        'casecuritycollected', 'enrollmentagentrestrictionscollected', 'isuserspecifiessanenabledcollected',
        'unresolvedpublishedtemplates'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, _object):
        super().__init__(_object)

        self._entry_type = "EnterpriseCA"
        self.IsDeleted = False
        self.ContainedBy = {}
        self.IsACLProtected = False
        self.Properties['casecuritycollected'] = False
        self.Properties['enrollmentagentrestrictionscollected'] = False
        self.Properties['isuserspecifiessanenabledcollected'] = False
        self.Properties['unresolvedpublishedtemplates'] = []
        self.CARegistryData = None
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

        if 'flags' in _object.keys():
            int_flag = int(_object.get("flags"))
            self.Properties['flags'] = ', '.join([member.name for member in PkiCertificateAuthorityFlags if member.value & int_flag == member.value])

        if 'name' in _object.keys():
            self.Properties['caname'] = _object.get('name')
            if 'domain' in self.Properties.keys():
                self.Properties['name'] = _object.get('name').upper() + "@" + self.Properties['domain'].upper()

        if 'dnshostname' in _object.keys():
            self.Properties['dnshostname'] = _object.get('dnshostname')

        if 'cacertificate' in _object.keys():
            self.parse_cacertificate(_object)

        if 'ntsecuritydescriptor' in _object.keys():
            self.RawAces = _object['ntsecuritydescriptor']

        self.HostingComputer = None
        self.EnabledCertTemplates = []

        if 'certificatetemplates' in _object.keys():
            self.CertTemplates = _object.get('certificatetemplates').split(', ')
    

    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        data = super().to_json(properties_level)

        data["HostingComputer"] = self.HostingComputer
        data["CARegistryData"] = self.CARegistryData
        data["EnabledCertTemplates"] = self.EnabledCertTemplates
        data["Aces"] = self.Aces
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["IsDeleted"] = self.IsDeleted
        data["IsACLProtected"] = self.IsACLProtected
        data["ContainedBy"] = self.ContainedBy
        
        return data