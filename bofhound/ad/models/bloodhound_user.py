from bloodhound.ad.utils import ADUtils
from bloodhound.ad.structures import LDAP_SID
from bloodhound.enumeration.memberships import MembershipEnumerator

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundUser(BloodHoundObject):

    GUI_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'samaccountname',
        'isaclprotected', 'description', 'whencreated', 'sensitive',
        'dontreqpreauth', 'passwordnotreqd', 'unconstraineddelegation',
        'pwdneverexpires', 'enabled', 'trustedtoauth', 'lastlogon', 'lastlogontimestamp',
        'pwdlastset', 'serviceprincipalnames', 'hasspn', 'admincount',
        'displayname', 'email', 'title', 'homedirectory', 'userpassword',
        'unixpassword', 'unicodepassword', 'sfupassword', 'logonscript', 'sidhistory'
    ]

    COMMON_PROPERTIES = [
        'samaccounttype', 'objectsid', 'primarygroupid', 'isdeleted',
        'msds-groupmsamembership', 'serviceprincipalname', 'useraccountcontrol', 
        'mail', 'msds-allowedtodelegateto', 'unicodepwd', 'allowedtodelegate',   
        'memberof'
    ]

    def __init__(self, _object=None):
        super().__init__(_object)

        self._entry_type = "User"
        self.PrimaryGroupSid = None
        self.AllowedToDelegate = []
        self.Aces = []
        self.ContainedBy = {}
        self.SPNTargets = []
        self.HasSIDHistory = []
        self.IsACLProtected = False
        self.MemberOfDNs = []

        if isinstance(_object, dict):
            self.PrimaryGroupSid = self.get_primary_membership(_object) # Returns none if not exist

            if 'distinguishedname' in _object.keys() and 'samaccountname' in _object.keys():
                domain = ADUtils.ldap2domain(_object.get('distinguishedname')).upper()
                name = f'{_object.get("samaccountname")}@{domain}'.upper()
                self.Properties["name"] = name
                self.Properties["domain"] = domain
                logger.debug(f"Reading User object {ColorScheme.user}{name}[/]", extra=OBJ_EXTRA_FMT)

            if 'admincount' in _object.keys():
                self.Properties["admincount"] = int(_object.get('admincount')) == 1 # do not move this lower, it may break imports for users

            # self.Properties["highvalue"] = False,

            if 'useraccountcontrol' in _object.keys():
                uac = int(_object.get('useraccountcontrol', 0))
                self.Properties["unconstraineddelegation"] = uac & 0x00080000 == 0x00080000
                self.Properties["passwordnotreqd"] = uac & 0x00000020 == 0x00000020
                self.Properties["enabled"] = uac & 2 == 0
                self.Properties["dontreqpreauth"] = uac & 0x00400000 == 0x00400000
                self.Properties["sensitive"] = uac & 0x00100000 == 0x00100000
                self.Properties["trustedtoauth"] = uac & 0x01000000 == 0x01000000
                self.Properties["pwdneverexpires"] = uac & 0x00010000 == 0x00010000

            if 'lastlogon' in _object.keys():
                self.Properties["lastlogon"] = ADUtils.win_timestamp_to_unix(
                    int(_object.get('lastlogon'))
                )

            if 'lastlogontimestamp' in _object.keys():
                self.Properties["lastlogontimestamp"] = ADUtils.win_timestamp_to_unix(
                    int(_object.get('lastlogontimestamp'))
                )

            if 'pwdlastset' in _object.keys():
                self.Properties["pwdlastset"] = ADUtils.win_timestamp_to_unix(
                    int(_object.get('pwdlastset'))
                )

            if 'useraccountcontrol' in _object.keys():
                self.Properties["dontreqpreauth"] = int(_object.get('useraccountcontrol', 0)) & 0x00400000 == 0x00400000
                self.Properties["pwdneverexpires"] = int(_object.get('useraccountcontrol', 0)) & 0x00010000 == 0x00010000
                self.Properties["sensitive"] = int(_object.get('useraccountcontrol', 0)) & 0x00100000 == 0x00100000

            if 'serviceprincipalname' in _object.keys():
                self.Properties["serviceprincipalnames"] = _object.get('serviceprincipalname').split(',')
                self.Properties['hasspn'] = True
            else:
                self.Properties["serviceprincipalnames"] = []
                self.Properties['hasspn'] = False

            if 'serviceprincipalname' in _object.keys():
                self.Properties["hasspn"] = len(_object.get('serviceprincipalname', [])) > 0

            if 'samaccounttype' in _object.keys():
                self.Properties["samaccounttype"] = _object.get('samaccounttype')
            
            if 'displayname' in _object.keys():
                self.Properties["displayname"] = _object.get('displayname')

            if 'mail' in _object.keys():
                self.Properties["email"] = _object.get('mail')

            if 'title' in _object.keys():
                self.Properties["title"] = _object.get('title')

            if 'homedirectory' in _object.keys():
                self.Properties["homedirectory"] = _object.get('homedirectory')

            if 'description' in _object.keys():
                self.Properties["description"] = _object.get('description')

            if 'userpassword' in _object.keys():
                self.Properties["userpassword"] = ADUtils.ensure_string(_object.get('userpassword'))

            if 'sidhistory' in _object.keys():
                self.Properties["sidhistory"] = [LDAP_SID(bsid).formatCanonical() for bsid in _object.get('sIDHistory', [])]

            if 'msds-allowedtodelegateto' in _object.keys():
                if len(_object.get('msds-allowedtodelegateto', [])) > 0:
                    self.Properties['allowedtodelegate'] = _object.get('msds-allowedtodelegateto', [])

            if 'ntsecuritydescriptor' in _object.keys():
                self.RawAces = _object['ntsecuritydescriptor']

            if 'memberof' in _object.keys():
                self.MemberOfDNs = [f'CN={dn.upper()}' for dn in _object.get('memberof').split(', CN=')]
                if len(self.MemberOfDNs) > 0:
                    self.MemberOfDNs[0] = self.MemberOfDNs[0][3:]

            ### TODO Not supported for the moment
            # self.Properties['displayname'] = None
            # self.Properties['email'] = None
            # self.Properties['title'] = None
            # self.Properties['homedirectory'] = None
            # self.Properties['userpassword'] = None
            # self.Properties['unixpassword'] = None
            # self.Properties['unicodepassword'] = None
            # self.Properties['sfupassword'] = None
            # self.Properties['logonscript'] = None
            # self.Properties['sidhistory'] = []


    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        user = super().to_json(properties_level)

        user["ObjectIdentifier"] = self.ObjectIdentifier
        user["ContainedBy"] = self.ContainedBy
        user["AllowedToDelegate"] = self.AllowedToDelegate
        user["PrimaryGroupSID"] = self.PrimaryGroupSid

        user["Aces"] = self.Aces
        user["SPNTargets"] = self.SPNTargets
        user["HasSIDHistory"] = self.HasSIDHistory
        user["IsACLProtected"] = self.IsACLProtected

        # TODO: RBCD
        # Process resource-based constrained delegation
        # _, aces = parse_binary_acl(data,
        #                            'computer',
        #                            object.get('msDS-AllowedToActOnBehalfOfOtherIdentity'),
        #                            self.addc.objecttype_guid_map)
        # outdata = self.aceresolver.resolve_aces(aces)
        # for delegated in outdata:
        #     if delegated['RightName'] == 'Owner':
        #         continue
        #     if delegated['RightName'] == 'GenericAll':
        #         data['AllowedToAct'].append({'MemberId': delegated['PrincipalSID'], 'MemberType': delegated['PrincipalType']})
        #
        # # Run ACL collection if this was not already done centrally
        # if 'acl' in collect and not skip_acl:
        #     _, aces = parse_binary_acl(data,
        #                                'computer',
        #                                object.get('nTSecurityDescriptor',
        #                                                           raw=True),
        #                                self.addc.objecttype_guid_map)
        #     # Parse aces
        #     data['Aces'] = self.aceresolver.resolve_aces(aces)

        return user
