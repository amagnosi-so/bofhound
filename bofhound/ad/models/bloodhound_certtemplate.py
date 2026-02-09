from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
import ast
import base64

from bofhound.ad.helpers.cert_utils import OID_TO_STR_MAP, MS_PKI_CERTIFICATE_NAME_FLAG, MS_PKI_PRIVATE_KEY_FLAG, MS_PKI_ENROLLMENT_FLAG, filetime_to_span, span_to_str
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundCertTemplate(BloodHoundObject):
    GUI_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'isaclprotected',
        'description', 'whencreated', 'validityperiod', 'renewalperiod',
        'schemaversion', 'displayname', 'oid', 'enrollmentflag', 'requiresmanagerapproval',
        'nosecurityextension', 'certificatenameflag', 'enrolleesuppliessubject', 'subjectaltrequireupn',
        'subjectaltrequiredns', 'subjectaltrequiredomaindns', 'subjectaltrequireemail',
        'subjectaltrequirespn', 'subjectrequireemail', 'ekus', 'certificateapplicationpolicy',
        'authorizedsignatures', 'applicationpolicies', 'issuancepolicies', 'effectiveekus',
        'authenticationenabled'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, _object):

        super().__init__(_object)

        self._entry_type = "PKI Template"
        self.GPLinks = []
        self.ContainedBy = {}
        self.IsACLProtected = False
        self.cas_ids = []

        if 'objectguid' in _object.keys():
            self.ObjectIdentifier = _object.get("objectguid").upper()

        if 'distinguishedname' in _object.keys():
            domain = ADUtils.ldap2domain(_object.get('distinguishedname')).upper()
            self.Properties['domain'] = domain
            self.Properties['distinguishedname'] = _object.get('distinguishedname').upper()
            self.Properties['name'] = self.get_cn_from_dn(_object.get('distinguishedname')) + "@" + domain

        if 'description' in _object.keys():
            self.Properties['description'] = _object.get('description')
        else:
            self.Properties['description'] = None

        if 'pkiexpirationperiod' in _object.keys():
            pKIExpirationPeriod_b64 = _object.get("pkiexpirationperiod")
            pKIExpirationPeriod_byte_array = base64.b64decode(pKIExpirationPeriod_b64)
            self.Properties["validityperiod"] = span_to_str(filetime_to_span(pKIExpirationPeriod_byte_array))

        if 'pkioverlapperiod' in _object.keys():
            pKIRenewalPeriod_b64 = _object.get("pkioverlapperiod")
            pKIRenewalPeriod_byte_array = base64.b64decode(pKIRenewalPeriod_b64)
            self.Properties["renewalperiod"] = span_to_str(filetime_to_span(pKIRenewalPeriod_byte_array))

        if 'mspki-template-schema-version' in _object.keys():
            self.Properties['schemaversion'] = int(_object.get('mspki-template-schema-version'))

        if 'displayname' in _object.keys():
            self.Properties["displayname"] = _object.get("displayname")

        if 'mspki-cert-template-oid' in _object.keys():
            self.Properties["oid"] = _object.get("mspki-cert-template-oid")

        if 'mspki-enrollment-flag' in _object.keys():
            enrollment_flag = _object.get("mspki-enrollment-flag")
            if enrollment_flag is not None:
                enrollment_flag = MS_PKI_ENROLLMENT_FLAG(int(enrollment_flag))
            else:
                enrollment_flag = MS_PKI_ENROLLMENT_FLAG(0)
            self.Properties["enrollmentflag"] = ', '.join(enrollment_flag.to_str_list())

            requires_manager_approval = (
                MS_PKI_ENROLLMENT_FLAG.PEND_ALL_REQUESTS in enrollment_flag
            )
            self.Properties["requiresmanagerapproval"] = requires_manager_approval

            no_security_extension = (
                MS_PKI_ENROLLMENT_FLAG.NO_SECURITY_EXTENSION in enrollment_flag
            )
            self.Properties["nosecurityextension"] = no_security_extension
        
        if 'mspki-certificate-name-flag' in _object.keys():
            certificate_name_flag = _object.get('mspki-certificate-name-flag')
            if certificate_name_flag is not None:
                certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(
                    int(certificate_name_flag)
                )
            else:
                certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(0)
            self.Properties["certificatenameflag"] = ", ".join(certificate_name_flag.to_str_list())

            enrollee_supplies_subject = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT,
                ]
            )
            self.Properties["enrolleesuppliessubject"] = enrollee_supplies_subject

            subjectaltrequireupn = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.SUBJECT_ALT_REQUIRE_UPN,
                ]
            )
            self.Properties["subjectaltrequireupn"] = subjectaltrequireupn

            subjectaltrequiredns = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.SUBJECT_ALT_REQUIRE_DNS,
                ]
            )
            self.Properties["subjectaltrequiredns"] = subjectaltrequiredns

            subjectaltrequiredomaindns = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.SUBJECT_ALT_REQUIRE_DOMAIN_DNS,
                ]
            )
            self.Properties["subjectaltrequiredomaindns"] = subjectaltrequiredomaindns

            subjectaltrequireemail = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.SUBJECT_ALT_REQUIRE_EMAIL,
                ]
            )
            self.Properties["subjectaltrequireemail"] = subjectaltrequireemail

            subjectaltrequirespn = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.SUBJECT_ALT_REQUIRE_SPN,
                ]
            )
            self.Properties["subjectaltrequirespn"] = subjectaltrequirespn

            subjectrequireemail = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.SUBJECT_REQUIRE_EMAIL,
                ]
            )
            self.Properties["subjectrequireemail"] = subjectrequireemail

        ekus = []
        if 'pkiextendedkeyusage' in _object.keys():
            ekus = _object.get('pkiextendedkeyusage').split(', ')

            ### This parses ekus to readable format
            #ekus = list(
            #    map(lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x, ekus)
            #)
            self.Properties["ekus"] = ekus

            ### Not needed anymore
            #any_purpose = (
            #    "Any Purpose" in ekus or len(ekus) == 0
            #)
            #client_authentication = any_purpose or any(
            #    eku in ekus
            #    for eku in [
            #        "Client Authentication",
            #        "Smart Card Logon",
            #        "PKINIT Client Authentication",
            #    ]
            #)
            #enrollment_agent = any_purpose or any(
            #    eku in ekus
            #    for eku in [
            #        "Certificate Request Agent",
            #    ]
            #)

            #self.Properties["Client Authentication"] = client_authentication
            #self.Properties["Enrollment Agent"] = enrollment_agent            
            #self.Properties["Any Purpose"] = any_purpose
        
        #self.Properties["Certificate Authorities"] = []
        #self.Properties["Enabled"] = True

        if 'mspki-certificate-application-policy' in _object.keys():
            self.Properties['certificateapplicationpolicy'] = _object.get('mspki-certificate-application-policy').split(', ')
        else:
            self.Properties['certificateapplicationpolicy'] = []
            
        if 'mspki-ra-signature' in _object.keys():
            authorized_signatures_required = _object.get("mspki-ra-signature")
            if authorized_signatures_required is not None:
                authorized_signatures_required = int(authorized_signatures_required)
            else:
                authorized_signatures_required = 0
            self.Properties["authorizedsignatures"] = authorized_signatures_required
            


        self.Properties['applicationpolicies'] = []
        if 'mspki-private-key-flag' in _object.keys():
            private_key_flag = _object.get("mspki-private-key-flag")
            if private_key_flag is not None:
                private_key_flag = MS_PKI_PRIVATE_KEY_FLAG(int(private_key_flag))
            else:
                private_key_flag = MS_PKI_PRIVATE_KEY_FLAG(0)

        if 'mspki-ra-application-policies' in _object.keys():
            applicationpolicies = _object.get('mspki-ra-application-policies')
            schemaversions_noparsing = [0, 1, 2]

            hasUseLegacyProvider = (
                MS_PKI_PRIVATE_KEY_FLAG.USE_LEGACY_PROVIDER in private_key_flag
            )

            if ('schemaversion' in self.Properties and 
              (self.Properties['schemaversion'] in schemaversions_noparsing or
              (self.Properties['schemaversion'] == 4 and hasUseLegacyProvider))):
                self.Properties['applicationpolicies'] = applicationpolicies
            
            else:
                # Divide entries into groups of three, filter, and select third element
                result = [parts[2] for parts in (applicationpolicies[i*3:i*3+3] for i in range(len(applicationpolicies)//3))
                        if len(parts) == 3 and parts[0] == 'mspki-ra-application-policies']

                # Convert the result to an array
                result_array = list(result)
                self.Properties['applicationpolicies'] = result_array

        if 'mspki-ra-policies' in _object.keys():
            self.Properties['issuancepolicies'] = _object.get('mspki-ra-policies').split(', ')
        else:
            self.Properties['issuancepolicies'] = []

        if ('schemaversion' in self.Properties and self.Properties['schemaversion'] == 1 and len(ekus)>0):
            self.Properties['effectiveekus'] = ekus
        elif self.Properties['certificateapplicationpolicy']:
            self.Properties['effectiveekus'] = self.Properties['certificateapplicationpolicy']
        else:
            self.Properties['effectiveekus'] = []
        
        AuthenticationOIDs = ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0']
        self.Properties['authenticationenabled'] = bool(set(self.Properties['effectiveekus']).intersection(AuthenticationOIDs)) or len(self.Properties['effectiveekus']) == 0

        if 'ntsecuritydescriptor' in _object.keys():
            self.RawAces = _object['ntsecuritydescriptor']

    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        data = super().to_json(properties_level)
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["ContainedBy"] = self.ContainedBy
        data["Aces"] = self.Aces
        data['IsACLProtected'] = self.IsACLProtected
        data["cas_ids"] = self.cas_ids
        return data