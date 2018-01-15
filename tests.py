import unittest

import checkdmarc

known_good_domains = [
    "fbi.gov",
    "dhs.gov",
    "paypal.com",
    "google.com",
    "microsoft.com",
    "amazon.com"
]


class Test(unittest.TestCase):
    def testKnownGood(self):
        """Testing domains with known SPF and DMARC records"""
        results = checkdmarc.check_domains(known_good_domains)
        for domain in results:
            spf_error = None
            dmarc_error = None
            if "error" in domain["spf"]:
                spf_error = domain["spf"]["error"]
            if "error" in domain["dmarc"]:
                dmarc_error = domain["dmarc"]["error"]
            self.assertEqual(domain["spf"]["valid"], True, "Known good domain {0} failed SPF check: {0}".format(
                domain["domain"], spf_error))
            self.assertEqual(domain["dmarc"]["valid"], True, "Known good domain {0} failed DMARC check: {1}".format(
                domain["domain"], dmarc_error))

    def testIncludeMissingSPF(self):
        """SPF records that include domains that are missing SPF records raise SPFRecordNotFound"""
        spf_record = '"v=spf1 include:spf.comendosystems.com include:bounce.peytz.dk include:etrack.indicia.dk ' \
                     'include:etrack1.com include:mail1.dialogportal.com ' \
                     'include:mail2.dialogportal.com a:mailrelay.jppol.dk a:sendmail.jppol.dk ?all"'
        domain = "ekstrabladet.dk"
        self.assertRaises(checkdmarc.SPFRecordNotFound, checkdmarc.parse_spf_record, spf_record, domain)

    def testTooManySPFDNSLookups(self):
        """SPF records with > 10 SPF mechanisms that cause DNS lookups raise SPFTooManyDNSLookups"""
        spf_record = "v=spf1 ip4:205.131.177.0/24 ip4:205.131.188.0/24 ip4:73.23.28.0/24 ip4:137.227.97.89/32 " \
                     "ip4:137.227.97.90/32 ip4:137.227.196.62/32 ip4:137.227.28.0/24 ip4:137.227.82.0/24 " \
                     "ip4:198.183.146.165/32 ip6:2620:109:20:2000::0141 ip6:2620:109:20:2000::0158 " \
                     "ip6:2620:109:0:2000::251  include:leepfrog.com include:spf.mailengine1.com " \
                     "include:monster.com include:accenture.com include:usalearning.net " \
                     "include:MAAS360.com include:MAAS360.info include:Fiberlink.com -all"
        domain = "opm.gov"
        self.assertRaises(checkdmarc.SPFTooManyDNSLookups, checkdmarc.parse_spf_record, spf_record, domain)

    def testSPFSyntaxErrors(self):
        """SPF record syntax errors raise SPFSyntaxError"""
        spf_record = '"v=spf1 mx a:mail.cohaesio.net include: trustpilotservice.com ~all"'
        domain = "surftown.dk"
        self.assertRaises(checkdmarc.SPFSyntaxError, checkdmarc.parse_spf_record, spf_record, domain)

    def testSPFIncludeLoop(self):
        """SPF record with include loop raises SPFIncludeLoop"""
        spf_record = '"v=spf1 mx a ip4:213.161.174.26 a:spf.protection.outlook.com include:berlevag.kommune.no ~all"'
        domain = "kommune.no"
        self.assertRaises(checkdmarc.SPFIncludeLoop, checkdmarc.parse_spf_record, spf_record, domain)

    def testSPFMissingMXRecord(self):
        """A warning is issued if a SPF record contains a mx mechanism pointing to a domain that has no MX records"""
        spf_record = '"v=spf1 mx a mx:mail.hhj.no ~all"'
        domain = "pario.no"
        results = checkdmarc.parse_spf_record(spf_record, domain)
        self.assertIn("mail.hhj.no does not have any MX records", results["warnings"])

    def testSPFMissingARecord(self):
        """A warning is issued if a SPF record contains a mx mechanism pointing to a domain that has no A records"""
        spf_record = '"v=spf1 include:_spf.bibsyst.no a mx ~all"'
        domain = "sogne.folkebibl.no"
        results = checkdmarc.parse_spf_record(spf_record, domain)
        self.assertIn("sogne.folkebibl.no does not have any A/AAAA records", results["warnings"])

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(Test)
    unittest.TextTestRunner(verbosity=2).run(suite)