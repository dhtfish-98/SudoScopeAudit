import unittest
from sudo_scope_audit import analyze
from sudo_scope_audit.common import InputError

class SudoTests(unittest.TestCase):
    def snapshot(self,text,**files):return dict(files={'/etc/sudoers':text,**files})
    def test_narrow_positive(self):
        r=analyze(self.snapshot('Defaults env_reset,use_pty\nalice workstation=(root) PASSWD: /usr/sbin/status-helper'))
        self.assertEqual(r['status'],'PASS')
    def test_multihost_separator_spacing(self):
        for separator in (':', ' :', ': ', ' : ', '\t:\t'):
            with self.subTest(separator=separator):
                text='alice host1=/usr/sbin/status-helper'+separator+'ALL=/usr/sbin/check'
                self.assertEqual(analyze(self.snapshot(text))['status'],'OPEN')
    def test_escaped_colon_command_argument(self):
        self.assertEqual(analyze(self.snapshot(r'alice box=/usr/sbin/helper a\:b'))['status'],'PASS')
    def test_even_backslashes_do_not_escape_host_separator(self):
        self.assertEqual(analyze(self.snapshot(r'alice box=/usr/sbin/helper a\\:ALL=/usr/sbin/check'))['status'],'OPEN')
    def test_inherited_auth_tags(self):
        r=analyze(self.snapshot('alice workstation=(root) NOPASSWD: /usr/sbin/a, /usr/sbin/b, PASSWD: /usr/sbin/c'))
        self.assertEqual([f['status'] for f in r['findings'] if f['check']=='grant_auth'],['FAIL','FAIL','PASS'])
    def test_alias_forward_reference(self):
        r=analyze(self.snapshot('OPS MACHINE = CMDS\nUser_Alias OPS=alice\nHost_Alias MACHINE=workstation\nCmnd_Alias CMDS=/usr/bin/bash'))
        self.assertTrue(any(f['check']=='command_basename' and f['status']=='FAIL' for f in r['findings']))
    def test_alias_cycle(self):
        r=analyze(self.snapshot('Cmnd_Alias A=B\nCmnd_Alias B=A\nalice box=A'));self.assertEqual(r['status'],'OPEN')
    def test_include_cycle(self):
        r=analyze(self.snapshot('#include /etc/sudoers'));self.assertEqual(r['status'],'OPEN')
    def test_includedir_order_and_skip(self):
        r=analyze(self.snapshot('#includedir /etc/sudoers.d',**{'/etc/sudoers.d/good':'alice box=/usr/sbin/check','/etc/sudoers.d/bad.conf':'ALL ALL=ALL'}))
        self.assertEqual(r['status'],'PASS')
    def test_negation_is_unknown(self):
        self.assertEqual(analyze(self.snapshot('alice box=!/usr/sbin/helper'))['status'],'OPEN')
    def test_default_scope_open(self):self.assertEqual(analyze(self.snapshot('Defaults:alice authenticate'))['status'],'OPEN')
    def test_catalog_exact_basename(self):
        self.assertEqual(analyze(self.snapshot('alice box=/usr/bin/bashful'))['status'],'PASS')
    def test_empty_and_bad_types(self):
        self.assertEqual(analyze(self.snapshot(''))['status'],'OPEN')
        with self.assertRaises(InputError):analyze({'files':[]})
    def test_quoted_comma_and_continuation(self):
        self.assertEqual(analyze(self.snapshot('alice box=/usr/sbin/helper "a,b", \\\n /usr/sbin/check'))['status'],'PASS')
    def test_unterminated_quote(self):
        with self.assertRaises(InputError):analyze(self.snapshot('alice box=/usr/sbin/a "oops'))

    def test_include_diamond_budget(self):
        files={"/etc/sudoers":"#include /n0\n#include /n0"}
        for i in range(14):files["/n"+str(i)]="#include /n"+str(i+1)+"\n#include /n"+str(i+1)
        files["/n14"]="alice box=/usr/sbin/check"
        with self.assertRaises(InputError):analyze({"files":files})
    def test_alias_dag_budget(self):
        lines=["Cmnd_Alias A"+str(i)+"=A"+str(i+1)+",A"+str(i+1) for i in range(14)]
        lines += ["Cmnd_Alias A14=/usr/sbin/check","alice box=A0"]
        with self.assertRaises(InputError):analyze(self.snapshot("\n".join(lines)))
    def test_runas_alias_and_undefined(self):
        self.assertEqual(analyze(self.snapshot("alice box=(UNKNOWN) /usr/sbin/check"))["status"],"OPEN")
        self.assertEqual(analyze(self.snapshot("Runas_Alias LIMITED=root\nalice box=(LIMITED) /usr/sbin/check"))["status"],"PASS")
        self.assertEqual(analyze(self.snapshot("alice box=(!root) /usr/sbin/check"))["status"],"OPEN")
    def test_user_list_whitespace(self):
        self.assertEqual(analyze(self.snapshot("alice, bob box=/usr/sbin/check"))["status"],"PASS")

    def test_malformed_include_not_comment(self):
        for directive in ['#include','@include','#includedir','@includedir']:
            with self.assertRaises(InputError):analyze(self.snapshot(directive+'\nalice box=(root) /usr/sbin/helper'))
    def test_boolean_default_assignment_open(self):
        for assignment in ('authenticate=false','use_pty=false','env_reset=false'):
            self.assertEqual(analyze(self.snapshot('Defaults '+assignment+'\nalice box=/usr/sbin/helper'))['status'],'OPEN')
