"""Syntactic sudoers risk review over supplied files, never privilege evaluation."""
import json
import posixpath
import re
from importlib.resources import files as resources
from .common import InputError, Report, filemap, logical_lines, mapping, string

LIMITS = ["Syntactic grants only; no NSS, netgroups, host membership, filesystem permissions or effective sudo authorization is inferred.",
          "Digests, command regexes, per-scope Defaults, negation semantics, and multi-host grant segments are explicitly OPEN."]

def parts(value):
    result, token, quote, escape = [], "", None, False
    for char in value:
        if escape:
            token += "\\" + char; escape = False
        elif char == "\\":
            escape = True
        elif quote:
            token += char
            if char == quote: quote = None
        elif char in "\"'":
            quote = char; token += char
        elif char == ',':
            result.append(token.strip()); token = ""
        else: token += char
    if escape or quote: raise InputError("unterminated sudoers quote or escape")
    result.append(token.strip())
    if any(not p for p in result): raise InputError("empty sudoers list item")
    return result

def uncomment(line):
    quote, escape = None, False
    for i, char in enumerate(line):
        if escape: escape = False; continue
        if char == "\\": escape = True; continue
        if quote:
            if char == quote: quote = None
        elif char in "\"'": quote = char
        elif char == '#' and (i == 0 or line[i-1].isspace()) and not (i+1 < len(line) and line[i+1].isdigit()):
            return line[:i].strip()
    return line.strip()

def analyze(snapshot):
    mapping(snapshot, "snapshot")
    data = filemap(snapshot.get("files")); entry = string(snapshot.get("entry", "/etc/sudoers"), "entry")
    report = Report("SudoScopeAudit", "Complete supplied include graph, aliases, Defaults and syntactic grants")
    rows, visiting = [], []
    budget = {"references": 0, "rows": 0}
    def spend(kind):
        budget[kind] += 1
        if budget[kind] > 10000: raise InputError("sudo expansion budget exceeded: " + kind)
    def visit(path):
        spend("references")
        if path in visiting or len(visiting) >= 32:
            report.add("include_graph", "OPEN", path, "Include cycle or depth limit"); return
        if path not in data:
            report.add("include_graph", "OPEN", path, "Referenced snapshot file missing"); return
        visiting.append(path)
        for number, raw in logical_lines(data[path]):
            spend("rows")
            line = raw.strip(); where = path + ":" + str(number)
            inc = re.match(r'^(?:#|@)(include|includedir)\s+(.+)$', line)
            if re.match(r'^(?:#|@)(?:include|includedir)\b', line) and not inc:
                raise InputError('malformed sudoers include at ' + where)
            if inc:
                target = inc[2].strip('"')
                target = posixpath.normpath(target if target.startswith('/') else posixpath.join(posixpath.dirname(path), target))
                if inc[1] == 'include': visit(target)
                else:
                    children = sorted(p for p in data if posixpath.dirname(p) == target and '.' not in posixpath.basename(p) and not p.endswith('~'))
                    if not children: report.add("include_graph", "OPEN", where, "Include directory empty or missing in snapshot")
                    for child in children: visit(child)
                continue
            line = uncomment(line)
            if line: rows.append((where, line))
        visiting.pop()
    visit(entry)
    aliases = {kind: {} for kind in ('User', 'Host', 'Runas', 'Cmnd')}; grants = []
    for where, line in rows:
        alias = re.match(r'^(User|Host|Runas|Cmnd)_Alias\s+([A-Z][A-Z0-9_]*)\s*=\s*(.+)$', line)
        if alias:
            kind, name, value = alias.groups()
            if name in aliases[kind]: report.add("alias_duplicate", "FAIL", where, "Duplicate alias " + name)
            aliases[kind][name] = parts(value); continue
        if line.startswith('Defaults'):
            match = re.fullmatch(r'Defaults\s+(.+)', line)
            if not match:
                report.add("defaults_scope", "OPEN", where, "Scoped Defaults unsupported"); continue
            for item in parts(match[1]):
                key = item.split('=', 1)[0].strip()
                if '=' in item:
                    report.add('defaults_unsupported','OPEN',where,'Valued Defaults semantics not evaluated');continue
                if key in ('!authenticate', '!env_reset', 'setenv'):
                    report.add("defaults_risk", "FAIL", where, "Relaxed default: " + key)
                elif key in ('authenticate', 'env_reset', '!setenv', 'use_pty', 'log_input', 'log_output'):
                    report.add("defaults_risk", "PASS", where, "Explicit defensive default: " + key)
                else: report.add("defaults_unsupported", "OPEN", where, "Unassessed default: " + item)
            continue
        grant = re.fullmatch(r'([^\s,]+(?:\s*,\s*[^\s,]+)*)\s+([^=]+?)\s*=\s*(.*)', line)
        if not grant:
            report.add("syntax", "OPEN", where, "Unrecognized sudoers construct"); continue
        users, hosts, commands = grant.groups()
        runas = None
        if commands.startswith('('):
            end = commands.find(')')
            if end < 0: raise InputError("unterminated runas list")
            runas = commands[1:end]; commands = commands[end+1:].strip()
        grants.append((where, parts(users), parts(hosts), runas, parts(commands)))
    def resolve(kind, token, trail=()):
        spend("references")
        if token.startswith('!'):
            report.add("negation", "OPEN", token, "Negated entries need effective policy evaluation"); return []
        if token in aliases[kind]:
            if token in trail or len(trail) >= 32:
                report.add("alias_cycle", "OPEN", token, "Alias cycle/depth limit"); return []
            return [x for item in aliases[kind][token] for x in resolve(kind, item, trail+(token,))]
        if re.fullmatch(r'[A-Z][A-Z0-9_]*', token) and token != 'ALL':
            report.add("alias_missing", "OPEN", token, "Undefined alias"); return []
        return [token]
    risky = set(json.loads(resources(__package__).joinpath('risky_commands.json').read_text()))
    for where, users, hosts, runas, commands in grants:
        subjects = [v for x in users for v in resolve('User', x)]
        targets = [v for x in hosts for v in resolve('Host', x)]
        report.check("subject_scope", 'ALL' not in subjects, where, "Subjects: " + ','.join(subjects))
        report.check("host_scope", 'ALL' not in targets, where, "Hosts: " + ','.join(targets))
        if runas is not None:
            segments = runas.split(':')
            if len(segments) > 2: raise InputError("malformed runas list")
            for index, segment in enumerate(segments):
                if not segment.strip():
                    report.add("runas_identity", "OPEN", where, "Implicit invoking identity needs context"); continue
                identities = [v for item in parts(segment) for v in resolve('Runas', item)]
                report.check("runas_scope", 'ALL' not in identities, where,
                             ("Runas users: " if index == 0 else "Runas groups: ") + ','.join(identities))
        tags = set()
        for item in commands:
            tag = re.match(r'^((?:(?:NOPASSWD|PASSWD|SETENV|NOSETENV|NOEXEC|EXEC|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT):\s*)+)(.*)$', item)
            if tag:
                for value in re.findall(r'([A-Z_]+):', tag[1]):
                    for group in [('NOPASSWD','PASSWD'),('SETENV','NOSETENV')]:
                        if value in group: tags.difference_update(group)
                    tags.add(value)
                item = tag[2]
            if not item: raise InputError("empty tagged command")
            report.check("grant_auth", 'NOPASSWD' not in tags, where, "Password authentication tag")
            report.check("grant_environment", 'SETENV' not in tags, where, "Environment override tag")
            for command in resolve('Cmnd', item):
                if command == 'ALL': report.add("command_scope", "FAIL", where, "Unrestricted command grant"); continue
                if command.startswith('^') or re.match(r'^sha\d+:', command) or ' : ' in command:
                    report.add("command_semantics", "OPEN", where, "Digest/regex/multi-host syntax unsupported"); continue
                executable = command.split()[0].replace('\\', '')
                if not executable.startswith('/'):
                    report.add("command_semantics", "OPEN", where, "Executable path or alias unresolved"); continue
                report.check("command_basename", posixpath.basename(executable) not in risky, where, "Risk catalog basename: " + executable)
                report.check("command_location", not executable.startswith(('/tmp/','/home/','/etc/','/var/tmp/')), where, "Executable location: " + executable)
                report.check("command_wildcard", not any(c in command for c in '*?['), where, "Command contains broad pattern" if any(c in command for c in '*?[') else "No command pattern")
    if not grants: report.add("grants", "OPEN", entry, "No grants available to assess")
    return report.finish(LIMITS)
