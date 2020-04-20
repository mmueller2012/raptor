#!/usr/bin/python3
#
# Tool to manage Debian/Ubuntu repositories.
#
# Copyright (C) 2017 Michael Müller
# Copyright (C) 2017 Sebastian Lackner
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#

import argparse
import json
import os
import sys
import hashlib
import gzip
import bz2
import lzma
import shutil
import subprocess

from email.utils import formatdate
from debian.debfile import DebFile

def create_dir(path):
    try:
        os.mkdir(path, mode=0o755)
    except FileExistsError:
        pass

def hash_file(path, hasher_cls):
    hasher = hasher_cls()

    with open(path, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)

    return hasher.hexdigest()

def hash_bytes(data, hasher_cls):
    hasher = hasher_cls()
    hasher.update(data)
    return hasher.hexdigest()

def load_config(path):
    def check_single_word(test_str):
        space_chars = [' ', '\t', '\n']
        if any(s in test_str for s in space_chars):
            return False
        return True

    # Not all of them are required by Debian, but it makes things easier
    required_fields = [
        "Origin",
        "Label",
        "Suite",
        "Codename",
        "Version",
        "Architectures",
        "Components",
        "Description",
    ]

    with open(path, "r") as fp:
        config = json.load(fp)

    for distro in config:
        # Verify that we got all fields
        for field in required_fields:
            if field not in distro:
                raise RuntimeError("Configuration field %s missing in distro config" % field)

        # Verify that Architectures and Components are non empty
        if not len(distro["Architectures"]):
            raise RuntimeError("No architectures defined")
        if not len(distro["Components"]):
            raise RuntimeError("No components defined")

        # Verify some requirements described at https://wiki.debian.org/RepositoryFormat
        if "\n" in distro["Origin"]:
            raise RuntimeError("Origin must not contain line breaks")
        if "\n" in distro["Label"]:
            raise RuntimeError("Label must not contain line breaks")
        if not check_single_word(distro["Suite"]):
            raise RuntimeError("Suite must be a single word: %s" % distro["Suite"])
        if not check_single_word(distro["Codename"]):
            raise RuntimeError("Codename must be a single word: %s" % distro["Codename"])
        if any(not check_single_word(arch) for arch in distro["Architectures"]):
            raise RuntimeError("Architectures must consist of a single word")
        if any(not check_single_word(comp) for comp in distro["Components"]):
            raise RuntimeError("Components must consist of a single word")

    # Verify that codename and suite are unique
    suites = set()
    codenames = set()
    for distro in config:
        if distro["Codename"] in codenames:
            raise RuntimeError("Codename %s is not unique" % distro["Codename"])
        if distro["Suite"] in suites:
            raise RuntimeError("Suite %s is not unique" % distro["Suite"])

        codenames.add(distro["Codename"])
        suites.add(distro["Suite"])

    return config

def init_dirs(repodir, config):
    if not os.path.isdir(repodir):
        raise RuntimeError("%s is not a directory" % repodir)
    if os.path.exists(os.path.join(repodir, "conf", "distributions")):
        raise RuntimeError("%s has incompatible repository format" % repodir)

    dists_dir = os.path.join(repodir, "dists")
    pool_dir  = os.path.join(repodir, "pool")

    create_dir(dists_dir)
    create_dir(pool_dir)
    create_dir(os.path.join(repodir, ".cache"))

    for distro in config:
        distro_dir = os.path.join(dists_dir, distro["Codename"])
        create_dir(distro_dir)

        suite_symlink = os.path.join(dists_dir, distro["Suite"])

        if os.path.islink(suite_symlink) and os.path.realpath(suite_symlink) != os.path.realpath(distro_dir):
            os.unlink(suite_symlink)

        try:
            os.symlink(distro["Codename"], suite_symlink, target_is_directory=True)
        except FileExistsError:
            pass

        for component in distro["Components"]:
            create_dir(os.path.join(pool_dir, component))

            comp_dir = os.path.join(distro_dir, component)
            create_dir(comp_dir)

            for architecture in distro["Architectures"]:
                create_dir(os.path.join(comp_dir, "binary-%s" % architecture))

def load_cache(repodir):
    cachefile = os.path.join(repodir, ".cache", "packages")
    try:
        with open(cachefile, "r") as fp:
            return json.load(fp)
    except FileNotFoundError:
        return {}

def save_cache(repodir, cache):
    cachefile     = os.path.join(repodir, ".cache", "packages")
    cachefile_tmp = os.path.join(repodir, ".cache", "packages-tmp")

    with open(cachefile_tmp, "w") as fp:
        json.dump(cache, fp, indent=4)

    os.rename(cachefile_tmp, cachefile)

def get_distro(config, codename):
    for distro in config:
        if distro["Codename"] == codename:
            return distro
    raise RuntimeError("Could not find codename %s" % codename)

def get_packages(cache, codename, component, arch):
    if codename not in cache:
        cache[codename] = {}

    if arch not in cache[codename]:
        cache[codename][arch] = {}

    return cache[codename][arch]

def get_package_versions(cache, codename, component, arch, name):
    packages = get_packages(cache, codename, component, arch)

    if name not in packages:
        packages[name] = {}

    return packages[name]

def add_package_to_cache(config, cache, codename, component, package):
    distro = get_distro(config, codename)
    if component not in distro["Components"]:
        raise RuntimeError("Can not add package %s, component %s not supported by the repository" % (package, component))

    deb = DebFile(filename=package)
    fields = deb.debcontrol()
    arch = fields["Architecture"]

    if arch not in distro["Architectures"]:
        raise RuntimeError("Can not add package %s, architecture not supported by the repository" % package)

    fields["SHA256"]   = hash_file(package, hashlib.sha256)
    fields["SHA1"]     = hash_file(package, hashlib.sha1)
    fields["MD5sum"]   = hash_file(package, hashlib.md5)
    fields["Size"]     = str(os.path.getsize(package))
    fields["Filename"] = "pool/%s/%s" % (component, os.path.basename(package))

    packages = get_package_versions(cache, codename, component, arch, fields["Package"])
    if fields["Version"] in packages:
        raise RuntimeError("Package %s with version %s already exists in the repository" % (fields["Package"], fields["version"]))

    # convert dict like object to tuple to keep original sorting in json file
    packages[fields["Version"]] = [(field, fields[field]) for field in fields]

    print ("-> Adding %s=%s to cache for %s/%s" % (fields["Package"], fields["Version"], codename, arch))
    return fields["Filename"]

def generate_arch_release(distro, component, architecture):
    content = ""

    content += "Archive: %s\n"      % distro["Suite"]
    content += "Version: %s\n"      % distro["Version"]
    content += "Component: %s\n"    % component
    content += "Origin: %s\n"       % distro["Origin"]
    content += "Label: %s\n"        % distro["Label"]
    content += "Architecture: %s\n" % architecture
    content += "Description: %s\n"  % distro["Description"]

    return content.encode("utf-8")

def generate_arch_packages(packages):
    content = ""

    for package_name, versions in sorted(packages.items()):
        for version, package in sorted(versions.items()):
            for (field, value) in package:
                content += "%s: %s\n" % (field, value)
            content += "\n"

    return content.encode("utf-8")

def format_release_date():
    date_str = formatdate()
    if not date_str.endswith("-0000"):
        raise RuntimeError("formatdate() returned invalid date: %s" % date_str)

    # Debian requires the timezone offset to be written as +0000 instead of -0000
    date_str = date_str[:-5] + "+0000"
    return date_str

def generate_distro_release(distro, files):
    content = ""

    content += "Origin: %s\n"        % distro["Origin"]
    content += "Label: %s\n"         % distro["Label"]
    content += "Suite: %s\n"         % distro["Suite"]
    content += "Version: %s\n"       % distro["Version"]
    content += "Codename: %s\n"      % distro["Codename"]
    content += "Date: %s\n"          % format_release_date()
    content += "Architectures: %s\n" % " ".join(distro["Architectures"])
    content += "Components: %s\n"    % " ".join(distro["Components"])
    content += "Description: %s\n"   % distro["Description"]

    content += "MD5Sum:\n"
    for filename, data in files.items():
        content += " %s %s %s\n" % (hash_bytes(data, hashlib.md5), len(data), filename)

    content += "SHA1:\n"
    for filename, data in files.items():
        content += " %s %s %s\n" % (hash_bytes(data, hashlib.sha1), len(data), filename)

    content += "SHA256:\n"
    for filename, data in files.items():
        content += " %s %s %s\n" % (hash_bytes(data, hashlib.sha256), len(data), filename)

    content += "\n"
    return content.encode("utf-8")

def check_output_with_input(*popenargs, **kwargs):
    if 'stdout' in kwargs or 'stdin' in kwargs:
        raise ValueError('stdout/stdin argument not allowed')

    input = kwargs['input']
    del kwargs['input']

    process = subprocess.Popen(stdout=subprocess.PIPE, stdin=subprocess.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate(input)
    retcode = process.poll()

    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        error = subprocess.CalledProcessError(retcode, cmd)
        error.output = output
        raise error

    return output

def generate_distro_files(cache, distro, gpg_key):
    files = {}

    for component in distro["Components"]:
        for arch in distro["Architectures"]:
            arch_dir = os.path.join(component, "binary-%s" % arch)
            packages = get_packages(cache, distro["Codename"], component, arch)

            files[os.path.join(arch_dir, "Release")]  = generate_arch_release(distro, component, arch)

            package_content = generate_arch_packages(packages)
            files[os.path.join(arch_dir, "Packages")] = package_content
            files[os.path.join(arch_dir, "Packages.gz")]  = gzip.compress(package_content)
            files[os.path.join(arch_dir, "Packages.bz2")] = bz2.compress(package_content)
            files[os.path.join(arch_dir, "Packages.xz")]  = lzma.compress(package_content, format=lzma.FORMAT_XZ)

    files["Release"] = generate_distro_release(distro, files)
    if gpg_key:
        files["InRelease"]   = check_output_with_input(["gpg", "--yes", "--clear-sign",
                                                        "-u", gpg_key, "--armor"], input=files["Release"])
        files["Release.gpg"] = check_output_with_input(["gpg", "--yes", "--detach-sign",
                                                        "-u", gpg_key, "--armor"], input=files["Release"])

    return files

def generate_files(cache, config, gpg_key):
    files = {}

    for distro in config:
        distro_files = generate_distro_files(cache, distro, gpg_key)

        for filename, data in distro_files.items():
            files[os.path.join("dists", distro["Codename"], filename)] = data

    return files

def verify_debs(repodir, cache, remove_missing=False, verify_checksums=False):
    def get_field(fields, name):
        for field_name, value in fields:
            if field_name == name:
                return value
        raise RuntimeError("Could not find field %s" % name)

    ret = True
    for codename, architectures in cache.items():
        for arch, packages in architectures.items():
            for name, versions in packages.items():

                version_remove = []
                for version, fields in versions.items():
                    filename = get_field(fields, "Filename")
                    debfile = os.path.join(repodir, filename)

                    if not os.path.isfile(debfile):
                        print ("WARNING: Could no find file %s" % filename)
                        if remove_missing:
                            version_remove.append(version)
                        else:
                            ret = False

                    elif verify_checksums:
                        if hash_file(debfile, hashlib.md5) != get_field(fields, "MD5sum"):
                            print ("MD5 checksum does not match for %s" % filename)
                            ret = False
                        if hash_file(debfile, hashlib.sha1) != get_field(fields, "SHA1"):
                            print ("SHA1 checksum does not match for %s" % filename)
                            ret = False
                        if hash_file(debfile, hashlib.sha256) != get_field(fields, "SHA256"):
                            print ("SHA256 checksum does not match for %s" % filename)
                            ret = False

                for version in version_remove:
                    print ("-> Removing %s=%s from cache for %s/%s" % (name, version, codename, arch))
                    del versions[version]

    return ret

def repo_update(repodir, config, gpg_key, codename=None, component=None, new_packages=None):
    init_dirs(repodir, config)
    cache = load_cache(repodir)

    copy_files = []
    if new_packages:
        if not codename:
            raise ValueError("codename must be set when adding new packages")
        if not component:
            raise ValueError("component must be set when adding new packages")

        for package in new_packages:
            dest = add_package_to_cache(config, cache, codename, component, package)
            copy_files.append((package, os.path.join(repodir, dest)))

    files = generate_files(cache, config, gpg_key)

    for src, dst in copy_files:
        shutil.copy(src, dst)

    for filename, data in files.items():
        with open(os.path.join(repodir, filename), "wb") as fp:
            fp.write(data)

    save_cache(repodir, cache)

def repo_verify(repodir, remove_missing):
    if not os.path.isdir(repodir):
        raise RuntimeError("%s is not a directory" % repodir)
    create_dir(os.path.join(repodir, ".cache"))
    cache = load_cache(repodir)

    ret = verify_debs(repodir, cache, remove_missing=remove_missing, verify_checksums=True)

    save_cache(repodir, cache)

    if not ret:
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Raptor")
    parser.add_argument('--repodir',   help="Path to the repository", required=True)
    parser.add_argument('--config',    help="Path to distro config", required=False)
    parser.add_argument('--gpgkey',    help="Key used for signing the repository data", required=False)

    subparsers = parser.add_subparsers(dest="command")

    add_parser = subparsers.add_parser('add', help="Add new packages")
    add_parser.add_argument('--component', default="main", help="Component for the package")
    add_parser.add_argument('codename',    help="Codename of the distro packages")
    add_parser.add_argument('packages',    nargs='+', help="Packages to add")

    update_parser = subparsers.add_parser('update', help="Regenerate metadata")

    verify_parser = subparsers.add_parser('verify', help="Verify deb files against metadata")
    verify_parser.add_argument('--remove', action="store_true", help="Remove missing packages from cache")

    args = parser.parse_args()

    if args.command == "add":
        if not args.config:
            raise RuntimeError("You need to specify a config to add a package")
        config = load_config(args.config)
        repo_update(args.repodir, config, args.gpgkey, args.codename, args.component, args.packages)
    elif args.command == "update":
        if not args.config:
            raise RuntimeError("You need to specify a config to update the repo")
        config = load_config(args.config)
        repo_update(args.repodir, config, args.gpgkey)
    elif args.command == "verify":
        repo_verify(args.repodir, args.remove)
    else:
        raise NotImplementedError("Unimplemented command?")

if __name__ == '__main__':
    main()
