#
# Copyright 2016 Edward Tomasz Napierala
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################


import crypt
import errno
from libc.time cimport time, time_t
from posix.unistd cimport uid_t, gid_t


cdef extern from "<rpcsvc/ypclnt.h>":
    cdef struct ypall_callback:
        int (*foreach)(unsigned long, char *, int, char *, int, void *)
        void *data

    int yp_bind(char *dom)
    void yp_unbind(char *dom)
    int yp_get_default_domain(char **domp)
    int yp_all(char *indomain, char *inmap, ypall_callback *incallback)
    int yp_match(char *indomain, char *inmap, const char *inkey, int inkeylen, char **outval, int *outvallen)
    const char *yperr_string(int incode)


cdef extern from "<ypclnt.h>":
    ctypedef ypclnt ypclnt_t

    cdef struct ypclnt:
        char *domain
        char *mapname
        char *server
        char *error


cdef extern from "<pwd.h>":
    cdef struct passwd:
        char *pw_name
        char *pw_passwd
        uid_t pw_uid
        gid_t pw_gid
        time_t pw_change
        char *pw_class
        char *pw_gecos
        char *pw_dir
        char *pw_shell
        time_t pw_expire
        int pw_fields

    ypclnt_t *ypclnt_new(const char *, const char *, const char *)
    void ypclnt_free(ypclnt_t *)
    int ypclnt_connect(ypclnt_t *)
    int ypclnt_havepasswdd(ypclnt_t *)
    int ypclnt_passwd(ypclnt_t *, const passwd *, const char *)


cdef int ypcat_foreach(unsigned long instatus, char *inkey, int inkeylen, char *inval, int invallen, void *indata):
    l = <object>indata
    l.append(inval)


def __ypdomain(domain_name):
    cdef char *domain = NULL

    if domain_name is None:
        error = yp_get_default_domain(&domain)
        if error != 0:
            raise OSError(errno.EINVAL, yperr_string(error))
    else:
        domain = domain_name

    return domain


def ypbind(domain_name=None):
    domain_name = __ypdomain(domain_name)
    error = yp_bind(domain_name)
    if error != 0:
        raise OSError(errno.EINVAL, yperr_string(error))


def ypunbind(domain_name=None):
    domain_name = __ypdomain(domain_name)
    yp_unbind(domain_name)


def ypcat(map_name, domain_name=None):
    cdef ypall_callback ypcb
    result = []

    domain_name = __ypdomain(domain_name)

    ypcb.foreach = ypcat_foreach
    ypcb.data = <void *>result
    error = yp_all(domain_name, map_name, &ypcb)
    if error != 0:
        raise OSError(errno.EINVAL, yperr_string(error))

    return result


def ypmatch(key_name, map_name, domain_name=None):
    cdef char *outval
    cdef int outvallen

    domain_name = __ypdomain(domain_name)

    error = yp_match(domain_name, map_name, key_name, len(key_name), &outval, &outvallen)
    if error != 0:
        raise OSError(errno.EINVAL, yperr_string(error))

    return outval


# Note that this is implemented using entirely different piece
# of code, the libypclnt.  This is also what's used by chpass(1).
# The yppasswd(1) command, obviously, doesn't access YP directly
# at all, it just invokes PAM.
def yppasswd(username, old_password, password, domain_name=None):
    cdef passwd pw

    domain_name = __ypdomain(domain_name)

    entry = ypmatch(username, "passwd.byname").split(':')

    # Purpose of this weird 'tmp' dance is to work around some weird
    # memory corruption that happens otherwise.
    tmpname = entry[0]
    pw.pw_name = tmpname
    tmppasswd = crypt.crypt(password, old_password)
    pw.pw_passwd = tmppasswd
    pw.pw_uid = int(entry[2])
    pw.pw_gid = int(entry[3])
    pw.pw_class = ''
    tmpgecos = entry[4]
    pw.pw_gecos = tmpgecos
    tmpdir = entry[5]
    pw.pw_dir = tmpdir
    tmpshell = entry[6]
    pw.pw_shell = tmpshell

    if str(pw.pw_passwd) == '*':
        entry = ypmatch(username, "shadow.byname").split(':')
        tmppasswd = entry[1]
        pw.pw_passwd = tmppasswd

    ypclnt = ypclnt_new(domain_name, "passwd.byname", NULL)
    if ypclnt is NULL:
        raise OSError(errno.EINVAL, ypclnt.error)

    error = ypclnt_connect(ypclnt) 
    if error != 0:
        raise OSError(errno.EINVAL, ypclnt.error)

    error = ypclnt_passwd(ypclnt, &pw, old_password)
    if error != 0:
        raise OSError(errno.EINVAL, ypclnt.error)

    ypclnt_free(ypclnt)
