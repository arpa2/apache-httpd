Apache TLS Pool configuration
=============================

>   *A few modules: TLS Pool, HTTP SASL, ARPA2ACL.*

TLS Pool module
---------------

The plugin module that passes the responsibility over TLS to an external daemon,
the TLS Pool.

### Configuration of Apache Contexts

These go into the configuration files for Apache… or not!

-   `TLSPoolEnable on` to indicate the use of the security through the TLS Pool
    at the instant a TCP connection is accepted on its socket.

-   Global configuration variable `TLSPoolPath` references the UNIX domain
    socket for the TLS Pool.  It may be extended to network connections in
    future versions.

-   `ServerName` and `ServerAlias` indicate the name(s) acceptable to this
    environment.  They will be matched against the TLS SNI.  When this is
    encountered by the TLS Pool, it makes a callback to the Apache module to
    test if the requested name is acceptable.  The answer is based on the set of
    all `ServerName` and `ServerAlias` declarations in contexts with
    `TLSPoolEnable on`.  This callback is also how wildcards such as
    `*.arpa2.net` can be matched.

-   Certificates, keys, cipher suites are not set in Apache.  They are all left
    to the TLS Pool.

-   For the web, `ipproto` is always `TCP`, so no configuration.

-   For the web, `streamid` is never needed.

-   For the web, `service` is always `http`, in lowercase, and never `https`
    because it is `http` that runs over TLS.  No configuration.

-   The module may choose a sane value for the `timeout`.  It does not seem
    useful to configure this setting…???

-   The module may find a use for `ctlkey`, notably to allow detaching from the
    TLS side of the connection and possibly return later to renegotiate for
    client authentication.

Local flags are not used in Apache.  Normal `flags` are, of course.

-   The only facility used in Apache is `PIOF_FACILITY_STARTTLS`

-   Roles are `PIOF_STARTTLS_LOCALROLE_SERVER` and
    `PIOF_STARTTLS_REMOTEROLE_CLIENT` and both must be set to exclude
    peer-to-peer protocol variations.

-   It may??? be useful for auditing purposes to have an option to set
    `PIOF_STARTTLS_IGNORE_CACHES` for certain `<Location/>` that require active
    approval by the user.  Tell me what you think.  An option could be
    `TLSPoolIgnoreCaches on` in the right place in the configuration file.

-   When it is not stopped, the remote identity is required, causing a
    dependency on a client certificate.  This is not practical for HTTP, so the
    default should be `PIOF_STARTTLS_IGNORE_REMOTEID` unless
    `TLSPoolClientIdentity` is set to `request` or `require`.  If it is
    `request`, the flag `PIOF_STARTTLS_REQUEST_REMOTEID` is used instead.

-   `PIOF_STARTTLS_DETACH` does not seem to add any value for Apache, as it can
    probably deal with the control over the various TLS sockets and the ability
    to rearrange them.

-   `PIOF_STARTTLS_FORK` makes the TLS connection proceed even when Apache
    stops.  This is not useful, and may even serve the interests of exceptional
    attacks.  Moreover, Apache is pretty good at staying up even when reloading
    configurations.

-   Whether `PIOF_STARTTLS_DOMAIN_REPRESENTS_USER` is useful depends on the
    expectations about clients.  It can be set by default, or determined by
    `TLSPoolClientType` set as either `user` or `domain`.

-   The flag `PIOF_STARTTLS_LOCALID_CHECK` is required when various `ServerName`
    and/or `ServerAlias` values are set, and certainly when wildcards are
    involved.  It causes the callback mechanism to be used.

-   Initially, a TLS connection will be setup for the overall `<VirtualHost/>`
    for a given name.  But when the HTTP exchange calls for a
    `TLSPoolClientIdentity` there is a need for TLS renegotiation (up to 1.2) or
    a late request of a client identity (since 1.3).  This is done by repeating
    the TLS Pool exchange, with the `PIOF_STARTTLS_RENEGOTIATE` flag set.

-   There is some facilitation for on-the-fly re-signing, a function that is
    most useful in HTTPS proxies, as well as in web servers that simply want to
    sign everything with a single (intermediate) CA certificate, but not using
    static certificates.  The flag `PIOF_STARTTLS_LOCALID_ONTHEFLY` is set when
    a `<VirtualHost/>` specifies `TLSPoolFlyingSigner on`

 

Example virtual host configuration:

 

>   \<IfModule mod_arpa2_tlspool.c\>

>   \<VirtualHost 10.0.0.9:443 [2001:980:93a5:1::9]:443\>

>   ServerName internetwide.org

>   ServerAlias www.internetwide.org

>   ServerAlias \*.internetwide.org

>   DocumentRoot /var/www/trivial/internetwide.org

>   **TLSPoolEnable on**

>   GnuTLSPriorities SECURE

>   **\#NOPE\#** TLSPoolPriorities PFS:+SECURE256:+SECURE192

>   **\#NOPE\#** TLSPoolCertificateFile /etc/ssl/certs/iwo-2014-11-24.pem

>   **\#NOPE\#** TLSPoolKeyFile /etc/ssl/private/iwo-2014-11-24.key

>   \<Location /djangora/\>

>   **TLSPoolClientIdentity request** \# …, require, ignore

>   **\#NOPE\#** TLSPoolClientCA ...

>   **\#NOPE\#** TLSPoolClientVerifyDepth ...

>   SetHandler python-program

>   PythonHandler django.core.handlers.modpython

>   SetEnv PYTHONPATH

>   PythonPath "['/home/djangora'] + sys.path"

>   SetEnv DJANGO_SETTINGS_MODULE tcs.settings

>   \</Location\>

>   \</VirtualHost\>

>   \</IfModule\>

 

### Disclosure of Local Identities

There is an option in the TLS Pool to restrict who may see what local
identities.  For a TLS server, this will not work because the server presents
its identity before the client does.  So none of the `PIOF_LIDENTRY_` need
configuration in Apache.  Effectively, this is saying not to skip any local
identity.

Apache must register through `PIOC_LIDENTRY_REGISTER_V2` with the desired flags,
and handle any callbacks that arrive.

 

### Entry of PINs (Not Done)

Apache should not register to serve PIN codes to the TLS Pool.  This is very
deliberately a separate interface, intended for a users’s graphical interface.
When run on a headless server, the PIN can be setup in `tlspool.conf` instead.

 

### Delivery of Environment Variables

The following variables are delivered:

-   `LOCAL_USER` is always set when the TLS Pool is active, otherwise it is
    reset.

-   `REMOTE_USER` is set when the client identity is.  It is cleared when the
    TLS Pool is enabled and there is no client identity.

 

### Relation to HTTP headers

-   Consider `Upgrade:` to switch to TLS, much like STARTTLS.

-   Consider `STS` to pin the fact that a site is always under TLS.

 

Authentication through HTTP SASL
--------------------------------

Allow the same authentication flexibility for HTTP as for most other protocols.
Even IRC has this already!

Specifically facilitated: channel binding, at least when this is possible in the
current setting.  Otherwise, let me know what is missing (probably a requesting
command in the TLS Pool interface?)

Configuration: Reference an out-of-browser SASL solution.

-   Take a [look at Postfix](http://www.postfix.org/SASL_README.html) to see how
    they do it.

-   Consider both a client and server role for proxies; note that SASL can be
    taken out of context and passed on, even in other protocols.  Authentication
    however, may differ between uplink and downlink.

-   Consider an extra backend to pass a request over Diameter, either as part of
    Apache or as part of a SASL library.  We can define an AVP to do that, as
    this does not seem to be current practice (though it makes a lot of sense).

-   Consider using `libsasl2` as it comes with many plugin modules that are
    installed separately (at least, on Debian).

-   Consider the difference between authentication (“is it really you?”) and
    authorisation (“what are you allowed to do?”)

-   Keep in mind that the user can choose an authorisation name.  This is like a
    [step-down](http://internetwide.org/blog/2016/12/18/id-6-inheritance.html)
    from the authenticated name to one the s/he chooses to use.  Reasons to do
    this may include privacy, classifying traffic and security through not using
    a full-strength identity.  An ideal place to set an authorisation identity
    could be a pull-down menu in the browser or app; it would in fact also
    change things on the desktop, notably one’s Kerberos login.

 

Authorisation through ARPA2ACL
------------------------------

The [ACLs](http://donai.arpa2.net/acl.html) for ARPA2 are generally entered in
LDAP, then pulled out and shifted back and forth to come to an [efficient
implementation](http://donai.arpa2.net/acl-impl.html) that will be captured into
a library.

-   In addition to this central control, it would be useful to also have local
    configuration in Apache, for those without an IdentityHub.  The same ACL
    format would apply, and a similar mapping to a database format.  Where LDAP
    entries get added and removed, the change to one’s Apache configuration
    probably do similar things.

-   Configure the library location for ARPA2ACL queries.  Talk to Tim about
    configuration (which would be system-wide).

-   As an alternative to these libraries, we may consider to ask over Diameter.
    Tim’s libraries would then respond to that.

-   The things that we shield are `AccessControlledCommunication
    user@domain.name` for communication with a user;
    `AccessControlledResourceClass uuid` with a fixed UUID for a resource class,
    and `AccessControlledResourceInstance key` with a variable key for a
    resource instance (always together with a class).  The first and last forms
    may include bits and pieces taken from the current URL through pattern
    matching.  Every `<Location/>` can have at most one of these shielded
    objects.

    **New:** For operator simplicity, we could set a default ResourceClassUUID value
    `7a35d76d-a754-35a6-abe7-757c161f0263` and then use a default ResourceInstance
    string consisting of the (lowercase, no-trailing-dot, `xn-` i18n) hostname, a
    slash, and the (literal, case-sensitive) realm name.

-   ACL entries explicitly approve access, but by default it is all rejected.
    General patterns to accept everything exist.  Note that a gray-listed form
    exists, and should be implemented in whichever way makes sense to the
    protocol at hand.  If Apache cannot find a good mechanism for gray-listed
    requests, it may desire use of another protocol first.  Or, in line with
    what email does, wait for a while and then reload a page with a long code
    inserted into it.

-   Default mappings exist for HTTP methods to access rights.  These rights are
    flags, written as single letters, retrieved from the evaluation of the ACL.
    Custom alterations are possible, both on the basis of the `<Location/>` and
    on the method.

 

 
