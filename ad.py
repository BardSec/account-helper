"""
Active Directory client for password reset and account unlock operations.
Requires an LDAPS connection (ldaps://) — AD will reject password changes over plain LDAP.
"""
import ssl
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SUBTREE, Tls, MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars


class ADError(Exception):
    """Raised for any Active Directory operation failure."""
    pass


class ADClient:
    def __init__(self, server_url: str, base_dn: str, skip_tls_verify: bool = False):
        """
        Args:
            server_url:      LDAP server URL, e.g. ldaps://dc01.corp.com
            base_dn:         Search base, e.g. DC=corp,DC=com
            skip_tls_verify: Set True only in dev/test environments with self-signed certs.
        """
        self.server_url = server_url
        self.base_dn = base_dn
        self.skip_tls_verify = skip_tls_verify

    def _make_server(self) -> Server:
        use_ssl = self.server_url.lower().startswith("ldaps")
        tls_config = None
        if use_ssl:
            tls_config = Tls(
                validate=ssl.CERT_NONE if self.skip_tls_verify else ssl.CERT_REQUIRED
            )
        return Server(self.server_url, use_ssl=use_ssl, tls=tls_config, get_info=ALL)

    def _connect(self, username: str, password: str) -> Connection:
        """
        Bind to AD using the technician's credentials.

        Supports:
          - NTLM:   DOMAIN\\username
          - Simple: username@domain.com  or  cn=user,dc=corp,dc=com
        """
        server = self._make_server()
        auth = NTLM if "\\" in username else SIMPLE
        conn = Connection(server, user=username, password=password, authentication=auth)

        if not conn.bind():
            code = conn.result.get("result")
            if code == 49:
                raise ADError("Authentication failed — check your username and password.")
            raise ADError(
                f"Could not bind to Active Directory: {conn.result.get('description', 'unknown error')}"
            )
        return conn

    def reset_password(
        self,
        tech_username: str,
        tech_password: str,
        target_username: str,
        new_password: str,
        unlock: bool = False,
        force_change: bool = False,
    ) -> None:
        """
        Reset an AD user's password and optionally unlock their account.

        Args:
            tech_username:  The technician's AD login (e.g. CORP\\jsmith).
            tech_password:  The technician's AD password.
            target_username: sAMAccountName of the account to reset.
            new_password:   The new password to set.
            unlock:         If True, clear the lockout on the account after reset.
            force_change:   If True, require the user to change their password at next logon.

        Raises:
            ADError: on any failure (bad credentials, user not found, insufficient rights, etc.)
        """
        conn = self._connect(tech_username, tech_password)

        # Sanitise the username before inserting into the search filter (LDAP injection guard).
        safe_target = escape_filter_chars(target_username)
        conn.search(
            search_base=self.base_dn,
            search_filter=f"(&(objectClass=user)(sAMAccountName={safe_target}))",
            search_scope=SUBTREE,
            attributes=["distinguishedName", "sAMAccountName"],
        )

        if not conn.entries:
            raise ADError(f"No user found with username '{target_username}'.")

        user_dn = str(conn.entries[0].distinguishedName)

        # AD requires the password to be wrapped in double-quotes and UTF-16LE encoded.
        # This MUST be sent over LDAPS; plain LDAP will return Unwilling to Perform (53).
        encoded_password = f'"{new_password}"'.encode("utf-16-le")
        conn.modify(user_dn, {"unicodePwd": [(MODIFY_REPLACE, [encoded_password])]})

        result_code = conn.result.get("result")
        if result_code != 0:
            desc = conn.result.get("description", "unknown error")
            if result_code == 53:
                raise ADError(
                    "Password reset rejected (error 53 — Unwilling to Perform). "
                    "The server must be reachable via LDAPS (port 636) for password changes."
                )
            if result_code == 50:
                raise ADError(
                    "Insufficient permissions (error 50). "
                    "Your account needs 'Reset Password' rights on the target OU."
                )
            if result_code == 19:
                raise ADError(
                    "New password does not meet the domain's complexity requirements (error 19)."
                )
            raise ADError(f"Password reset failed: {desc} (code {result_code}).")

        if unlock:
            conn.modify(user_dn, {"lockoutTime": [(MODIFY_REPLACE, [0])]})
            if conn.result.get("result") != 0:
                desc = conn.result.get("description", "unknown")
                raise ADError(f"Password was reset but account unlock failed: {desc}.")

        if force_change:
            conn.modify(user_dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
            if conn.result.get("result") != 0:
                desc = conn.result.get("description", "unknown")
                raise ADError(
                    f"Password was reset but 'force change at next logon' could not be set: {desc}."
                )

        conn.unbind()
