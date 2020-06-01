# Monitoring Scripts

This script houses monitoring plugins I use in systems monitoring.  In many
cases, the scripts here are an updated version from my former employer, [Drexel
University][drexel].

# SSL certificate chain monitoring

The following script monitors certificate chains and reports the current status.

    ./ssl_chain_expiration.sh example.com

Checks an entire certificate chain of a remote service and alerts via exit code
and stdout if any certificate in the remote chain is nearly expired (within 60
days) or expired.

Exit states:

- `0` - success, entire certificate chain is valid for at least 60 days.
- `1` - warning, one of the certificates in the chain has less than 60 days
  before exiration.
- `2` - critical, one of the certificates in the chain has expired.

[drexel]: https://github.com/samrocketman/drexel-university
