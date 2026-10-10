import { CVEItem } from '../types/scanner';

export const KNOWN_SERVICE_CVES: Record<number, CVEItem[]> = {
  21: [
    {
      id: 'CVE-2011-2523',
      title: 'vsftpd 2.3.4 Backdoor Command Execution',
      cvss: 9.8,
      severity: 'CRITICAL',
      description: 'The vsftpd version 2.3.4 download package contained a malicious backdoor triggered when a username ending with ":)" is supplied, opening a shell on port 6200.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      affectedVersions: 'vsftpd 2.3.4',
      mitigation: 'Immediately purge vsftpd 2.3.4 and upgrade to vsftpd >= 3.0.5. Disable anonymous FTP access and isolate with network firewalls.',
      remediationSnippet: {
        language: 'bash',
        code: `# 1. Stop and disable legacy service\nsudo systemctl stop vsftpd\n\n# 2. Upgrade package via distribution repository\nsudo apt update && sudo apt install --only-upgrade vsftpd\n\n# 3. Restrict root logins in /etc/vsftpd.conf\nanonymous_enable=NO\nlocal_enable=YES\nwrite_enable=YES\nchroot_local_user=YES`,
        explanation: 'Disable anonymous access, enforce chroot jails, and migrate to SFTP/SSH rather than cleartext FTP.'
      }
    },
    {
      id: 'CVE-2020-9273',
      title: 'ProFTPD Use-After-Free Memory Corruption',
      cvss: 8.8,
      severity: 'HIGH',
      description: 'In ProFTPD 1.3.7, an uncaught use-after-free in the data transfer handling pool allows authenticated remote users to cause a denial of service or potentially execute code.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
      affectedVersions: 'ProFTPD < 1.3.7a',
      mitigation: 'Update ProFTPD to 1.3.7a or newer. Enforce TLS/FTPS connections and rate-limit authentication attempts.',
      remediationSnippet: {
        language: 'bash',
        code: `# Verify ProFTPD version\nproftpd -v\n\n# Patch configuration to require strict TLS\nTLSEngine on\nTLSRequired on\nTLSRSACertificateFile /etc/ssl/certs/proftpd.crt`,
        explanation: 'Require TLS encryption and verify that memory corruption patches have been applied.'
      }
    }
  ],
  22: [
    {
      id: 'CVE-2023-38408',
      title: 'OpenSSH PKCS#11 Provider Remote Code Execution',
      cvss: 9.8,
      severity: 'CRITICAL',
      description: 'A flaw in OpenSSH ssh-agent allows an attacker with access to the forwarded agent socket to load arbitrary shared libraries via PKCS#11 providers, resulting in remote code execution.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      affectedVersions: 'OpenSSH 5.5p1 through 9.3p1',
      mitigation: 'Upgrade OpenSSH to version 9.3p2 or higher. Disable Agent Forwarding by default in client and server configs.',
      remediationSnippet: {
        language: 'bash',
        code: `# In /etc/ssh/sshd_config\nAllowAgentForwarding no\nPermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\n\n# Reload daemon\nsudo systemctl reload sshd`,
        explanation: 'Enforce cryptographic key-only authentication, disable agent forwarding unless required, and upgrade OpenSSH.'
      }
    },
    {
      id: 'CVE-2020-15778',
      title: 'OpenSSH scp Command Injection via Shell Metacharacters',
      cvss: 7.8,
      severity: 'HIGH',
      description: 'A vulnerability in OpenSSH scp client allows local and remote attackers to bypass authorization and execute arbitrary shell commands when crafted file names are processed.',
      vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
      affectedVersions: 'OpenSSH <= 8.3p1',
      mitigation: 'Adopt SFTP or rsync over SSH instead of legacy scp protocol. Enforce OpenSSH >= 8.4p1 with strict quoting.',
      remediationSnippet: {
        language: 'bash',
        code: `# Use modern sftp or rsync instead of raw scp\nrsync -avz -e ssh ./source user@host:/dest\n\n# Or use the OpenSSH SFTP protocol switch\nscp -s user@host:file .`,
        explanation: 'Decommission legacy scp utilities in favor of SFTP sub-system protocols.'
      }
    }
  ],
  23: [
    {
      id: 'CVE-2020-10188',
      title: 'Telnetd Buffer Overflow & Cleartext Credential Sniffing',
      cvss: 9.8,
      severity: 'CRITICAL',
      description: 'Legacy Telnet daemons transmit all keystrokes and authentication in unencrypted cleartext, and utility function buffer overflows allow remote code execution.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      affectedVersions: 'inetutils-telnetd <= 1.9.4',
      mitigation: 'Disable Telnet daemon completely. Migrate all interactive management to SSH with public keys.',
      remediationSnippet: {
        language: 'bash',
        code: `sudo systemctl stop inetutils-telnetd\nsudo systemctl disable inetutils-telnetd\nsudo apt purge telnetd`,
        explanation: 'Decommission Telnet daemon and terminate cleartext port 23 listeners.'
      }
    }
  ],
  445: [
    {
      id: 'CVE-2017-0144',
      title: 'SMBv1 Remote Code Execution (EternalBlue)',
      cvss: 9.8,
      severity: 'CRITICAL',
      description: 'A remote code execution vulnerability exists in Microsoft Server Message Block 1.0 (SMBv1) protocol handling, permitting worm-like remote exploitation.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      affectedVersions: 'SMBv1 Server',
      mitigation: 'Completely disable SMBv1 across the enterprise. Block TCP 445 on perimeter firewalls.',
      remediationSnippet: {
        language: 'powershell',
        code: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force`,
        explanation: 'Disable legacy SMBv1 and enforce SMB signing.'
      }
    }
  ],
  3306: [
    {
      id: 'CVE-2012-2122',
      title: 'MySQL / MariaDB Authentication Bypass via memcmp Flaw',
      cvss: 9.8,
      severity: 'CRITICAL',
      description: 'A flaw in memcmp return value evaluation allows an attacker to authenticate as root or any user without knowing the password in roughly 1 out of 256 login attempts.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      affectedVersions: 'MySQL 5.1.x, 5.5.x, MariaDB < 5.5.24',
      mitigation: 'Upgrade MySQL to patched releases. Never expose port 3306 to public interfaces; bind strictly to 127.0.0.1.',
      remediationSnippet: {
        language: 'bash',
        code: `# In /etc/mysql/mysql.conf.d/mysqld.cnf\nbind-address = 127.0.0.1\n\n# Restart database server\nsudo systemctl restart mysql`,
        explanation: 'Bind database listener strictly to localhost.'
      }
    }
  ],
  80: [
    {
      id: 'CVE-2021-41773',
      title: 'Apache HTTP Server Path Traversal & Remote Code Execution',
      cvss: 9.8,
      severity: 'CRITICAL',
      description: 'A flaw in the path normalization logic in Apache HTTP Server 2.4.49 allows attackers to traverse directory boundaries and read arbitrary files or execute CGI scripts.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      affectedVersions: 'Apache 2.4.49, 2.4.50',
      mitigation: 'Upgrade Apache HTTP Server to version 2.4.51 or later immediately. Ensure Require all denied is configured for root filesystem.',
      remediationSnippet: {
        language: 'apache',
        code: `<Directory />\n    AllowOverride none\n    Require all denied\n</Directory>\n\n# Verify Apache Version\nhttpd -v`,
        explanation: 'Deny directory traversal permissions across the root system and verify CGI modules are deactivated if unneeded.'
      }
    },
    {
      id: 'CVE-2021-23017',
      title: 'Nginx DNS Resolver 1-Byte Memory Overwrite Off-by-One',
      cvss: 7.7,
      severity: 'HIGH',
      description: 'A 1-byte memory overwrite flaw in Nginx DNS resolver code could allow an attacker forging UDP DNS responses to cause worker process crash or arbitrary code execution.',
      vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
      affectedVersions: 'Nginx 0.6.18 - 1.20.0',
      mitigation: 'Upgrade to Nginx >= 1.20.1 or >= 1.21.0. If unable to patch immediately, disable the resolver directive in public configs.',
      remediationSnippet: {
        language: 'nginx',
        code: `# Inspect nginx configuration for dynamic upstream resolver\nnginx -t\n\n# Ensure TLS redirection and security headers are enforced\nserver {\n    listen 80 default_server;\n    return 301 https://$host$request_uri;\n}`,
        explanation: 'Redirect all plaintext HTTP traffic to HTTPS and update nginx binary packages.'
      }
    },
    {
      id: 'CVE-2023-25690',
      title: 'Apache HTTP Server mod_proxy HTTP Request Splitting',
      cvss: 7.5,
      severity: 'HIGH',
      description: 'Certain mod_proxy configurations allow HTTP request splitting via crafted request headers, causing backend request smuggling.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
      affectedVersions: 'Apache 2.4.0 through 2.4.55',
      mitigation: 'Update Apache HTTP Server to 2.4.56 or higher. Audit RewriteRule and ProxyPass configurations.',
      remediationSnippet: {
        language: 'apache',
        code: `# Ensure strict proxy rewrite flags are set\nRewriteEngine On\nRewriteRule ^/(.*)$ balancer://cluster/$1 [P,NE]`,
        explanation: 'Prevent unencoded carriage return/linefeed injection into backend reverse proxy connections.'
      }
    }
  ],
  443: [
    {
      id: 'CVE-2022-3786',
      title: 'OpenSSL X.509 Email Address Buffer Overrun',
      cvss: 7.5,
      severity: 'HIGH',
      description: 'A buffer overrun can be triggered in X.509 certificate verification during name constraint checking, causing denial of service.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      affectedVersions: 'OpenSSL 3.0.0 through 3.0.6',
      mitigation: 'Upgrade OpenSSL library to version 3.0.7 or later.',
      remediationSnippet: {
        language: 'bash',
        code: `# Check OpenSSL version\nopenssl version\n\n# Update libssl\nsudo apt update && sudo apt install --only-upgrade openssl libssl-dev`,
        explanation: 'Apply system-wide OpenSSL patch and restart dependent web services.'
      }
    },
    {
      id: 'CVE-2020-0601',
      title: 'Windows CryptoAPI Spoofing Vulnerability (CurveBall)',
      cvss: 8.1,
      severity: 'HIGH',
      description: 'A spoofing vulnerability exists in the way Windows CryptoAPI validates Elliptic Curve Cryptography (ECC) certificates.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
      affectedVersions: 'Windows 10 / Server 2016 / 2019',
      mitigation: 'Install Microsoft KB4534273 cumulative security update. Enforce strict TLS 1.3 cipher suites.',
      remediationSnippet: {
        language: 'nginx',
        code: `# Enforce TLSv1.3 and robust ECDHE ciphers\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_stapling on;\nssl_stapling_verify on;`,
        explanation: 'Configure forward secrecy ciphers and enable OCSP stapling.'
      }
    }
  ],
  8080: [
    {
      id: 'CVE-2021-44228',
      title: 'Apache Log4j2 JNDI Remote Code Execution (Log4Shell)',
      cvss: 10.0,
      severity: 'CRITICAL',
      description: 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      affectedVersions: 'Log4j 2.0-beta9 through 2.15.0',
      mitigation: 'Upgrade to Log4j 2.17.1 or higher. Set formatMsgNoLookups=true or remove JndiLookup class from classpath.',
      remediationSnippet: {
        language: 'bash',
        code: `# Immediate JVM mitigation parameter\njava -Dlog4j2.formatMsgNoLookups=true -jar service.jar\n\n# Or remove the class file from the JAR\nzip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`,
        explanation: 'Disable JNDI lookup functionality and upgrade log4j dependencies across all build pipelines.'
      }
    },
    {
      id: 'CVE-2022-22965',
      title: 'Spring Framework Spring4Shell Remote Code Execution',
      cvss: 9.8,
      severity: 'CRITICAL',
      description: 'A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      affectedVersions: 'Spring Framework 5.3.0 to 5.3.17, 5.2.0 to 5.2.19',
      mitigation: 'Upgrade to Spring Framework 5.3.18 or 5.2.20. Upgrade to Apache Tomcat 10.0.20, 9.0.62, or 8.5.78.',
      remediationSnippet: {
        language: 'xml',
        code: `<!-- In Maven pom.xml -->\n<properties>\n    <spring-framework.version>5.3.20</spring-framework.version>\n</properties>`,
        explanation: 'Update spring framework parent POM to patched version.'
      }
    },
    {
      id: 'CVE-2023-20860',
      title: 'Spring Framework Security Pattern Matching Bypass',
      cvss: 7.5,
      severity: 'HIGH',
      description: 'Using ** as a pattern in Spring Security mvcMatchers with Spring MVC creates a mismatch in pattern matching between Spring MVC and Spring Security, causing authorization bypass.',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      affectedVersions: 'Spring Framework 6.0.0 - 6.0.6, 5.3.0 - 5.3.25',
      mitigation: 'Upgrade to Spring Framework 6.0.7+ or 5.3.26+.',
      remediationSnippet: {
        language: 'java',
        code: `@Bean\npublic SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n    http.authorizeHttpRequests(authz -> authz\n        .requestMatchers("/api/admin/**").hasRole("ADMIN")\n        .anyRequest().authenticated());\n    return http.build();\n}`,
        explanation: 'Use modern requestMatchers and ensure pattern resolution sync.'
      }
    }
  ]
};
