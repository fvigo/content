Downloads X509 Certificates of a remote SSL server.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| address | Server address. It can be a URL or address:port format. |
| sni | Specify servername in the request. If set to "true" the hostname is used.<br/>If set to "false" servername is not specified. Any other value is used as servername.<br/>Default: "true".<br/> |
| sni | Comma separated list of SSL protocols to try or "flex" for version-flexible handshake. Default: flex.<br/> |
| full_chain | Save full certificate chain offered by remote server. Default: "true"<br/> |
| proxy | Use proxy. Address of the HTTP proxy to use to reach the SSL server.<br/>Supports http URL and address:port format. Default: No proxy.<br/> |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Certificate.IssuerDN | The Issuer Distinguished Name of the certificate. | String |
| Certificate.MD5 | MD5 Fingerprint of the certificate in DER format. | String |
| Certificate.PEM | Certificate in PEM format. | String |
| Certificate.SHA256 | SHA256 Fingerprint of the certificate in DER format. | String |
| Certificate.SubjectDN | The Subject Distinguished Name of the certificate.<br/>This field includes the Common Name of the certificate.<br/> | String |
| DBotScore.Indicator | The indicator that was tested. | String |
| DBotScore.Score | The vendor used to calculate the score. | Number |
| DBotScore.Type | The indicator type. | String |
| DBotScore.Vendor | The actual score. | String |


## Script Example
```!CertificateFromSSLServer address=https://demisto.pan.dev```

## Context Example
```json
{
    "Certificate": [
        {
            "IssuerDN": "b'O'=b'Digital Signature Trust Co.', b'CN'=b'DST Root CA X3'",
            "MD5": "42313a35343a30393a32373a34463a35343a41443a38463a30323a33443a33423a38353a41353a45433a45433a3544",
            "PEM": "-----BEGIN CERTIFICATE-----\nMIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\nMSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\nDkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\nSjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\nGkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\nAQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\nq6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\nSMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\nZ8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\na6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\n/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\nAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\nCCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\nbTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\nc3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\nVAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\nARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\nMDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\nY3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\nAAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\nuM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\nwApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\nX4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\nPfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\nKOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\n-----END CERTIFICATE-----\n",
            "SHA256": "32353a38343a37443a36363a38453a42343a46303a34463a44443a34303a42313a32423a36423a30373a34303a43353a36373a44413a37443a30323a34333a30383a45423a36433a32433a39363a46453a34313a44393a44453a32313a3844",
            "SubjectDN": "b'C'=b'US', b'O'=b\"Let's Encrypt\", b'CN'=b\"Let's Encrypt Authority X3\""
        },
        {
            "IssuerDN": "b'C'=b'US', b'O'=b\"Let's Encrypt\", b'CN'=b\"Let's Encrypt Authority X3\"",
            "MD5": "43323a36433a43413a36443a38453a41453a31353a36323a35343a35453a41323a46393a32413a37383a36413a3446",
            "PEM": "-----BEGIN CERTIFICATE-----\nMIIFeTCCBGGgAwIBAgISAzEbsD9qaotTNWpIjVYTuJfLMA0GCSqGSIb3DQEBCwUA\nMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\nExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDExMDkwODI3MjJaFw0y\nMTAyMDcwODI3MjJaMBQxEjAQBgNVBAMMCSoucGFuLmRldjCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBAN9SNys/BIObvOjc4I9JXOev91udhfUWMZ4B1G/P\nRYIcyVxlQKbgPrzGG0RaC14fPoQ5Jt9G/iP6+xZSIE5dsXN6BEx0z1XxsXNNC4p1\nmxAMMnNR5dOVlkvmW2NCl5Ei38FZrA2Ppf+SnNyNK/O4JC7q3FFYxv6uzvmyMS7P\nlct6XR29BkcOQXGcFn4uVXfa5gex710P20bqaSLePPR3Q01xeNPPtaaRM3XQq/lX\n4jzWFNcKaNyHb/ZoH6CJxue+L3tjA/vWJ/0bDUAtHBauTiuQINwEgKsMVX0GJ8+R\ndQEbNvqcnvyMXRCjyH4jowClVIPqvMCFKCLWywZz83ksZbsCAwEAAaOCAo0wggKJ\nMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\nDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUMNCAdN2NspaIwq5z3DadxFiiBkQwHwYD\nVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYBBQUHAQEEYzBhMC4G\nCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2VuY3J5cHQub3JnMC8G\nCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5cHQub3JnLzBE\nBgNVHREEPTA7ggkqLnBhbi5kZXaCB3Bhbi5kZXaCJXBhbm9zLmRldmVsb3BlcnMu\ncGFsb2FsdG9uZXR3b3Jrcy5jb20wTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYB\nBAGC3xMBAQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5v\ncmcwggEDBgorBgEEAdZ5AgQCBIH0BIHxAO8AdgBvU3asMfAxGdiZAKRRFf93FRwR\n2QLBACkGjbIImjfZEwAAAXWsVNeKAAAEAwBHMEUCIGqLW6M9TglATvIjIe16M04e\nE+N7u2WQ9pXOzCnsGs9jAiEA2xUatPkccLZQBUvSdm+lxpDybWUiVuy0u0WvA1PK\n4loAdQB9PvL4j/+IVWgkwsDKnlKJeSvFDngJfy5ql2iZfiLw1wAAAXWsVNfFAAAE\nAwBGMEQCIFGFLG63CN5rzm6+7COMdfX9lEInTK75K+1S3DJfuBRgAiBsy078DE9N\nUS0VvJT1RbwUd9gHmrdYTjHvoB3+0s+HFzANBgkqhkiG9w0BAQsFAAOCAQEADBhy\nMXGZEwZOtJ9s629vBpXlToQuldMzMruK7YnU8k5jlYo+zf0h+Cho8FVyDGyL2lDP\nnogirsZLE8c3VG+6THsazDlRkrC4kgluwFO+O5Uek+x5/EKUHexKRLZugPcCLJze\nxZY466i/TNUJQboSqAeQ9G0c6icuXQyyNEjOGISL6EJPXYKFMsKYS+3bKG6rjIcB\nwh3punkiV5xTWBkhkXQXDGbIiDexPlCru6pYBRdjYLh7djqNcaETyZzlMGuqaXPV\nKLkHysDrPFRMv7vsVZtfl+uo/IZDlu/f/l9dbAOSm7U2Y4lMDcFFvgBFe92VugRX\nlsIyitGgEHPo3lfpKw==\n-----END CERTIFICATE-----\n",
            "SHA256": "38443a41383a44313a46393a44303a32323a38453a43333a38443a44363a35393a31353a34463a37333a34443a35393a36353a44303a43443a32343a38373a45413a34413a43343a34313a31423a39423a43303a41413a34443a37453a4136",
            "SubjectDN": "b'CN'=b'*.pan.dev'"
        }
    ],
    "DBotScore": [
        {
            "Indicator": "32353a38343a37443a36363a38453a42343a46303a34463a44443a34303a42313a32423a36423a30373a34303a43353a36373a44413a37443a30323a34333a30383a45423a36433a32433a39363a46453a34313a44393a44453a32313a3844",
            "Score": 0,
            "Type": "certificate",
            "Vendor": "X509Certificate"
        },
        {
            "Indicator": "38443a41383a44313a46393a44303a32323a38453a43333a38443a44363a35393a31353a34463a37333a34443a35393a36353a44303a43443a32343a38373a45413a34413a43343a34313a31423a39423a43303a41413a34443a37453a4136",
            "Score": 0,
            "Type": "certificate",
            "Vendor": "X509Certificate"
        }
    ]
}
```

## Human Readable Output

>### Certificates
>|subject|issuer|sha256|
>|---|---|---|
>| b'C'=b'US', b'O'=b"Let's Encrypt", b'CN'=b"Let's Encrypt Authority X3" | b'O'=b'Digital Signature Trust Co.', b'CN'=b'DST Root CA X3' | 32353a38343a37443a36363a38453a42343a46303a34463a44443a34303a42313a32423a36423a30373a34303a43353a36373a44413a37443a30323a34333a30383a45423a36433a32433a39363a46453a34313a44393a44453a32313a3844 |
>| b'CN'=b'*.pan.dev' | b'C'=b'US', b'O'=b"Let's Encrypt", b'CN'=b"Let's Encrypt Authority X3" | 38443a41383a44313a46393a44303a32323a38453a43333a38443a44363a35393a31353a34463a37333a34443a35393a36353a44303a43443a32343a38373a45413a34413a43343a34313a31423a39423a43303a41413a34443a37453a4136 |

