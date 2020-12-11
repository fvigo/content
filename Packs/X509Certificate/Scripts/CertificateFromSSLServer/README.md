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
| proxy | Use proxy. <br/>If "true", the system configured proxy is used.<br/>If "false", no proxy is used.<br/>If set to an address \(address:port or http URL\), the address is used as proxy address.<br/>Default: "true".<br/> |

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
            "MD5": "39393a31383a42363a44363a46463a30433a43303a35433a45463a43453a33303a37353a36393a42313a32373a3242",
            "PEM": "-----BEGIN CERTIFICATE-----\nMIIFezCCBGOgAwIBAgISA/JL4oaGczW5OqvCy9cEQqu6MA0GCSqGSIb3DQEBCwUA\nMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\nExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDExMDgxODE1NDFaFw0y\nMTAyMDYxODE1NDFaMBQxEjAQBgNVBAMMCSoucGFuLmRldjCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBANg20WTL+SVHruVKNy0hLNUlOUeK0EDdEV/rwsqk\niT3yIASK2AXzaOF3M8TVU6I/xEKVMnEmduxmSKeGIiF8+0ClKaXRGkt6ErVM6G+f\nHQOAMNYIOmWe199hRFrKKmH/F9ws366vjQMwP7xUwcQPsSKhirz1VoOpYLBgQ8FO\nF8IWJuad8wiW6qfRZXEUl9Ta4klekG5/Kp3P/pPnNn65rFYrMCcmaSLymdfcyGpV\nEtipNc8X5zvryZ3q1sNRG05MSNhtN0FtnuRG99oetzjUP/MhiX+6RqbG2Ou33b+A\nnOPKsTksDNeSNMPJpd/vxYnjzTeISo10+AuXRrpJ2I9nzhECAwEAAaOCAo8wggKL\nMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\nDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUuENucz/GeiKrE10fxExRWTUydqMwHwYD\nVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYBBQUHAQEEYzBhMC4G\nCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2VuY3J5cHQub3JnMC8G\nCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5cHQub3JnLzBG\nBgNVHREEPzA9ggkqLnBhbi5kZXaCJ2RlbWlzdG8uZGV2ZWxvcGVycy5wYWxvYWx0\nb25ldHdvcmtzLmNvbYIHcGFuLmRldjBMBgNVHSAERTBDMAgGBmeBDAECATA3Bgsr\nBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIBFhpodHRwOi8vY3BzLmxldHNlbmNyeXB0\nLm9yZzCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2AESUZS6w7s6vxEAH2Kj+KMDa\n5oK+2MsxtT/TM5a1toGoAAABdalJF6wAAAQDAEcwRQIgY7UA7lCiPYQi2OiML/mg\nZ7LQyFegVH1tX2dBG23D5tgCIQC9c9UX886gpx4ROpDyHdSd+k0a9BR5dDdyPfj0\ncRm1LgB1AH0+8viP/4hVaCTCwMqeUol5K8UOeAl/LmqXaJl+IvDXAAABdalJF+MA\nAAQDAEYwRAIgKMtxuyKPcT0QxAJKN0uNl4jcJn0pdBzHqafHQXni9gYCIGqdT8l5\n3OEkoiQ17boLs4saRFlg2a2zx0cB4jEPg6/eMA0GCSqGSIb3DQEBCwUAA4IBAQBD\nGb01zj3OJ5cntlFldFGzlNDMMrsJxYPNZJfjKr/USMZ/OTjN9snr2HvWnhFTrD8L\n7HxDbYWXt0dMwQZtA0ZIKrlUIZrxhnyPsehYRrKm9+G8X2n/K6vseCwxxTfIlL2R\nOvmeIWc8NBxJ6bu/s2xIYuIk07fHOpw537pk8NIZnkeOL9VPwKsAgotCyB+6AQ1f\nraEqZXkLJYnNYoYh24QVrP9RX/wZdPqDaFAAesTRwiSP7EF/jZpDR9qV97wHHf5Y\nIS4pZ6GLGp6w0cVySp0mZR2yOtMeb64Dj1egdJQEU5HMnoO3OpTu2l3FzqVZ2TkO\nDFO4KRA2df7pJLNqY7Db\n-----END CERTIFICATE-----\n",
            "SHA256": "38313a36383a31413a41443a36303a37453a36363a41313a41373a37433a31413a44363a32423a31453a44413a30423a33453a31443a30423a37373a46393a41323a42393a30313a44443a41383a32383a44303a38423a34313a32463a3246",
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
            "Indicator": "38313a36383a31413a41443a36303a37453a36363a41313a41373a37433a31413a44363a32423a31453a44413a30423a33453a31443a30423a37373a46393a41323a42393a30313a44443a41383a32383a44303a38423a34313a32463a3246",
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
>| b'CN'=b'*.pan.dev' | b'C'=b'US', b'O'=b"Let's Encrypt", b'CN'=b"Let's Encrypt Authority X3" | 38313a36383a31413a41443a36303a37453a36363a41313a41373a37433a31413a44363a32423a31453a44413a30423a33453a31443a30423a37373a46393a41323a42393a30313a44443a41383a32383a44303a38423a34313a32463a3246 |

